#!/usr/bin/env python3
"""把已验证的实际 ZIP 程序部署到本项目私有开发验收环境，不授予正式发布资格。"""
import argparse
import copy
import datetime
import hashlib
import json
import math
import pathlib
import re
import secrets
import subprocess
import time
import zipfile

import remote_acceptance as acceptance
import remote_review as review_tools
from check_package_acceptance import verify_archive
from package_linux import ROLES

SCOPES = {
    'offline': ('actual_upx_zip_offline_pcap_to_roles_mtls_search_notification_replay', 'TestLiveRolesNativeCaptureToSearchNotificationAndReplay'),
    'capture': ('actual_upx_zip_managed_af_packet_http_to_roles_search_notification_packet_export', 'TestManagedCaptureNativeLiveHTTPEndToEnd'),
}
ROLE_NAMES = {
    'starbeacon': 'platform', 'starbeacon-ingest': 'ingest',
    'starbeacon-worker': 'worker', 'starbeaconctl': 'starbeaconctl',
    'starbeacon-agent': 'agent',
}


def read_json(path, limit=1024*1024):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError('候选身份或证据必须为有界普通文件')
    return json.loads(path.read_bytes())


def verify_execution(state, identity, expected_exit=0):
    if identity.get('project') != state['project'] or not re.fullmatch(r'[a-f0-9]{64}', identity.get('container_id', '')) or not re.fullmatch(re.escape(state['project']) + r'-[a-z0-9-]+', identity.get('container', '')):
        raise ValueError('实际执行容器身份无效')
    value = json.loads(acceptance.ssh(state['host'], ['docker', 'inspect', identity['container_id']], stdout=subprocess.PIPE, timeout=20).stdout)[0]
    labels = value['Config']['Labels']
    observed = value['State']
    if value['Name'] != '/' + identity['container'] or labels.get('io.starbeacon.candidate.project') != state['project'] or labels.get('io.starbeacon.candidate.source') != state['workspace_sha256'] or observed['Running'] or observed['OOMKilled'] or observed['ExitCode'] != expected_exit:
        raise ValueError('实际执行状态或源码标签与候选不一致')


def verify_flow(directory, kind, state, checksums):
    report = read_json(directory / 'package-e2e.json')
    scope, testcase = SCOPES[kind]
    path = directory / 'package-e2e.jsonl'
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16*1024*1024:
        raise ValueError('缺少原始 ZIP 业务执行事件')
    raw = path.read_bytes()
    events = [json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    passed = [row['Test'] for row in events if row.get('Action') == 'pass' and row.get('Test') and '/' not in row['Test']]
    if report.get('status') != 'passed' or report.get('exit_code') != 0 or report.get('scope') != scope or report.get('backend_source') != state['workspace_sha256'] or report.get('checksums') != checksums or report.get('evidence', {}).get('sha256') != hashlib.sha256(raw).hexdigest() or passed != [testcase] or any(row.get('Action') in ('fail', 'skip') for row in events):
        raise ValueError('ZIP 业务链路证据、来源或实际制品不一致')
    execution = read_json(directory / 'execution.json')
    verify_execution(state, execution['identity'])
    return {'scope':scope, 'sha256':hashlib.sha256(raw).hexdigest()}


def candidate_files(directory, identity, state, frontend_files):
    if not re.fullmatch(re.escape(state['directory']) + r'/linux-candidate-[a-f0-9]{12}', identity.get('directory', '')):
        raise ValueError('远程原生 ZIP 目录不属于已登记的候选')
    checksums = read_json(directory / 'checksums.json')
    if identity.get('status') != 'passed' or identity.get('project') != state['project'] or identity.get('backend_source') != state['workspace_sha256'] or identity.get('commit') != state['commit'] or identity.get('checksums') != checksums or checksums.get('commit') != state['commit'] or identity.get('version') != checksums.get('version'):
        raise ValueError('候选与当前独立验收源码不一致')
    entries = checksums.get('archives')
    if not isinstance(entries, list) or len(entries) != 2:
        raise ValueError('候选必须包含平台和采集器两个 ZIP')
    files, manifests, seen = {}, {}, set()
    for record in entries:
        name = record.get('name', '')
        match = re.fullmatch(r'starbeacon-(platform|collector)-(.+)-linux-amd64\.zip', name)
        if not match or match[2] != checksums['version'] or match[1] in seen:
            raise ValueError('候选 ZIP 名称、目标架构或版本无效')
        bundle = match[1]
        seen.add(bundle)
        verify_archive(directory / name, record, checksums, bundle, 'amd64')
        with zipfile.ZipFile(directory / name) as archive:
            prefix = 'starbeacon-' + bundle
            manifest = json.loads(archive.read(prefix + '/manifest.json'))
            manifests[bundle] = manifest
            for role in ROLES[bundle]:
                files['bin/' + role] = archive.read(prefix + '/bin/' + role)
            actual = {entry.filename.removeprefix(prefix + '/www/'):archive.read(entry) for entry in archive.infolist() if entry.filename.startswith(prefix + '/www/')}
            expected = {name.removeprefix('ui/' + bundle + '/'):data for name, data in frontend_files.items() if name.startswith('ui/' + bundle + '/')}
            if actual != expected:
                raise ValueError('ZIP 的实际页面与当前已构建前端不一致')
            files.update({'ui/' + bundle + '/' + name:data for name, data in actual.items()})
    if seen != {'platform', 'collector'}:
        raise ValueError('候选缺少双端程序')
    return files, manifests, checksums


def extract_remote_binaries(state, directory, identity):
    if not re.fullmatch(re.escape(state['directory']) + r'/linux-candidate-[a-f0-9]{12}', identity.get('directory', '')):
        raise ValueError('远程原生 ZIP 目录不属于已登记的候选')
    # 使用已通过原生验证的同一 ZIP，避免重复传输程序；每个原包及程序均重新核对摘要。
    probe = '''import hashlib,json,os,pathlib,stat,sys,zipfile
p=pathlib.Path(sys.argv[1]);origin=pathlib.Path(sys.argv[2])/'output';metadata=json.loads((p/'candidate.json').read_text());records=metadata['binaries'];roles={'platform':('starbeacon','starbeacon-ingest','starbeacon-worker','starbeaconctl'),'collector':('starbeacon-agent',)}
if origin.is_symlink() or not origin.is_dir():raise ValueError('原生 ZIP 目录不可核对')
destination=p/'bin';destination.mkdir(mode=0o755);os.chown(destination,65532,65532);seen=set()
for record in metadata['checksums']['archives']:
 source=origin/record['name']
 if source.is_symlink() or not source.is_file() or source.stat().st_size!=record['size']:raise ValueError('远程 ZIP 类型或长度不一致')
 digest=hashlib.sha256()
 with source.open('rb') as stream:
  for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
 if digest.hexdigest()!=record['sha256']:raise ValueError('远程 ZIP 摘要不一致')
 bundle='platform' if record['name'].startswith('starbeacon-platform-') else 'collector';prefix='starbeacon-'+bundle
 with zipfile.ZipFile(source) as archive:
  for role in roles[bundle]:
   info=archive.getinfo(prefix+'/bin/'+role);expected=records[role]
   if not stat.S_ISREG(info.external_attr>>16) or info.file_size!=expected['size'] or info.file_size>67108864:raise ValueError('远程 ZIP 程序类型或长度不一致')
   data=archive.read(info)
   if hashlib.sha256(data).hexdigest()!=expected['sha256']:raise ValueError('远程 ZIP 程序摘要不一致')
   target=destination/role
   fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o755)
   with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
   os.chown(target,65532,65532);seen.add(role)
if seen!=set(records):raise ValueError('远程 ZIP 缺少已核验的角色程序')
print('远程 ZIP 与五个程序摘要核对通过')
'''
    acceptance.ssh(state['host'], ['python3', '-c', probe, directory, identity['directory']], stdout=subprocess.PIPE, timeout=60)


def verify_backend_report(backend, state):
    phases = backend.get('phases')
    percentage = backend.get('coverage', {}).get('percentage')
    if backend.get('scope') != 'backend_functional_and_live_af_packet' or backend.get('status') != 'passed' or backend.get('project') != state['project'] or backend.get('workspace_sha256') != state['workspace_sha256'] or backend.get('commit') != state['commit'] or type(percentage) not in (int, float) or not math.isfinite(percentage) or not 90 <= percentage <= 100 or not isinstance(phases, list) or len(phases) != 3:
        raise ValueError('最新同源完整后端与覆盖率门禁未通过')
    if {row.get('phase') for row in phases} != {'baseline', 'capture', 'combine'} or any(row.get('status') != 'passed' or row.get('exit_code') != 0 for row in phases) or len({row.get('container_id') for row in phases}) != 3:
        raise ValueError('完整后端缺少三个独立通过的真实执行阶段')
    match = re.fullmatch(re.escape(state['directory']) + r'/backend-functional-([a-f0-9]{12})', backend.get('directory', ''))
    if not match or any(row.get('container') != state['project'] + '-' + row['phase'] + '-' + match[1] for row in phases):
        raise ValueError('完整后端执行阶段没有绑定同一个独立实例')
    return phases


def replace_binary_mounts(volumes, directory, roles):
    if not isinstance(volumes, list) or any(not isinstance(value, str) or len(value.split(':')) not in (2, 3) for value in volumes):
        raise ValueError('既有挂载定义无法核对')
    targets = {'/usr/local/bin/' + role for role in roles}
    return [value for value in volumes if value.split(':')[1] not in targets] + [directory + '/bin/' + role + ':/usr/local/bin/' + role + ':ro' for role in roles]


def replace_frontend_mount(volumes, directory):
    if not isinstance(volumes, list) or any(not isinstance(value, str) or len(value.split(':')) not in (2, 3) for value in volumes):
        raise ValueError('既有前端挂载定义无法核对')
    current = [value for value in volumes if value.split(':')[1] == '/ui']
    if len(current) != 1 or not current[0].endswith(':/ui:ro'):
        raise ValueError('前端必须具有唯一的只读制品挂载')
    return [directory + '/ui:/ui:ro' if value == current[0] else value for value in volumes]


def frontend_records(files):
    result, size, applications = {}, 0, set()
    for name, data in files.items():
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or len(path.parts) < 3 or path.parts[0] != 'ui' or path.parts[1] not in ROLES or path.as_posix() != name or any(ord(char) < 32 for char in name) or not isinstance(data, bytes):
            raise ValueError('前端制品路径或内容无效')
        size += len(data)
        applications.add(path.parts[1])
        result[name] = {'size':len(data), 'sha256':hashlib.sha256(data).hexdigest()}
    if size > 32*1024*1024 or applications != {'platform', 'collector'} or any('ui/' + app + '/index.html' not in result for app in applications):
        raise ValueError('前端制品超过预算或缺少双端入口')
    return result


FRONTEND_HTTP_PROBE = '''import hashlib,json,sys,urllib.error,urllib.parse,urllib.request
expected=json.loads(sys.argv[1]);ports=json.loads(sys.argv[2]);rows={}
if set(ports)!={'platform','collector'} or any(type(port) is not int or not 1<=port<=65535 for port in ports.values()):raise ValueError('同源网关端口无效')
for name,record in expected.items():
 app,relative=name.removeprefix('ui/').split('/',1)
 url='http://127.0.0.1:'+str(ports[app])+'/'+urllib.parse.quote(relative,safe='/')
 request=urllib.request.Request(url,headers={'Accept-Encoding':'identity'})
 try:response=urllib.request.urlopen(request,timeout=5)
 except urllib.error.HTTPError as error:raise ValueError('在线前端文件不可用') from error
 with response:
  if response.status!=200 or response.geturl()!=url or response.headers.get('Content-Encoding') not in (None,'identity'):raise ValueError('前端文件响应无效')
  digest=hashlib.sha256();size=0
  while True:
   block=response.read(min(65536,record['size']-size+1))
   if not block:break
   size+=len(block)
   if size>record['size']:raise ValueError('在线前端文件长度与 ZIP 不一致')
   digest.update(block)
  actual={'size':size,'sha256':digest.hexdigest()}
  if actual!=record:raise ValueError('在线前端文件字节与 ZIP 不一致')
  rows[name]=actual
print(json.dumps(rows))
'''


def verify_online_frontend(state, files):
    expected = frontend_records(files)
    result = acceptance.ssh(state['host'], ['docker', 'exec', '--user', '65532:65532', state['project'] + '-review-1', 'python3', '-c', FRONTEND_HTTP_PROBE, json.dumps(expected), json.dumps({'platform':8080, 'collector':8081})], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if len(result.stdout) > 1024*1024:
        raise ValueError('在线前端证据超过预算')
    observed = json.loads(result.stdout)
    if observed != expected:
        raise ValueError('在线前端返回的文件集合或摘要与 ZIP 不一致')
    return {'scope':'actual_gateway_bytes_match_zip_frontend', 'files':observed}


def verify_remote_evidence(state):
    probe = '''import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);expected=json.loads(sys.argv[2]);records={};count=0
for name in ('backend.json','baseline.json','capture/capture.json'):
 p=root/name
 if p.is_symlink() or p.parent.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=1048576:raise ValueError('缺少完整执行报告')
 data=p.read_bytes();report=json.loads(data)
 if report.get('status')!='passed' or any(report.get(key)!=value for key,value in expected.items()):raise ValueError('实际执行报告来源不一致')
 records[name]=hashlib.sha256(data).hexdigest()
 evidence=report.get('evidence')
 if not isinstance(evidence,list) or not 0<len(evidence)<=100:raise ValueError('实际执行报告缺少有界证据')
 seen=set()
 for entry in evidence:
  relative=pathlib.PurePosixPath(entry['path'])
  if relative.is_absolute() or '..' in relative.parts or relative.as_posix() in seen:raise ValueError('执行证据路径不可核对')
  seen.add(relative.as_posix());q=p.parent/relative
  if q.is_symlink() or q.parent.is_symlink() or not q.is_file() or q.stat().st_size>268435456:raise ValueError('执行证据不可读取')
  digest=hashlib.sha256()
  with q.open('rb') as stream:
   for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
  if digest.hexdigest()!=entry.get('sha256'):raise ValueError('执行证据摘要不一致')
  count+=1
print(json.dumps({'reports':records,'evidence_files_checked':count}))
'''
    expected = {key:state[key] for key in ('workspace_sha256', 'commit', 'project', 'clean_commit')}
    result = acceptance.ssh(state['host'], ['python3', '-c', probe, state['directory'] + '/reports', json.dumps(expected)], stdout=subprocess.PIPE, timeout=60)
    if len(result.stdout) > 16384:
        raise ValueError('执行证据核对结果超过预算')
    return json.loads(result.stdout)


def verify_online(state, image, binary_records, checksums):
    versions, records = {}, {}
    probe = '''import hashlib,json,pathlib,sys
rows={}
for role in sys.argv[1:]:
 p=pathlib.Path('/usr/local/bin')/role
 if p.is_symlink() or not p.is_file():raise ValueError('在线程序不是普通文件')
 digest=hashlib.sha256()
 with p.open('rb') as stream:
  for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
 rows[role]={'size':p.stat().st_size,'sha256':digest.hexdigest()}
print(json.dumps(rows))
'''
    for service, roles in [('review', ROLES['platform']), ('review-capture', ROLES['collector'])]:
        name = state['project'] + '-' + service + '-1'
        container = json.loads(acceptance.ssh(state['host'], ['docker', 'inspect', name], stdout=subprocess.PIPE, timeout=20).stdout)[0]
        if container['Image'] != image or not container['State']['Running'] or container['State']['OOMKilled'] or container['State'].get('Health', {}).get('Status') != 'healthy' or container['Config']['Labels'].get('com.docker.compose.project') != state['project'] or container['Config']['Labels'].get('com.docker.compose.service') != service:
            raise ValueError('在线角色运行状态或实例身份不一致')
        observed = json.loads(acceptance.ssh(state['host'], ['docker', 'exec', name, 'python3', '-c', probe, *roles], stdout=subprocess.PIPE, timeout=30).stdout)
        for role in roles:
            record = binary_records[role]
            if observed.get(role) != {key:record[key] for key in ('size', 'sha256')}:
                raise ValueError('在线实际程序字节与 ZIP 制品不一致')
            version = acceptance.ssh(state['host'], ['docker', 'exec', name, '/usr/local/bin/' + role, '--version'], stdout=subprocess.PIPE, timeout=20).stdout.decode().strip()
            if version != 'StarBeacon ' + ROLE_NAMES[role] + ' ' + checksums['version'] + ' (' + checksums['commit'] + ')':
                raise ValueError('在线程序实际版本未达到候选身份')
            versions[role] = version
            records[role] = observed[role]
    return versions, records


def capture_observation(state, expected_version=None, attempts=1):
    # 凭据始终留在已登记的私有容器配置中；证据仅保存白名单运行字段。
    probe = '''import http.cookiejar,json,pathlib,sys,time,urllib.request
config=json.loads(pathlib.Path('/data/agent.json').read_text())
password=config.get('SB_LOCAL_PASSWORD','')
secret=config.get('SB_LOCAL_PASSWORD_FILE','')
if secret:
 if password:raise ValueError('采集器密码配置存在冲突')
 password=pathlib.Path(secret).read_text().removesuffix('\\n').removesuffix('\\r')
if not 12<=len(password.encode())<=72:raise ValueError('采集器本地密码配置无效')
settings={'tenant':config['SB_TENANT_ID'],'collector_origin':config['SB_ALLOWED_ORIGIN'],'password':password}
base='http://127.0.0.1:28081/api/local/v1';csrf=''
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def request(path,body=None):
 headers={'Origin':settings['collector_origin'],'Content-Type':'application/json','X-CSRF-Token':csrf}
 req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
 with opener.open(req,timeout=15) as response:return json.load(response)
principal=request('/auth/login',{'username':'admin','password':settings['password']});csrf=principal['csrf_token']
try:
 if principal.get('tenant_id')!=settings['tenant'] or principal.get('role')!='admin':raise ValueError('采集身份不属于当前验收租户')
 for attempt in range(int(sys.argv[2])):
  capture=request('/capture-config');health=request('/health')
  if capture.get('status')=='running' and capture.get('revision')==capture.get('applied_revision') and not health.get('errors') and (not sys.argv[1] or health.get('version')==sys.argv[1]):break
  if attempt+1<int(sys.argv[2]):time.sleep(1)
 fields=('interfaces','threads','bpf_filter','promiscuous','managed','status','revision','applied_revision','applied_settings','settings_sha256','config_sha256','observed_at','spool_bytes','spool_budget','rotation_pending')
 print(json.dumps({'capture':{key:capture.get(key) for key in fields},'health':{key:health.get(key) for key in ('version','errors','capture_status','observed_at')}}))
finally:request('/auth/logout',{})
'''
    result = acceptance.ssh(state['host'], ['docker', 'exec', state['project'] + '-review-capture-1', 'python3', '-c', probe, expected_version or '', str(attempts)], stdout=subprocess.PIPE, timeout=60)
    if len(result.stdout) > 65536:
        raise ValueError('采集状态观察超过预算')
    value = json.loads(result.stdout)
    capture, health = value['capture'], value['health']
    if capture.get('managed') is not True or capture.get('status') != 'running' or capture.get('revision') != capture.get('applied_revision') or health.get('errors') != [] or health.get('capture_status') != 'running' or expected_version and health.get('version') != expected_version:
        raise ValueError('托管采集尚未实际生效或存在运行错误')
    return value


def stop_roles(state, review):
    for service in ('review-capture', 'review-web', 'review'):
        review_tools.compose(state, review, ['stop', '--timeout', '15', service], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)


def remove_stopped_dependencies(state, services=('review-capture', 'review-web')):
    # 共享平台网络命名空间的容器先释放引用，持久目录和数据库不参与容器回收。
    if not services or len(set(services)) != len(services) or any(service not in ('review-capture','review-web') for service in services):
        raise ValueError('停止依赖回收范围不属于本实例的双端角色')
    probe = '''import http.client,json,socket,sys
class Unix(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect('/var/run/docker.sock')
rows=[]
for service in json.loads(sys.argv[2]):
 name=sys.argv[1]+'-'+service+'-1';c=Unix('localhost',timeout=8);c.request('GET','/containers/'+name+'/json');r=c.getresponse();raw=r.read(1048577);c.close()
 if r.status==404:continue
 if r.status!=200 or len(raw)>1048576:raise ValueError('依赖容器无法核验')
 v=json.loads(raw);labels=v['Config']['Labels'];state=v['State']
 if v['Name']!='/'+name or labels.get('com.docker.compose.project')!=sys.argv[1] or labels.get('com.docker.compose.service')!=service or state['Running'] or state['Dead'] or state['Status'] not in ('exited','created'):raise ValueError('依赖容器归属或停止状态不一致')
 rows.append({'service':service,'id':v['Id']})
print(json.dumps(rows))
'''
    response = acceptance.ssh(state['host'], ['python3', '-c', probe, state['project'], json.dumps(services)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
    if len(response.stdout) > 4096:
        raise ValueError('依赖容器响应超过预算')
    records = json.loads(response.stdout)
    if not isinstance(records, list) or len(records) > len(services) or len({row.get('service') for row in records}) != len(records) or any(row.get('service') not in services or not re.fullmatch(r'[a-f0-9]{64}', row.get('id','')) for row in records):
        raise ValueError('依赖容器身份记录无效')
    for row in records:
        acceptance.ssh(state['host'], ['docker', 'rm', row['id']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)


def start_roles(state, review):
    remove_stopped_dependencies(state)
    review_tools.compose(state, review, ['up', '-d', '--wait', '--wait-timeout', '120', '--force-recreate', '--no-deps', 'review'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=150)
    review_tools.compose(state, review, ['up', '-d', '--no-deps', 'review-web'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    review_tools.compose(state, review, ['up', '-d', '--wait', '--wait-timeout', '90', '--force-recreate', '--no-deps', 'review-capture'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=110)


def migration_service(state, review, definition, directory):
    """迁移只能使用当前候选 CLI 和本实例的持久身份，不调用初始化服务。"""
    expected = state['directory'] + '/' + review.get('name', '')
    if review.get('scope') != 'development_ui_review' or not re.fullmatch(r'review-[a-f0-9]{16}', review.get('name', '')) or review.get('directory') != expected or review.get('database') != 'sbui_' + review['name'].removeprefix('review-') or not re.fullmatch(re.escape(expected) + r'/candidate-[a-f0-9]{16}', directory):
        raise ValueError('候选迁移不属于已登记的独立界面数据库')
    runtime = definition.get('services', {}).get('review')
    if not isinstance(runtime, dict) or runtime.get('entrypoint') != ['python3', '/review/runtime.py'] or not isinstance(runtime.get('environment'), dict) or not isinstance(runtime.get('volumes'), list) or runtime.get('network_mode') is not None:
        raise ValueError('候选迁移运行定义无法核对')
    required = directory + '/bin/starbeaconctl:/usr/local/bin/starbeaconctl:ro'
    if required not in runtime['volumes'] or expected + '/data:/data' not in runtime['volumes'] or any(not isinstance(v, str) or len(v.split(':')) not in (2, 3) for v in runtime['volumes']):
        raise ValueError('迁移必须使用实际 ZIP CLI 与本实例的持久目录')
    targets = [v.split(':')[1] for v in runtime['volumes']]
    if len(targets) != len(set(targets)) or runtime['environment'].get('SB_RUNTIME_DB_PASSWORD') != '${SB_RUNTIME_DB_PASSWORD}' or 'POSTGRES_PASSWORD' in runtime['environment']:
        raise ValueError('迁移挂载目标重复或在线角色凭据范围无效')
    configurations = [v for v in runtime['volumes'] if v.split(':')[1] == '/review']
    if len(configurations) != 1 or not configurations[0].endswith(':/review:ro') or not configurations[0].split(':')[0].startswith(expected + '/') or '..' in pathlib.PurePosixPath(configurations[0].split(':')[0]).parts:
        raise ValueError('迁移配置不属于本实例的只读目录')
    migration = copy.deepcopy(runtime)
    migration['init'] = True
    for field in ('healthcheck', 'depends_on', 'ports', 'restart', 'container_name'):
        migration.pop(field, None)
    migration.update(entrypoint=['python3', '/migration/runtime.py'], command=['migrate'], restart='no', environment={'SB_RUNTIME_DB_PASSWORD':'${SB_RUNTIME_DB_PASSWORD}', 'POSTGRES_PASSWORD':'${POSTGRES_PASSWORD}'})
    migration['volumes'] = [expected + '/data:/data', configurations[0], required, directory + '/migration-runtime.py:/migration/runtime.py:ro']
    migration['tmpfs'] = [*migration.get('tmpfs', []), *[path+':rw,noexec,nosuid,nodev,size=1m,mode=1777' for path in ('/etc/suricata','/var/lib/suricata','/var/log/suricata','/var/run/suricata')]]
    migration['labels'] = {**migration.get('labels', {}), 'io.starbeacon.candidate.project': state['project'], 'io.starbeacon.candidate.source': state['workspace_sha256']}
    return {'services': {'review-migrate': migration}}


def migration_observation(state, definition, directory, name):
    # 退出记录独立于 Compose 控制连接；只返回身份、挂载和状态，不返回环境凭据。
    probe = '''import http.client,json,socket,sys
class Unix(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect('/var/run/docker.sock')
c=Unix('localhost',timeout=8);c.request('GET','/containers/'+sys.argv[1]+'/json');r=c.getresponse();raw=r.read(1048577);c.close()
if r.status!=200 or len(raw)>1048576:raise ValueError('迁移容器不可核对')
v=json.loads(raw);l=v['Config']['Labels'];z=v['State'];expected=json.loads(sys.argv[5]);mounts={m['Destination']:m for m in v['Mounts'] if m['Type']=='bind'}
if v['Name']!='/'+sys.argv[1] or l.get('com.docker.compose.project')!=sys.argv[2] or l.get('com.docker.compose.service')!='review-migrate' or l.get('com.docker.compose.oneoff')!='True' or l.get('io.starbeacon.candidate.source')!=sys.argv[3] or v['Image']!=sys.argv[4] or v['Config']['Entrypoint']!=['python3','/migration/runtime.py'] or v['Config']['Cmd']!=['migrate'] or v['HostConfig']['ReadonlyRootfs'] is not True or v['Config']['User']!='65532:65532':raise ValueError('迁移执行身份不同')
if set(mounts)!=set(expected) or any(mounts[target]['Source']!=row['source'] or mounts[target]['RW']!=row['rw'] for target,row in expected.items()):raise ValueError('迁移实际挂载不同')
if z['Running'] or z['Dead'] or z['OOMKilled'] or z['ExitCode']!=0 or z['Status']!='exited':raise ValueError('迁移实际退出未通过')
print(json.dumps({'container':sys.argv[1],'container_id':v['Id'],'image':v['Image'],'state':z,'mounts':mounts}))
'''
    runtime = definition['services']['review-migrate']
    expected = {v.split(':')[1]: {'source':v.split(':')[0], 'rw':len(v.split(':'))==2 or v.split(':')[2]!='ro'} for v in runtime['volumes']}
    result = acceptance.ssh(state['host'], ['python3','-c',probe,name,state['project'],state['workspace_sha256'],runtime['image'],json.dumps(expected)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if len(result.stdout)>32768:
        raise ValueError('迁移执行观察超过预算')
    return json.loads(result.stdout)


def migrate_candidate(state, review, definition, directory):
    migration = migration_service(state, review, definition, directory)
    encoded = (json.dumps(migration, ensure_ascii=False, indent=2) + '\n').encode()
    acceptance.ssh(state['host'], ['tee', directory + '/migrate.json'], input=encoded, stdout=subprocess.DEVNULL, timeout=20)
    started = time.monotonic()
    failure = None
    name = state['project']+'-review-migrate-'+directory.rsplit('-',1)[-1]
    try:
        result = review_tools.compose(state, review, ['-f', directory + '/migrate.json', 'run', '--no-deps', '-T', '--name', name, 'review-migrate'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=200)
        exit_code, output = result.returncode, result.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        failure = error
        exit_code, output = getattr(error, 'returncode', None), error.output or b''
    passed = failure is None and exit_code == 0 and isinstance(output, bytes) and len(output) <= 512*1024
    if not isinstance(output, bytes) or len(output) > 512*1024:
        output = '迁移日志超过核对预算\n'.encode()
    record = {'status': 'passed' if passed else 'failed', 'exit_code': exit_code, 'scope': 'actual_zip_cli_migrate_and_runtime_role_not_initialization', 'project': state['project'], 'backend_source': state['workspace_sha256'], 'directory': directory, 'database': review['database'], 'duration_seconds': round(time.monotonic()-started, 3), 'definition_sha256': hashlib.sha256(encoded).hexdigest(), 'log_sha256': hashlib.sha256(output).hexdigest()}
    if passed:
        try:
            record['execution'] = migration_observation(state, migration, directory, name)
        except (ValueError, subprocess.SubprocessError, OSError) as error:
            failure, passed = error, False
            record.update(status='failed', observation_error=type(error).__name__)
    acceptance.ssh(state['host'], ['tee', directory + '/migration.log'], input=output, stdout=subprocess.DEVNULL, timeout=20)
    acceptance.ssh(state['host'], ['tee', directory + '/migration-execution.json'], input=(json.dumps(record, ensure_ascii=False, indent=2)+'\n').encode(), stdout=subprocess.DEVNULL, timeout=20)
    if not passed:
        raise ValueError('实际 ZIP 数据库迁移未通过，候选启动已停止，执行记录已保留') from failure
    return record


def activate_candidate(state, review, definition, directory):
    # 定义预检先于停止现有角色；迁移失败不能继续启动候选角色。
    migration_service(state, review, definition, directory)
    stop_roles(state, review)
    acceptance.ssh(state['host'], ['cp', directory + '/compose.json', review['directory'] + '/compose.json'], timeout=20)
    migration = migrate_candidate(state, review, definition, directory)
    start_roles(state, review)
    return migration


def verified_frontend_only(state, review, image, binaries, checksums):
    live = review.get('runtime_candidate', {})
    if live.get('status') != 'passed' or live.get('backend_source') != state['workspace_sha256'] or review.get('runtime_backend_image') != image or live.get('version') != checksums['version'] or live.get('commit') != checksums['commit'] or live.get('binaries') != binaries:
        return False
    # 元数据相同还须核对在线五个程序的实际字节，才能保持检测角色运行。
    verify_online(state, image, binaries, checksums)
    return True


def activate_frontend(state, review, definition, directory):
    migration_definition = copy.deepcopy(definition)
    migration_definition['services']['review']['volumes'] = replace_binary_mounts(migration_definition['services']['review']['volumes'], directory, ROLES['platform'])
    migration_service(state, review, migration_definition, directory)
    migration = migrate_candidate(state, review, migration_definition, directory)
    review_tools.compose(state, review, ['stop','--timeout','15','review-web'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    remove_stopped_dependencies(state, ('review-web',))
    acceptance.ssh(state['host'], ['cp', directory+'/compose.json', review['directory']+'/compose.json'], timeout=20)
    review_tools.compose(state, review, ['up','-d','--no-deps','review-web'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    return migration


def deploy(args):
    state, review = review_tools.read_review()
    if review_tools.active_runtime_project(state, review) != state['project']:
        raise ValueError('独立运行实例的候选更新须使用专属部署定义，拒绝操作原角色')
    original_review = json.loads(json.dumps(review))
    capture = review_tools.managed_capture_metadata(state, review)
    if review.get('scope') != 'development_ui_review' or not capture:
        raise ValueError('候选部署仅用于已登记的独立开发验收双端环境')
    image = review_tools.backend_image(state)
    frontend, frontend_hash = review_tools.frontend_files()
    identity = read_json(args.identity)
    if identity.get('frontend_source') != frontend_hash:
        raise ValueError('候选前端来源不一致')
    files, manifests, checksums = candidate_files(args.directory, identity, state, frontend)
    verify_execution(state, identity)
    backend = read_json(args.functional)
    for phase in verify_backend_report(backend, state):
        verify_execution(state, dict(phase, project=state['project']))
    raw_backend = acceptance.ssh(state['host'], ['cat', state['directory'] + '/reports/backend.json'], stdout=subprocess.PIPE, timeout=20).stdout
    if len(raw_backend) > 1024*1024:
        raise ValueError('完整后端组合报告超过预算')
    completed = json.loads(raw_backend)
    if completed.get('scope') != backend['scope'] or completed.get('status') != 'passed' or completed.get('workspace_sha256') != state['workspace_sha256'] or completed.get('project') != state['project'] or completed.get('commit') != state['commit'] or completed.get('coverage') != backend['coverage']:
        raise ValueError('远程实际组合报告与完整后端门禁不一致')
    execution_evidence = verify_remote_evidence(state)
    flow = {kind:verify_flow(getattr(args, kind), kind, state, checksums) for kind in SCOPES}
    original = acceptance.ssh(state['host'], ['cat', review['directory'] + '/compose.json'], stdout=subprocess.PIPE, timeout=20).stdout
    if len(original) > 1024*1024:
        raise ValueError('既有环境定义超过预算')
    definition = json.loads(original)
    if set(definition['services']) != {'review-init', 'review', 'review-web', 'review-capture'}:
        raise ValueError('候选不得改动其它服务')
    for service in ('review', 'review-web', 'review-capture'):
        current = json.loads(acceptance.ssh(state['host'], ['docker', 'inspect', state['project'] + '-' + service + '-1'], stdout=subprocess.PIPE, timeout=20).stdout)[0]
        if current['Config']['Labels'].get('com.docker.compose.project') != state['project'] or current['Config']['Labels'].get('com.docker.compose.service') != service:
            raise ValueError('在线服务不属于本实例')
    previous_capture = capture_observation(state)
    directory = review['directory'] + '/candidate-' + secrets.token_hex(8)
    binary_records = {role:record for manifest in manifests.values() for role, record in manifest['binaries'].items()}
    frontend_only = verified_frontend_only(state, review, image, binary_records, checksums)
    metadata = {'schema_version':1, 'scope':'engineering_actual_zip_review_not_formal_release', 'project':state['project'], 'backend_source':state['workspace_sha256'], 'frontend_source':frontend_hash, 'version':checksums['version'], 'commit':checksums['commit'], 'clean_commit':False, 'directory':directory, 'checksums':checksums, 'binaries':binary_records, 'flows':flow, 'capture_before':previous_capture, 'backend_execution_evidence':execution_evidence}
    frontend_from_zip = {name:data for name, data in files.items() if name.startswith('ui/')}
    frontend_records(frontend_from_zip)
    migration_runtime = (acceptance.ROOT / 'tests/acceptance/review_runtime.py').read_bytes()
    metadata['migration_runtime_sha256'] = hashlib.sha256(migration_runtime).hexdigest()
    review_tools.upload_bundle(state, directory, {**frontend_from_zip, 'candidate.json':(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n').encode(), 'rollback-compose.json':original, 'migration-runtime.py':migration_runtime})
    extract_remote_binaries(state, directory, identity)
    probe = '''import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);x=json.loads((p/'candidate.json').read_text())
wrapper=p/'migration-runtime.py'
if wrapper.is_symlink() or not wrapper.is_file() or wrapper.stat().st_size>65536 or hashlib.sha256(wrapper.read_bytes()).hexdigest()!=x['migration_runtime_sha256']:raise ValueError('迁移入口类型或摘要不一致')
for role,record in x['binaries'].items():
 q=p/'bin'/role
 if q.is_symlink() or not q.is_file() or q.stat().st_size!=record['size']:raise ValueError('实际程序类型或长度不一致')
 digest=hashlib.sha256()
 with q.open('rb') as stream:
  for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
 if digest.hexdigest()!=record['sha256']:raise ValueError('实际程序摘要不一致')
 q.chmod(0o755)
print('程序上传摘要核对通过')
'''
    acceptance.ssh(state['host'], ['python3', '-c', probe, directory], stdout=subprocess.PIPE, timeout=30)
    # 只覆盖五个程序文件，保留隔离工具、数据库、设备身份和原有持久目录。
    if not frontend_only:
        for service, roles in [('review', ROLES['platform']), ('review-capture', ROLES['collector'])]:
            definition['services'][service]['image'] = image
            definition['services'][service]['init'] = True
            definition['services'][service]['volumes'] = replace_binary_mounts(definition['services'][service]['volumes'], directory, roles)
    definition['services']['review-web']['volumes'] = replace_frontend_mount(definition['services']['review-web']['volumes'], directory)
    encoded = (json.dumps(definition, ensure_ascii=False, indent=2) + '\n').encode()
    acceptance.ssh(state['host'], ['tee', directory + '/compose.json'], input=encoded, stdout=subprocess.DEVNULL, timeout=20)
    if not frontend_only:
        migration_service(state, review, definition, directory)
    recorded = False
    try:
        migration = activate_frontend(state, review, definition, directory) if frontend_only else activate_candidate(state, review, definition, directory)
        versions, records = verify_online(state, image, binary_records, checksums)
        online_frontend = verify_online_frontend(state, frontend_from_zip)
        current_capture = capture_observation(state, checksums['version'], attempts=20)
        for key in ('interfaces', 'threads', 'bpf_filter', 'promiscuous', 'revision', 'applied_revision', 'applied_settings', 'settings_sha256'):
            if previous_capture['capture'][key] != current_capture['capture'][key]:
                raise ValueError('实际 ZIP 程序替换后采集参数或修订不一致')
        metadata.update(status='passed', versions=versions, online_binaries=records, online_frontend=online_frontend, migration=migration, activation_mode='frontend_only_verified_identical_online_binaries' if frontend_only else 'all_roles', capture_after=current_capture, capture_restart=not frontend_only, capture_gap_possible=True, deployed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        review.update(runtime_candidate=metadata, runtime_backend_source=state['workspace_sha256'], runtime_backend_image=image, runtime_frontend_source=frontend_hash)
        review_tools.verify_gateway(state, review)
        acceptance.ssh(state['host'], ['tee', directory + '/deployment.json'], input=(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n').encode(), stdout=subprocess.DEVNULL, timeout=20)
        review_tools.write_review(review)
        recorded = True
    except Exception:
        if frontend_only:
            review_tools.compose(state, review, ['stop','--timeout','15','review-web'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        else:
            stop_roles(state, review)
        acceptance.ssh(state['host'], ['cp', directory + '/rollback-compose.json', review['directory'] + '/compose.json'], timeout=20)
        if frontend_only:
            remove_stopped_dependencies(state, ('review-web',))
            review_tools.compose(state, review, ['up','-d','--no-deps','review-web'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        else:
            start_roles(state, review)
        if recorded:
            review_tools.write_review(original_review)
        raise
    output = pathlib.Path('.local/acceptance') / ('candidate-review-' + directory.rsplit('-', 1)[-1] + '.json')
    output.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
    output.chmod(0o600)
    print(json.dumps({'status':'passed', 'scope':metadata['scope'], 'source':state['workspace_sha256'], 'version':checksums['version'], 'versions':versions}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory', 'identity', 'functional', 'offline', 'capture'):
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    deploy(args)


if __name__ == '__main__':
    main()
