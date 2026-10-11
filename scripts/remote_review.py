#!/usr/bin/env python3
"""部署专属、仅回环访问的开发验收环境；不替换正式服务或验收报告。"""
import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import subprocess
import tarfile
import tempfile

import remote_acceptance as acceptance

ROOT = pathlib.Path(__file__).resolve().parents[1]
STATE = ROOT / '.local/acceptance/review.json'


def frontend_files():
    files, checksum = {}, hashlib.sha256()
    for app in ('platform', 'collector'):
        directory = ROOT / 'web' / app / 'dist'
        if not (directory / 'index.html').is_file():
            raise ValueError('需要先完成两个工程前端构建')
        for path in sorted(directory.rglob('*')):
            if path.is_symlink():
                raise ValueError('前端制品不得包含符号链接')
            if path.is_file():
                name, data = 'ui/' + app + '/' + path.relative_to(directory).as_posix(), path.read_bytes()
                files[name] = data
                checksum.update(name.encode() + b'\0' + data + b'\0')
    if sum(map(len, files.values())) > 32 * 1024 * 1024:
        raise ValueError('验收前端制品超过 32 MiB')
    return files, checksum.hexdigest()


def nginx_config():
    prefix = '''worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 256; }
http {
 include /etc/nginx/mime.types;
 default_type application/octet-stream;
 access_log /dev/stdout;
 client_body_temp_path /tmp/client;
 proxy_temp_path /tmp/proxy;
 fastcgi_temp_path /tmp/fastcgi;
 uwsgi_temp_path /tmp/uwsgi;
 scgi_temp_path /tmp/scgi;
'''
    for app, port, target in [('platform', 8080, 28080), ('collector', 8081, 28081)]:
        template = (ROOT / 'deploy/nginx' / (app + '.conf')).read_text()
        template = template.replace('listen 80;', f'listen {port};').replace('/srv/starbeacon/' + app, '/ui/' + app)
        if f'proxy_pass http://127.0.0.1:{target};' not in template:
            raise ValueError('同源代理模板与角色入口不一致')
        prefix += template + '\n'
    return prefix + '}\n'


def read_review():
    result = json.loads(STATE.read_text())
    state = acceptance.read_state(ROOT / '.local/acceptance/remote.json')
    if result.get('project') != state['project'] or not re.fullmatch(r'review-[a-f0-9]{16}', result.get('name', '')) or result.get('directory') != state['directory'] + '/' + result['name']:
        raise ValueError('界面验收标识无效，拒绝操作其他目录')
    if result.get('database') != 'sbui_' + result['name'].removeprefix('review-'):
        raise ValueError('界面验收必须使用本实例的独立数据库')
    for key in ('platform_port', 'collector_port'):
        if type(result.get(key)) is not int or not 1024 <= result[key] <= 65535:
            raise ValueError('界面验收端口无效')
    return state, result


def compose(state, review, arguments, **options):
    return acceptance.ssh(state['host'], ['docker', 'compose', '--env-file', state['directory'] + '/dependencies.env', '-p', state['project'], '-f', state['directory'] + '/compose.json', '-f', review['directory'] + '/compose.json', *arguments], **options)


def backend_image(state):
    if acceptance.snapshot_sources()[1] != state['workspace_sha256']:
        raise ValueError('工作区与远程源码快照不一致，需要重新构建验收制品')
    acceptance.verify_image(state)
    identity = acceptance.ssh(state['host'], ['docker', 'image', 'inspect', '--format', '{{.Id}}', acceptance.image_name(state)], stdout=subprocess.PIPE, timeout=15).stdout.decode().strip()
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', identity):
        raise ValueError('验收后端镜像身份无效')
    return identity


def upload_bundle(state, directory, files, *, timeout=30):
    with tempfile.TemporaryDirectory(prefix='starbeacon-review-') as temporary:
        path = pathlib.Path(temporary) / 'review.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for filename, content in files.items():
                acceptance.archive_bytes(archive, filename, content, 0o600 if filename == 'config.json' else 0o644)
        acceptance.ssh(state['host'], ['mkdir', '-m', '700', directory], timeout=15)
        with path.open('rb') as file:
            acceptance.ssh(state['host'], ['tar', '-xzf', '-', '--no-same-owner', '-C', directory], stdin=file, timeout=timeout)
    acceptance.ssh(state['host'], ['chown', '-R', '65532:65532', directory], timeout=15)


def write_review(value):
    if STATE.is_symlink():
        raise ValueError('验收状态不得为符号链接')
    with tempfile.NamedTemporaryFile(mode='w', dir=STATE.parent, prefix='.review-', delete=False) as file:
        path = pathlib.Path(file.name)
        os.chmod(path, 0o600)
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write('\n')
    try:
        path.replace(STATE)
    finally:
        path.unlink(missing_ok=True)


def managed_capture_metadata(state, review):
    """只接管本实例先前登记的独立采集器，保留原有 WAL、凭据与原包目录。"""
    path = ROOT / '.local/acceptance/capture-ui.json'
    if not path.exists():
        return None
    if path.is_symlink() or path.stat().st_size > 16384:
        raise ValueError('界面采集器验收状态文件无效')
    value = json.loads(path.read_text())
    base = re.escape(review['directory']) + r'/capture-ui-[a-f0-9]{16}'
    if not isinstance(value, dict) or value.get('project') != state['project'] or value.get('scope') != 'isolated_live_capture_ui_review' or not re.fullmatch(base, value.get('bundle', '')) or not re.fullmatch(base + r'/agent-data', value.get('agent_data', '')) or value.get('host_network') is not False or value.get('host_network_admin') is not False or value.get('capabilities') != ['NET_RAW', 'SETFCAP']:
        raise ValueError('独立采集器身份或持久目录不属于当前界面验收实例')
    return value


def capture_service(state, image, directory, capture, runtime):
    return {
        'image': image, 'platform': 'linux/amd64', 'pull_policy': 'never', 'user': '0:0',
        'entrypoint': ['python3', '/capture-review/capture_runtime.py'],
        'network_mode': 'service:review', 'read_only': True,
        'cap_drop': ['ALL'], 'cap_add': ['NET_RAW', 'SETFCAP'],
        'security_opt': list(runtime['security_opt']),
        'tmpfs': ['/tmp:rw,exec,nosuid,nodev,size=256m'],
        'volumes': [capture['agent_data'] + ':/data', directory + '/capture_runtime.py:/capture-review/capture_runtime.py:ro'],
        'mem_limit': '1g', 'cpus': '1', 'pids_limit': 128,
        'depends_on': {'review': {'condition': 'service_healthy'}},
        'healthcheck': {'test': ['CMD', 'curl', '--fail', '--silent', 'http://127.0.0.1:28081/readyz'], 'interval': '2s', 'timeout': '3s', 'retries': 20, 'start_period': '5s'},
    }


def update(state, review):
    """固定代码与前端制品身份，不重新初始化租户、凭据或采集样本。"""
    if review.get('runtime_candidate'):
        raise ValueError('当前环境使用已验证的 ZIP 程序，请通过候选部署流程更新，不能隐式改用覆盖率程序')
    image = backend_image(state)
    files, digest = frontend_files()
    directory = review['directory'] + '/bundle-' + secrets.token_hex(8)
    files['runtime.py'] = (ROOT / 'tests/acceptance/review_runtime.py').read_bytes()
    files['nginx.conf'] = nginx_config().encode()
    config_bytes = acceptance.ssh(state['host'], ['cat', review['directory'] + '/config.json'], stdout=subprocess.PIPE, timeout=15).stdout
    if len(config_bytes) > 65536:
        raise ValueError('界面验收配置超过容量')
    settings = json.loads(config_bytes)
    if settings.get('database') != review['database'] or settings.get('tenant') != 'review_' + review['name'].removeprefix('review-'):
        raise ValueError('界面验收升级配置与本实例不一致')
    capture = managed_capture_metadata(state, review)
    settings['collector_execution'] = 'isolated_managed' if capture else 'embedded'
    files['config.json'] = (json.dumps(settings, ensure_ascii=False) + '\n').encode()
    if capture:
        files['capture_runtime.py'] = (ROOT / 'tests/acceptance/review_capture_runtime.py').read_bytes()
    upload_bundle(state, directory, files)
    definition = json.loads(acceptance.ssh(state['host'], ['cat', review['directory'] + '/compose.json'], stdout=subprocess.PIPE, timeout=15).stdout)
    services = definition.get('services', {})
    allowed = {'review-init', 'review', 'review-web'}
    if set(services) not in (allowed, allowed | {'review-capture'}):
        raise ValueError('界面验收服务身份不一致')
    if 'review-capture' in services and capture is None:
        raise ValueError('独立采集器缺少当前实例的持久目录身份')
    if not review.get('runtime_backend_image'):
        original = acceptance.ssh(state['host'], ['docker', 'inspect', '--format', '{{.Image}}', state['project'] + '-review-1'], stdout=subprocess.PIPE, timeout=15).stdout.decode().strip()
        labels = json.loads(acceptance.ssh(state['host'], ['docker', 'image', 'inspect', '--format', '{{json .Config.Labels}}', original], stdout=subprocess.PIPE, timeout=15).stdout)
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', original) or labels.get('io.starbeacon.acceptance.source') != review['backend_source']:
            raise ValueError('原始初始化镜像身份无法核对')
        services['review-init']['image'] = original
    runtime = services['review']
    runtime['image'] = image
    runtime['volumes'] = [review['directory'] + '/data:/data', directory + ':/review:ro']
    # 初始化制品保持原始身份；界面升级不调用 review-init。
    services['review-web']['volumes'] = [directory + '/ui:/ui:ro', directory + '/nginx.conf:/config/nginx.conf:ro']
    if capture:
        services['review-capture'] = capture_service(state, image, directory, capture, runtime)
    data = (json.dumps(definition, ensure_ascii=False, indent=2) + '\n').encode()
    acceptance.ssh(state['host'], ['tee', directory + '/compose.json'], input=data, stdout=subprocess.DEVNULL, timeout=15)
    acceptance.ssh(state['host'], ['mv', directory + '/compose.json', review['directory'] + '/compose.json'], timeout=15)
    # 同源网关共享业务容器网络命名空间，须先释放引用再替换业务容器。
    if capture:
        compose(state, review, ['stop', '--timeout', '15', 'review-capture'])
    compose(state, review, ['stop', '--timeout', '15', 'review-web'])
    compose(state, review, ['stop', '--timeout', '15', 'review'])
    # 迁移凭据仅交给专属临时容器；不进入在线角色，也不重新初始化数据。
    migration = dict(runtime, command=['migrate'], environment=dict(runtime['environment'], POSTGRES_PASSWORD='${POSTGRES_PASSWORD}'))
    migration_definition = {'services': {'review-migrate': migration}}
    acceptance.ssh(state['host'], ['tee', directory + '/migrate.json'], input=(json.dumps(migration_definition, ensure_ascii=False, indent=2)+'\n').encode(), stdout=subprocess.DEVNULL, timeout=15)
    compose(state, review, ['-f', directory + '/migrate.json', 'run', '--rm', '--no-deps', 'review-migrate'])
    compose(state, review, ['up', '-d', '--wait', '--wait-timeout', '120', '--no-deps', 'review', 'review-web'])
    if capture:
        compose(state, review, ['up', '-d', '--wait', '--wait-timeout', '90', '--no-deps', 'review-capture'])
        actual_capture = acceptance.ssh(state['host'], ['docker', 'inspect', '--format', '{{.Image}}', state['project'] + '-review-capture-1'], stdout=subprocess.PIPE, timeout=15).stdout.decode().strip()
        if actual_capture != image:
            raise ValueError('独立采集器镜像未达到目标身份')
    actual = acceptance.ssh(state['host'], ['docker', 'inspect', '--format', '{{.Image}}', state['project'] + '-review-1'], stdout=subprocess.PIPE, timeout=15).stdout.decode().strip()
    if actual != image:
        raise ValueError('运行镜像未达到目标身份')
    review.update(runtime_backend_source=state['workspace_sha256'], runtime_backend_image=image, runtime_frontend_source=digest, runtime_nginx_source=hashlib.sha256(files['nginx.conf']).hexdigest(), runtime_bundle=directory)
    write_review(review)
    if capture:
        capture.update(source_sha256=state['workspace_sha256'], frontend_sha256=digest, runtime_bundle=directory)
        capture_path = ROOT / '.local/acceptance/capture-ui.json'
        with tempfile.NamedTemporaryFile(mode='w', dir=capture_path.parent, prefix='.capture-ui-', delete=False) as file:
            replacement = pathlib.Path(file.name)
            os.chmod(replacement, 0o600)
            json.dump(capture, file, ensure_ascii=False, indent=2)
            file.write('\n')
        try:
            replacement.replace(capture_path)
        finally:
            replacement.unlink(missing_ok=True)
    print(json.dumps({key: review[key] for key in ('project', 'scope', 'runtime_backend_source', 'runtime_backend_image', 'runtime_frontend_source')}, ensure_ascii=False, indent=2))


def verify_gateway(state, review):
    """核对真实 Nginx 的 History、资源与未授权 API，不使用浏览器缓存代替服务响应。"""
    probe = '''import json, urllib.request, urllib.error
rows=[]
for app,port,prefix in [('platform',8080,'/api/v1'),('collector',8081,'/api/local/v1')]:
    paths=['/index.html','/invalid-page','/assets/missing-resource.js',prefix+'/auth/me']
    if app=='platform': paths+=['/assets','/assets/','/mcp','/.well-known/oauth-protected-resource/mcp']
    for path in paths:
        try: response=urllib.request.urlopen('http://127.0.0.1:'+str(port)+path,timeout=5)
        except urllib.error.HTTPError as error: response=error
        with response:
            row={'app':app,'path':path,'status':response.status,'content_type':response.headers.get('Content-Type',''),'cache_control':response.headers.get('Cache-Control',''),'nosniff':response.headers.get('X-Content-Type-Options',''),'location':response.headers.get('Location'),'body':response.read(32768).decode('utf-8','replace')}
            expected=401 if path.endswith('/auth/me') else 404 if path.endswith('missing-resource.js') or path in ['/mcp','/.well-known/oauth-protected-resource/mcp'] else 200
            assert row['status']==expected and not row['location'], '状态或重定向不符合路由契约'
            if expected==200: assert 'text/html' in row['content_type'] and '<div id="app"' in row['body'] and 'no-store' in row['cache_control'] and row['nosniff']=='nosniff', 'History 页面响应不完整'
            if expected==401: assert 'application/json' in row['content_type'] and json.loads(row['body'])['code']=='unauthenticated' and row['nosniff']=='nosniff', 'API 被当作前端页面或鉴权缺失'
            if expected==404: assert '<div id="app"' not in row['body'], '缺少的静态资源被当作页面'
            del row['body']
            rows.append(row)
print(json.dumps(rows,ensure_ascii=False))
'''
    result = acceptance.ssh(state['host'], ['docker', 'exec', state['project'] + '-review-1', 'python3', '-c', probe], stdout=subprocess.PIPE, timeout=60)
    rows = json.loads(result.stdout)
    report = {'scope': 'development_gateway_review', 'backend_source': review.get('runtime_backend_source', review['backend_source']), 'frontend_source': review.get('runtime_frontend_source', review['frontend_source']), 'nginx_source': review.get('runtime_nginx_source'), 'rows': rows}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


def deploy():
    if STATE.exists():
        raise ValueError('界面验收状态已经存在；请先核对当前环境')
    state = acceptance.read_state(ROOT / '.local/acceptance/remote.json')
    backend = backend_image(state)
    files, digest = frontend_files()
    metadata = json.loads(acceptance.ssh(state['host'], ['docker', 'image', 'inspect', 'nginx:alpine'], stdout=subprocess.PIPE, timeout=15).stdout)
    if len(metadata) != 1 or metadata[0].get('Architecture') != 'amd64' or metadata[0].get('Os') != 'linux' or not any(name.startswith('nginx@sha256:') for name in metadata[0].get('RepoDigests', [])):
        raise ValueError('远程缓存缺少可核对的官方 Nginx amd64 制品')
    image = metadata[0]['Id']
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise ValueError('Nginx 镜像身份无效')
    name = 'review-' + secrets.token_hex(8)
    directory = state['directory'] + '/' + name
    # 独立内部网络不开放宿主端口，只通过授权 SSH 隧道访问专属容器。
    ports = [8080, 8081]
    database = 'sbui_' + name.removeprefix('review-')
    review = {'schema_version': 1, 'project': state['project'], 'name': name, 'directory': directory, 'database': database, 'platform_port': ports[0], 'collector_port': ports[1], 'backend_source': state['workspace_sha256'], 'frontend_source': digest, 'commit': state['commit'], 'clean_commit': state['clean_commit'], 'nginx_image': image, 'scope': 'development_ui_review'}
    config = {'tenant': 'review_' + name.removeprefix('review-'), 'database': database, 'namespace': state['project'] + '_' + name.removeprefix('review-'), 'username': 'review_' + secrets.token_hex(8), 'password': secrets.token_hex(24), 'credential_key': secrets.token_hex(32), 'platform_origin': 'http://127.0.0.1:5184', 'collector_origin': 'http://127.0.0.1:5185', 'backend_source': review['backend_source'], 'frontend_source': digest}
    security = ['no-new-privileges:true', 'seccomp=' + state['directory'] + '/bubblewrap-seccomp.json', 'apparmor=' + state['project'] + '_runner', 'systempaths=unconfined']
    runtime = {'image': backend, 'platform': 'linux/amd64', 'pull_policy': 'never', 'read_only': True, 'cap_drop': ['ALL'], 'security_opt': security, 'user': '65532:65532', 'tmpfs': ['/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777'], 'mem_limit': '1g', 'cpus': '2', 'pids_limit': 512, 'volumes': [directory + '/data:/data', directory + ':/review:ro'], 'entrypoint': ['python3', '/review/runtime.py'], 'environment': {key: '${' + key + '}' for key in ('SB_RUNTIME_DB_PASSWORD', 'REDIS_PASSWORD', 'NATS_TOKEN')}}
    initialize = dict(runtime, command=['initialize'], environment=dict(runtime['environment'], POSTGRES_PASSWORD='${POSTGRES_PASSWORD}'), volumes=[*runtime['volumes'], directory + '/helper:/source/.review-helper:ro'], tmpfs=['/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777'], mem_limit='2g')
    definition = {'services': {'review-init': initialize, 'review': dict(runtime, healthcheck={'test': ['CMD', 'curl', '--fail', '--silent', 'http://127.0.0.1:28080/readyz'], 'interval': '5s', 'timeout': '3s', 'retries': 12}), 'review-web': {'image': image, 'pull_policy': 'never', 'network_mode': 'service:review', 'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'user': '65532:65532', 'volumes': [directory + '/ui:/ui:ro', directory + '/nginx.conf:/config/nginx.conf:ro'], 'tmpfs': ['/tmp:rw,nosuid,nodev,size=128m,mode=1777'], 'entrypoint': ['nginx'], 'command': ['-c', '/config/nginx.conf', '-g', 'daemon off;'], 'mem_limit': '256m', 'cpus': '1', 'depends_on': {'review': {'condition': 'service_healthy'}}}}}
    files['runtime.py'] = (ROOT / 'tests/acceptance/review_runtime.py').read_bytes()
    files['config.json'] = (json.dumps(config, ensure_ascii=False) + '\n').encode()
    files['compose.json'] = (json.dumps(definition, ensure_ascii=False, indent=2) + '\n').encode()
    files['nginx.conf'] = nginx_config().encode()
    files['helper/main.go'] = b'package main\nimport("os";"github.com/kkx600/StarBeacon/internal/testpcap")\nfunc main(){b,e:=testpcap.HTTP(false);if e!=nil{panic(e)};if _,e=os.Stdout.Write(b);e!=nil{panic(e)}}\n'
    upload_bundle(state, directory, files)
    acceptance.ssh(state['host'], ['mkdir', '-m', '700', directory + '/data'], timeout=15)
    acceptance.ssh(state['host'], ['chown', '-R', '65532:65532', directory], timeout=15)
    STATE.parent.mkdir(parents=True, exist_ok=True)
    # 本项目 PostgreSQL 容器中的独立数据库隔离浏览器作业与回归消费者，拒绝同名覆盖。
    acceptance.ssh(state['host'], ['docker', 'exec', state['project'] + '-postgres-1', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'starbeacon_owner', '-d', 'postgres', '-c', 'CREATE DATABASE ' + database + ' OWNER starbeacon_owner'], timeout=15)
    acceptance.ssh(state['host'], ['docker', 'exec', state['project'] + '-postgres-1', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'starbeacon_owner', '-d', 'postgres', '-c', 'REVOKE ALL ON DATABASE ' + database + ' FROM PUBLIC'], timeout=15)
    with open(STATE, 'x', opener=lambda filename, flags: os.open(filename, flags, 0o600)) as file:
        json.dump(dict(review, username=config['username'], password=config['password']), file, ensure_ascii=False, indent=2)
        file.write('\n')
    compose(state, review, ['run', '--rm', '--no-deps', 'review-init'])
    compose(state, review, ['up', '-d', '--wait', '--wait-timeout', '120', '--no-deps', 'review', 'review-web'])
    print(json.dumps({key: review[key] for key in ('project', 'name', 'platform_port', 'collector_port', 'backend_source', 'frontend_source', 'scope')}, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('deploy', 'update', 'verify-gateway', 'start', 'tunnel', 'status', 'stop'))
    arguments = parser.parse_args()
    if arguments.action == 'deploy':
        deploy()
    else:
        state, review = read_review()
        if arguments.action == 'update':
            update(state, review)
        elif arguments.action == 'verify-gateway':
            verify_gateway(state, review)
        elif arguments.action == 'tunnel':
            payload = acceptance.ssh(state['host'], ['docker', 'inspect', state['project'] + '-review-1', '--format', '{{json .NetworkSettings.Networks}}'], stdout=subprocess.PIPE, timeout=15)
            networks = json.loads(payload.stdout)
            network = networks.get(state['project'] + '_default')
            if len(networks) != 1 or not network or network.get('Gateway'):
                raise ValueError('验收容器不在本项目的独立内部网络')
            address = ipaddress.IPv4Address(network['IPAddress'])
            if not address.is_private:
                raise ValueError('验收容器地址不是私网')
            os.execvp('ssh', ['ssh', '-N', '-o', 'BatchMode=yes', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15', '-L', f'127.0.0.1:5184:{address}:8080', '-L', f'127.0.0.1:5185:{address}:8081', state['host']])
        elif arguments.action == 'start':
            ready = acceptance.ssh(state['host'], ['python3', '-c', 'import pathlib;print(pathlib.Path(' + repr(review['directory'] + '/data/ready.json') + ').is_file())'], stdout=subprocess.PIPE, timeout=15)
            if ready.stdout.strip() != b'True':
                acceptance.verify_image(state)
                compose(state, review, ['run', '--rm', '--no-deps', 'review-init'])
            compose(state, review, ['up', '-d', '--wait', '--wait-timeout', '120', '--no-deps', 'review', 'review-web'])
        else:
            compose(state, review, ['ps', '--all', 'review', 'review-web'] if arguments.action == 'status' else ['stop', 'review-web', 'review'])


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('界面验收环境未完成；仅保留本项目状态，请检查专属日志。')
