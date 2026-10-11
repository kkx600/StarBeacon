#!/usr/bin/env python3
"""在专属开发容器中启动真实角色，用于浏览器验收，不提供生产入口。"""
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse

DATA = pathlib.Path('/data')
CONFIG = pathlib.Path('/review/config.json')


def private_json(path, value):
    with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as file:
        json.dump(value, file, ensure_ascii=False)


def replace_private_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.identity-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as file:
            json.dump(value, file, ensure_ascii=False)
            file.write('\n')
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)


def initialize():
    settings = json.loads(CONFIG.read_text())
    database = settings['database']
    if not re.fullmatch(r'sbui_[a-f0-9]{16}', database):
        raise ValueError('界面验收数据库身份无效')
    if (DATA / 'ready.json').exists():
        raise ValueError('验收初始化已经完成，禁止覆盖身份或配置')
    quote = lambda text: urllib.parse.quote(text, safe='')
    environment = dict(os.environ, SB_MODE='development', GOCOVERDIR=str(DATA / 'counters'))
    (DATA / 'counters').mkdir(mode=0o700)
    environment['SB_MIGRATION_DATABASE_URL'] = 'postgres://starbeacon_owner:' + quote(environment['POSTGRES_PASSWORD']) + '@postgres:5432/' + database + '?sslmode=disable'
    environment['SB_BOOTSTRAP_PASSWORD'] = settings['password']
    def ctl(*arguments):
        result = subprocess.run(['starbeaconctl', *arguments], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=65)
        if result.returncode:
            raise ValueError('验收初始化失败：' + arguments[0])
        return result.stdout
    ctl('migrate')
    ctl('runtime-role')
    ctl('bootstrap', '--tenant', settings['tenant'], '--username', settings['username'], '--name', '浏览器验收')
    ctl('dev-pki', '--dir', str(DATA / 'pki'))
    ctl('command-keys', '--dir', str(DATA / 'trust'))
    identity = json.loads(ctl('provision-agent', '--tenant', settings['tenant'], '--sensor', 'sensor_review', '--name', '验收探针', '--ca-dir', str(DATA / 'pki'), '--dir', str(DATA / 'sensor')))
    common = {
        'SB_MODE': 'development',
        'SB_TRUSTED_PROXY_CIDRS': '127.0.0.1/32,::1/128',
        'SB_DATABASE_URL': 'postgres://starbeacon_app:' + quote(environment['SB_RUNTIME_DB_PASSWORD']) + '@postgres:5432/' + database + '?sslmode=disable',
        'SB_NATS_URL': 'nats://' + quote(environment['NATS_TOKEN']) + '@nats:4222',
        'SB_NATS_NAMESPACE': settings['namespace'], 'SB_NATS_REPLICAS': '1', 'SB_STREAM_BYTES': '16777216',
        'SB_ES_URL': 'http://elasticsearch:9200',
        'SB_REDIS_URL': 'redis://:' + quote(environment['REDIS_PASSWORD']) + '@redis:6379/15',
        'SB_TLS_CA': str(DATA / 'pki/ca.crt'), 'SB_TLS_CERT': str(DATA / 'pki/server.crt'), 'SB_TLS_KEY': str(DATA / 'pki/server.key'),
        'SB_CREDENTIAL_KEY': settings['credential_key'],
    }
    platform = dict(common, SB_HTTP_ADDR='127.0.0.1:28080', SB_GRPC_ADDR='127.0.0.1:29091', SB_ALLOWED_ORIGIN=settings['platform_origin'], SB_COMMAND_SIGNING_KEY=str(DATA / 'trust/command.key'), SB_REPLAY_BACKEND='filesystem', SB_REPLAY_DIR=str(DATA / 'platform-samples'), SB_REPLAY_BYTES='104857600')
    ingest = dict(common, SB_HTTP_ADDR='127.0.0.1:28180', SB_GRPC_ADDR='127.0.0.1:29090')
    worker = dict(common, SB_HTTP_ADDR='127.0.0.1:28181')
    collector = {
        'SB_MODE': 'development', 'SB_HTTP_ADDR': '127.0.0.1:28081', 'SB_ALLOWED_ORIGIN': settings['collector_origin'],
        'SB_TRUSTED_PROXY_CIDRS': '127.0.0.1/32,::1/128',
        'SB_LOCAL_PASSWORD': settings['password'], 'SB_TENANT_ID': identity['TenantID'], 'SB_SENSOR_ID': identity['SensorID'], 'SB_REGISTRATION_ID': identity['RegistrationID'],
        'SB_INGEST_ADDR': '127.0.0.1:29090', 'SB_PLATFORM_ADDR': '127.0.0.1:29091',
        'SB_TLS_CA': common['SB_TLS_CA'], 'SB_TLS_CERT': str(DATA / 'sensor/agent.crt'), 'SB_TLS_KEY': str(DATA / 'sensor/agent.key'),
        'SB_COMMAND_PUBLIC_KEY': str(DATA / 'trust/command.pub'), 'SB_EVE_PATH': str(DATA / 'capture/eve.json'),
        'SB_STATE_PATH': str(DATA / 'agent.db'), 'SB_REPLAY_DIR': str(DATA / 'collector-samples'), 'SB_REPLAY_BYTES': '104857600',
        'SB_SURICATA_BINARY': '/usr/bin/suricata', 'SB_SURICATA_CONFIG': '/etc/suricata/suricata.yaml',
    }
    for name, value in [('platform', platform), ('ingest', ingest), ('worker', worker), ('agent', collector)]:
        private_json(DATA / (name + '.json'), value)
    (DATA / 'capture').mkdir(mode=0o700)
    with (DATA / 'sample.pcap').open('xb') as packet:
        subprocess.run(['go', 'run', '/source/.review-helper/main.go'], cwd='/source', env=dict(environment, GOPROXY='off', CGO_ENABLED='0'), stdout=packet, check=True, timeout=120)
    (DATA / 'rules.rules').write_text('alert http any any -> any any (msg:"StarBeacon 界面验收流量"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1000999; rev:1;)\n')
    (DATA / 'capture.yaml').write_text('%YAML 1.1\n---\nrun-as: {}\nunix-command:\n  enabled: no\noutputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      ethernet: yes\n      types:\n        - alert\n        - http\n        - flow\n        - stats:\n            totals: yes\n            threads: no\n')
    with (DATA / 'capture.log').open('xb') as log:
        subprocess.run(['/usr/bin/suricata', '-c', '/etc/suricata/suricata.yaml', '--include', str(DATA / 'capture.yaml'), '-r', str(DATA / 'sample.pcap'), '-S', str(DATA / 'rules.rules'), '-l', str(DATA / 'capture'), '--runmode', 'single'], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
    if not (DATA / 'capture/eve.json').is_file():
        raise ValueError('原生离线分析没有产生 EVE')
    private_json(DATA / 'ready.json', {'tenant': settings['tenant'], 'scope': 'development_ui_review', 'backend_source': settings['backend_source'], 'frontend_source': settings['frontend_source']})
    print('专属验收身份、配置和原生离线流量已就绪')


def supervised_roles(settings):
    """独立网卡采集器与内嵌 EVE 采集器不能共用注册身份并发执行。"""
    mode = settings.get('collector_execution', 'embedded')
    if mode not in ('embedded', 'isolated_managed'):
        raise ValueError('界面验收采集器执行方式无效')
    roles = [('platform', 'starbeacon'), ('ingest', 'starbeacon-ingest'), ('worker', 'starbeacon-worker')]
    if mode == 'embedded':
        roles.append(('agent', 'starbeacon-agent'))
    return roles


def supervise():
    if not (DATA / 'ready.json').is_file():
        raise ValueError('需要先完成验收初始化')
    environment = {key: value for key, value in os.environ.items() if not key.startswith('SB_') and key not in ('POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'NATS_TOKEN', 'GOCOVERDIR')}
    children, logs = [], []
    stopped = False
    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for name, binary in supervised_roles(json.loads(CONFIG.read_text())):
            config = json.loads((DATA / (name + '.json')).read_text())
            log = (DATA / (name + '.log')).open('ab')
            logs.append(log)
            children.append(subprocess.Popen([binary], env=dict(environment, **config, GOCOVERDIR=str(DATA / 'counters')), stdout=log, stderr=subprocess.STDOUT))
        while not stopped:
            if any(child.poll() is not None for child in children):
                raise ValueError('验收角色提前退出，请检查专属角色日志')
            time.sleep(0.2)
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 12
        for child in children:
            try:
                child.wait(timeout=max(0.1, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        for log in logs:
            log.close()


def migrate():
    """仅迁移当前界面验收数据库，保留租户、凭据、采集样本与业务记录。"""
    settings = json.loads(CONFIG.read_text())
    ready = json.loads((DATA / 'ready.json').read_text())
    database = settings['database']
    if not re.fullmatch(r'sbui_[a-f0-9]{16}', database) or ready['tenant'] != settings['tenant'] or ready['scope'] != 'development_ui_review':
        raise ValueError('界面验收迁移身份不一致')
    configs = []
    for name in ('platform', 'agent'):
        path = DATA / (name + '.json')
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
            raise ValueError('界面验收身份配置无法核对')
        config = json.loads(path.read_text())
        if not isinstance(config, dict) or name == 'agent' and (config.get('SB_TENANT_ID') != settings['tenant'] or config.get('SB_SENSOR_ID') != 'sensor_review'):
            raise ValueError('采集器配置不属于本实例')
        if name == 'platform' and urllib.parse.urlparse(config.get('SB_DATABASE_URL', '')).path != '/' + database:
            raise ValueError('平台配置不属于本实例数据库')
        configs.append((path, config))
    quote = lambda text: urllib.parse.quote(text, safe='')
    environment = dict(os.environ, SB_MODE='development', GOCOVERDIR=str(DATA / 'counters'))
    environment['SB_MIGRATION_DATABASE_URL'] = 'postgres://starbeacon_owner:' + quote(environment['POSTGRES_PASSWORD']) + '@postgres:5432/' + database + '?sslmode=disable'
    for action in ('migrate', 'runtime-role'):
        result = subprocess.run(['starbeaconctl', action], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if result.returncode:
            raise ValueError('界面验收数据库迁移未完成：' + action)
    # 同一容器的代理覆盖客户端头；更新仅作用于本实例的身份配置，不轮换凭据。
    for path, config in configs:
        config['SB_TRUSTED_PROXY_CIDRS'] = '127.0.0.1/32,::1/128'
        replace_private_json(path, config)
    print('界面验收数据库结构与运行权限已就绪')


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['initialize']:
            initialize()
        elif sys.argv[1:] == ['migrate']:
            migrate()
        elif sys.argv[1:]:
            raise ValueError('界面验收运行方式无效')
        else:
            supervise()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('界面验收环境未就绪：' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
