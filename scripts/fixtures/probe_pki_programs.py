#!/usr/bin/env python3
"""在专属容器内验证实际 Go 程序的证书与事件链路；合成 EVE 不代表原生捕获验收。"""
import base64
import datetime
import hashlib
import http.client
import http.cookiejar
import http.server
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DATA = pathlib.Path('/data')
ORIGIN = 'http://127.0.0.1:29999'


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp(value=None):
    return (value or now()).isoformat()


def save(path, value):
    with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write('\n')


class EnrollmentGateway(http.server.BaseHTTPRequestHandler):
    # 仅提供设备注册的测试 TLS 入口，不能作为产品网关或生产 TLS 资格。
    def log_message(self, *_args):
        pass

    def do_POST(self):
        size = self.headers.get('Content-Length', '')
        if self.path != '/api/v1/sensor-enrollments/exchange' or not size.isdecimal() or not 0 < int(size) <= 24576:
            self.send_error(400)
            return
        upstream = http.client.HTTPConnection('127.0.0.1', 28080, timeout=20)
        try:
            upstream.request('POST', self.path, body=self.rfile.read(int(size)), headers={'Content-Type': 'application/json'})
            response = upstream.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError('测试网关上游响应超限')
            self.send_response(response.status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        finally:
            upstream.close()


def main():
    if (DATA / 'started.json').exists():
        raise ValueError('测试目录已有执行记录，拒绝复用凭据和旧结果')
    identifier = secrets.token_hex(8)
    tenant, sensor, registration = 'pki_program_' + identifier, 'probe_program', 'reg_program'
    username = 'pki_program_admin_' + identifier
    password = secrets.token_urlsafe(32)
    save(DATA / 'started.json', {'scope': 'isolated_actual_program_pki', 'tenant': tenant, 'started_at': stamp()})
    inherited = dict(os.environ)
    quote = lambda value: urllib.parse.quote(value, safe='')
    owner_url = 'postgres://starbeacon_owner:' + quote(inherited['POSTGRES_PASSWORD']) + '@postgres:5432/starbeacon?sslmode=disable'
    runtime_url = 'postgres://starbeacon_app:' + quote(inherited['SB_RUNTIME_DB_PASSWORD']) + '@postgres:5432/starbeacon?sslmode=disable'
    (DATA / 'counters').mkdir(mode=0o700)
    minimal = {key: value for key, value in inherited.items() if not key.startswith('SB_') and key not in ('POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'NATS_TOKEN', 'GOCOVERDIR')}
    common = dict(minimal, SB_MODE='development', SB_NATS_REPLICAS='1', SB_DATABASE_URL=runtime_url,
                  SB_NATS_URL='nats://' + quote(inherited['NATS_TOKEN']) + '@nats:4222', SB_NATS_NAMESPACE='pkiprog_' + identifier,
                  SB_STREAM_BYTES='16777216', SB_REDIS_URL='redis://:' + quote(inherited['REDIS_PASSWORD']) + '@redis:6379/14',
                  SB_ES_URL='http://elasticsearch:9200', GOCOVERDIR=str(DATA / 'counters'))

    def ctl(arguments, environment):
        result = subprocess.run(['starbeaconctl', *arguments], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if result.returncode:
            raise ValueError('实际管理工具未成功：' + arguments[0])
        return result.stdout

    owner = dict(minimal, SB_MODE='development', SB_MIGRATION_DATABASE_URL=owner_url, SB_BOOTSTRAP_PASSWORD=password, GOCOVERDIR=str(DATA / 'counters'))
    ctl(['bootstrap', '--tenant', tenant, '--username', username, '--name', '证书程序验收'], owner)
    ctl(['dev-pki', '--dir', str(DATA / 'server-pki')], owner)
    server = DATA / 'server-pki'
    bundle = server.joinpath('ca.crt').read_bytes() + pathlib.Path('/run/probe-ca/root_ca.crt').read_bytes()
    roots = DATA / 'client-roots.crt'
    roots.write_bytes(bundle)
    roots.chmod(0o600)
    tls = dict(SB_TLS_CA=str(roots), SB_TLS_CERT=str(server / 'server.crt'), SB_TLS_KEY=str(server / 'server.key'))
    configurations = {
        'platform': ('starbeacon', dict(common, **tls, SB_HTTP_ADDR='127.0.0.1:28080', SB_GRPC_ADDR='127.0.0.1:29091', SB_ALLOWED_ORIGIN=ORIGIN,
                                      SB_PROBE_CA_URL='https://step-ca:9000', SB_PROBE_CA_ROOT='/run/probe-ca/root_ca.crt', SB_PROBE_CA_PROVISIONER='starbeacon-probes',
                                      SB_PROBE_CA_JWK='/run/probe-ca/provisioner.jwk', SB_PROBE_CERTIFICATE_SECONDS='300',
                                      SB_REPLAY_BACKEND='filesystem', SB_REPLAY_DIR=str(DATA / 'platform-samples'), SB_REPLAY_BYTES='104857600')),
        'ingest': ('starbeacon-ingest', dict(common, **tls, SB_HTTP_ADDR='127.0.0.1:28180', SB_GRPC_ADDR='127.0.0.1:29090')),
        'worker': ('starbeacon-worker', dict(common, **tls, SB_HTTP_ADDR='127.0.0.1:28181')),
    }
    processes, logs = {}, []
    gateway = None
    result = None
    forced = []

    def start(role, binary, environment):
        log = (DATA / (role + '.log')).open('xb')
        logs.append(log)
        processes[role] = subprocess.Popen([binary], env=environment, stdout=log, stderr=subprocess.STDOUT)

    def alive():
        for role, process in processes.items():
            if process.poll() is not None:
                raise ValueError('实际 Go 程序提前退出：' + role)

    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    csrf = ''

    def api(method, path, body=None, local=False):
        port, prefix = (28081, '/api/local/v1') if local else (28080, '/api/v1')
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        headers = {'Content-Type': 'application/json', 'Origin': ORIGIN}
        if csrf and not local:
            headers['X-CSRF-Token'] = csrf
        request = urllib.request.Request('http://127.0.0.1:' + str(port) + prefix + path, data=data, headers=headers, method=method)
        with client.open(request, timeout=15) as response:
            return json.load(response)

    def wait_http(port):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            alive()
            try:
                with urllib.request.urlopen('http://127.0.0.1:' + str(port) + '/readyz', timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.2)
        raise ValueError('实际 Go 程序未就绪：' + str(port))

    try:
        for role, (binary, environment) in configurations.items():
            start(role, binary, environment)
        for port in (28080, 28180, 28181):
            wait_http(port)
        user = api('POST', '/auth/login', {'username': username, 'password': password})
        csrf = user['csrf_token']
        token = '.'.join(['sbe1', tenant, sensor, registration, 'enroll_program', base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')])
        receipt = api('POST', '/sensor-enrollments', {'token': token, 'name': '程序证书验收探针', 'ttl_seconds': 3600})
        if receipt['sensor_id'] != sensor or receipt['registration_id'] != registration:
            raise ValueError('真实平台注册凭据绑定不符')
        token_file = DATA / 'enrollment.token'
        with open(token_file, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as file:
            file.write(token + '\n')
        gateway = http.server.ThreadingHTTPServer(('127.0.0.1', 28443), EnrollmentGateway)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(server / 'server.crt', server / 'server.key')
        gateway.socket = context.wrap_socket(gateway.socket, server_side=True)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        identity = DATA / 'identity'
        initial = json.loads(ctl(['enroll-agent', '--dir', str(identity), '--token-file', str(token_file), '--ca-file', '/run/probe-ca/root_ca.crt',
                                  '--platform-ca-file', str(server / 'ca.crt'), '--platform-url', 'https://127.0.0.1:28443'], common))
        token_file.unlink()
        eve = DATA / 'eve.json'
        eve.write_bytes(b'')
        agent = dict(minimal, SB_MODE='development', SB_HTTP_ADDR='127.0.0.1:28081', SB_ALLOWED_ORIGIN=ORIGIN, SB_LOCAL_PASSWORD=password,
                     SB_TENANT_ID=tenant, SB_SENSOR_ID=sensor, SB_REGISTRATION_ID=registration,
                     SB_TLS_CA=str(server / 'ca.crt'), SB_IDENTITY_DIR=str(identity), SB_IDENTITY_ROOT='/run/probe-ca/root_ca.crt',
                     SB_PLATFORM_ADDR='127.0.0.1:29091', SB_INGEST_ADDR='127.0.0.1:29090', SB_STATE_PATH=str(DATA / 'agent.db'), SB_EVE_PATH=str(eve),
                     SB_REPLAY_DIR=str(DATA / 'collector-samples'), SB_REPLAY_BYTES='104857600', SB_WAL_BYTES='16777216', GOCOVERDIR=str(DATA / 'counters'))
        start('agent', 'starbeacon-agent', agent)
        wait_http(28081)
        api('POST', '/auth/login', {'username': 'admin', 'password': password}, local=True)
        start_at = now() - datetime.timedelta(minutes=1)

        def append_event(flow):
            event = {'timestamp': stamp(), 'event_type': 'alert', 'flow_id': flow, 'src_ip': '192.0.2.10', 'dest_ip': '198.51.100.20',
                     'src_port': 54321, 'dest_port': 80, 'proto': 'TCP', 'app_proto': 'http',
                     'http': {'http_method': 'GET', 'url': '/starbeacon/pki-program-acceptance', 'hostname': 'fixture.example.test'},
                     'alert': {'signature_id': 9100148, 'rev': 1, 'signature': 'StarBeacon 证书程序合成验收事件', 'severity': 1, 'action': 'allowed'}}
            with eve.open('ab') as file:
                file.write(json.dumps(event, ensure_ascii=False).encode() + b'\n')
                file.flush()
                os.fsync(file.fileno())

        def wait_events(minimum):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                alive()
                result = api('POST', '/alerts/search', {'start': stamp(start_at), 'end': stamp(now() + datetime.timedelta(seconds=1)),
                                                       'page': 1, 'page_size': 20, 'path': '/starbeacon/pki-program-acceptance'})
                if result['total'] >= minimum:
                    if any(item.get('sensor_id') != sensor for item in result['items']):
                        raise ValueError('事件来源未绑定实际探针')
                    return result['total']
                time.sleep(0.5)
            raise ValueError('真实程序的合成事件未通过 mTLS、队列及索引链路')

        append_event(18446744073709551613)
        wait_events(1)
        renewal_started = time.monotonic()
        current = initial
        while time.monotonic() - renewal_started < 300:
            alive()
            current = api('GET', '/identity', local=True)
            if current['fingerprint_sha256'] != initial['fingerprint_sha256']:
                break
            time.sleep(0.5)
        if current['fingerprint_sha256'] == initial['fingerprint_sha256']:
            raise ValueError('实际采集器程序未按真实时钟完成续签')
        renewed_seconds = time.monotonic() - renewal_started
        append_event(18446744073709551614)
        wait_events(2)
        certificates = api('GET', '/sensors/' + sensor + '/certificates')['items']
        if len(certificates) != 2:
            raise ValueError('真实程序续签档案数量不符')
        old = next(item for item in certificates if item['fingerprint_sha256'] == initial['fingerprint_sha256'])
        revoked = api('POST', '/sensor-certificates/' + old['id'] + '/revoke', {})
        if not revoked.get('revoked_at') or revoked['ca_revocation'] != 'confirmed':
            raise ValueError('实际平台程序未取得 CA 吊销确认')
        append_event(18446744073709551615)
        total = wait_events(3)
        result = {'schema_version': 1, 'status': 'passed', 'scope': 'actual_go_programs_pki_and_synthetic_eve_pipeline',
                  'source': inherited['SB_PROGRAM_SOURCE'], 'roles': list(processes), 'roles_alive': True,
                  'initial_fingerprint_sha256': initial['fingerprint_sha256'], 'renewed_fingerprint_sha256': current['fingerprint_sha256'],
                  'renewal_seconds': round(renewed_seconds, 3), 'ca_revocation': revoked['ca_revocation'], 'indexed_events': total,
                  'probe_ca_root_and_intermediate_private_keys_not_mounted': True, 'shared_test_role_filesystem': True,
                  'native_capture_qualification': False, 'production_tls_ha_qualification': False, 'finished_at': stamp()}
    finally:
        if gateway:
            gateway.shutdown()
            gateway.server_close()
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
        for role, process in processes.items():
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                forced.append(role)
                process.kill()
                process.wait(timeout=5)
        for log in logs:
            log.close()
    if result is not None:
        result['role_exit_codes'] = {role: process.returncode for role, process in processes.items()}
        result['binaries'] = {name: hashlib.sha256(pathlib.Path('/usr/local/bin', name).read_bytes()).hexdigest()
                              for name in ('starbeacon', 'starbeacon-ingest', 'starbeacon-worker', 'starbeacon-agent', 'starbeaconctl')}
        if forced or any(code != 0 for code in result['role_exit_codes'].values()):
            raise ValueError('实际 Go 程序未正常退出')
        save(DATA / 'result.json', result)
        print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        print('实际程序证书验收未通过：' + (str(error) if isinstance(error, ValueError) else type(error).__name__), flush=True)
        raise SystemExit(1)
