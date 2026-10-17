#!/usr/bin/env python3
"""在已通过基础验收的专属 Docker 项目内验证实际 Go 程序，不操作常驻业务实例。"""
import argparse
import hashlib
import json
import pathlib
import secrets
import subprocess

import remote_acceptance as acceptance
import remote_review

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(state_path, output):
    state = acceptance.read_state(state_path)
    output = output.absolute()
    if '..' in output.parts or not output.is_relative_to(ROOT / '.local/acceptance') or output.exists() or output.is_symlink() or any(parent.is_symlink() for parent in output.parents):
        raise ValueError('实际程序证据要求全新的工程私有目录')
    if acceptance.snapshot_sources()[1] != state['workspace_sha256'] or not state.get('step_ca_image'):
        raise ValueError('当前源码或独立 CA 身份不符')
    acceptance.verify_image(state)
    report = json.loads(acceptance.ssh(state['host'], ['cat', state['directory'] + '/reports/backend.json'], stdout=subprocess.PIPE, timeout=20).stdout)
    if report.get('status') != 'passed' or report.get('workspace_sha256') != state['workspace_sha256'] or report.get('coverage', {}).get('percentage', 0) < 90:
        raise ValueError('当前源码的后端与实际网卡门禁尚未通过')
    metadata = json.loads(acceptance.ssh(state['host'], ['docker', 'image', 'inspect', acceptance.image_name(state)], stdout=subprocess.PIPE, timeout=20).stdout)[0]
    attempt = secrets.token_hex(4)
    directory = state['directory'] + '/program-pki-' + state['workspace_sha256'][:16] + '-' + attempt
    project = state['project'] + '_pki_programs_' + attempt
    create = "import pathlib,sys,os; p=pathlib.Path(sys.argv[1]); p.mkdir(mode=0o700); d=p/'data'; d.mkdir(mode=0o700); os.chown(d,65532,65532)"
    acceptance.ssh(state['host'], ['python3', '-c', create, directory], timeout=20)
    source = (ROOT / 'scripts/fixtures/probe_pki_programs.py').read_bytes()
    remote_review.upload_bundle(state, directory + '/fixture', {'probe_pki_programs.py': source}, timeout=30)
    service = {'image': metadata['Id'], 'platform': 'linux/amd64', 'pull_policy': 'never', 'init': True,
               'user': '65532:65532', 'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
               'pids_limit': 512, 'mem_limit': '2g', 'cpus': '4', 'tmpfs': ['/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777'],
               'entrypoint': ['python3', '/fixture/probe_pki_programs.py'],
               'environment': {**{key: '${' + key + '}' for key in ('POSTGRES_PASSWORD', 'SB_RUNTIME_DB_PASSWORD', 'REDIS_PASSWORD', 'NATS_TOKEN')},
                               'SB_PROGRAM_SOURCE': state['workspace_sha256']},
               'volumes': [directory + '/data:/data', directory + '/fixture/probe_pki_programs.py:/fixture/probe_pki_programs.py:ro',
                           *[state['directory'] + '/pki/platform/' + name + ':/run/probe-ca/' + name + ':ro' for name in ('root_ca.crt', 'provisioner.jwk')]],
               'labels': {'io.starbeacon.acceptance.source': state['workspace_sha256'], 'io.starbeacon.fixture.type': 'actual-program-pki'}}
    definition = {'services': {'programs': service}, 'networks': {'default': {'external': True, 'name': state['project'] + '_default'}}}
    acceptance.ssh(state['host'], ['tee', directory + '/compose.json'], input=(json.dumps(definition, indent=2) + '\n').encode(), stdout=subprocess.DEVNULL, timeout=20)
    output.mkdir(mode=0o700, parents=True)
    name = project + '-programs'
    command = ['docker', 'compose', '--env-file', state['directory'] + '/dependencies.env', '-p', project, '-f', directory + '/compose.json']
    try:
        with (output / 'execution.log').open('xb') as log:
            acceptance.ssh(state['host'], [*command, 'run', '--no-deps', '--name', name, 'programs'], stdout=log, stderr=subprocess.STDOUT, timeout=600)
    finally:
        actual = json.loads(acceptance.ssh(state['host'], ['docker', 'inspect', '--format', '{{json .}}', name], stdout=subprocess.PIPE, timeout=20).stdout)
        observed = {'source': state['workspace_sha256'], 'image_id': actual['Image'], 'container_id': actual['Id'],
                    'actual_exit_code': actual['State']['ExitCode'], 'running': actual['State']['Running'], 'oom_killed': actual['State']['OOMKilled'],
                    'fixture_sha256': hashlib.sha256(source).hexdigest(), 'project': project, 'directory': directory}
        (output / 'execution.json').write_text(json.dumps(observed, indent=2) + '\n')
    if observed['running'] or observed['actual_exit_code'] != 0 or observed['oom_killed'] or observed['image_id'] != metadata['Id']:
        raise ValueError('实际程序容器没有通过验收')
    result = json.loads(acceptance.ssh(state['host'], ['cat', directory + '/data/result.json'], stdout=subprocess.PIPE, timeout=20).stdout)
    if result.get('status') != 'passed' or result.get('source') != state['workspace_sha256']:
        raise ValueError('实际程序结果与当前源码不符')
    (output / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'source': result['source'], 'renewal_seconds': result['renewal_seconds'], 'indexed_events': result['indexed_events']}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        run(args.state, args.output)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('实际程序证书验收未完成：' + (str(error) if isinstance(error, ValueError) else type(error).__name__))
        raise SystemExit(1)
