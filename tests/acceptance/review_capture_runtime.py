#!/usr/bin/env python3
"""仅在本项目的独立 Docker 网卡环境运行托管采集器。"""
import json
import os
import pathlib
import re


def configuration(data):
    path = data / 'agent.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError('采集器验收配置文件无效')
    config = json.loads(path.read_text())
    if not isinstance(config, dict) or config.get('SB_SENSOR_ID') != 'sensor_review' or not re.fullmatch(r'review_[a-f0-9]{16}', config.get('SB_TENANT_ID', '')):
        raise ValueError('采集器验收身份无效')
    if any(key in config for key in ('SB_DATABASE_URL', 'SB_MIGRATION_DATABASE_URL', 'SB_REDIS_URL', 'SB_NATS_URL')):
        raise ValueError('采集器不得持有平台依赖凭据')
    config.update(SB_CAPTURE_MANAGED='true', SB_CAPTURE_SPOOL_BYTES='104857600', SB_CAPTURE_ROTATE_BYTES='4194304', SB_TRUSTED_PROXY_CIDRS='127.0.0.1/32,::1/128')
    return config


def main():
    capability = next(line.split()[1] for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    if os.geteuid() != 0 or int(capability, 16) != ((1 << 13) | (1 << 31)):
        raise ValueError('采集器权限超出验收范围')
    data = pathlib.Path('/data')
    config = configuration(data)
    counters = data / 'capture-review-counters'
    counters.mkdir(mode=0o700, exist_ok=True)
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp', 'TMPDIR': '/tmp', 'GOCOVERDIR': str(counters), **config}
    os.execve('/usr/local/bin/starbeacon-agent', ['starbeacon-agent'], environment)


if __name__ == '__main__':
    main()
