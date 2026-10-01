#!/usr/bin/env python3
"""将本地管理工具返回的身份写入独立采集器配置。"""
import json
import pathlib
import secrets
import shlex
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
local = root / ".local"
target = local / "collector.env"
if target.exists():
    print("采集器配置已存在，注册身份保留。")
    raise SystemExit(0)
identity = json.loads(subprocess.check_output([sys.executable, str(root / "scripts/env-run.py"), str(local / "owner.env"), str(root / "bin/starbeaconctl"), "provision-agent", "--tenant", "tenant_local", "--sensor", "sensor_local", "--name", "本地采集器", "--dir", str(local / "collector"), "--ca-dir", str(local / "pki")], cwd=root))
values = {
    "SB_MODE": "development", "SB_HTTP_ADDR": "127.0.0.1:28081", "SB_ALLOWED_ORIGIN": "http://127.0.0.1:5175",
    "SB_TENANT_ID": identity["TenantID"], "SB_SENSOR_ID": identity["SensorID"], "SB_REGISTRATION_ID": identity["RegistrationID"],
    "SB_TLS_CA": str(local / "pki/ca.crt"), "SB_TLS_CERT": str(local / "collector/agent.crt"), "SB_TLS_KEY": str(local / "collector/agent.key"),
    "SB_PLATFORM_ADDR": "127.0.0.1:29091", "SB_INGEST_ADDR": "127.0.0.1:29090",
    "SB_EVE_PATH": str(local / "eve.json"), "SB_STATE_PATH": str(local / "collector/agent.db"), "SB_LOCAL_PASSWORD": secrets.token_urlsafe(24),
}
with target.open("x") as file:
    file.write("".join(f"{k}={shlex.quote(v)}\n" for k, v in values.items()))
target.chmod(0o600)
(local / "eve.json").touch(exist_ok=True)
print("采集器已登记；本地管理员密码位于 .local/collector.env。")
