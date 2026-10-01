#!/usr/bin/env python3
"""生成独立开发凭据；重跑不会覆盖已有秘密或重新签发身份。"""
import pathlib
import secrets
import shlex

root = pathlib.Path(__file__).resolve().parents[1]
local = root / ".local"
local.mkdir(mode=0o700, exist_ok=True)

def write(name, values):
    path = local / name
    if path.exists():
        return
    with path.open("x") as file:
        file.write("".join(f"{k}={shlex.quote(str(v))}\n" for k, v in values.items()))
    path.chmod(0o600)

def read(name):
    return dict((k, shlex.split(v)[0]) for k, v in (line.split("=", 1) for line in (local / name).read_text().splitlines()))

write("compose.env", {key: secrets.token_urlsafe(32) for key in ["SB_DEV_DB_OWNER_PASSWORD", "SB_DEV_REDIS_PASSWORD", "SB_DEV_NATS_TOKEN"]})
compose = read("compose.env")
write("owner.env", {"SB_MIGRATION_DATABASE_URL": f"postgres://starbeacon_owner:{compose['SB_DEV_DB_OWNER_PASSWORD']}@127.0.0.1:25432/starbeacon?sslmode=disable", "SB_RUNTIME_DB_PASSWORD": secrets.token_urlsafe(32), "SB_BOOTSTRAP_PASSWORD": secrets.token_urlsafe(24)})
owner = read("owner.env")
shared = {
    "SB_MODE": "development",
    "SB_DATABASE_URL": f"postgres://starbeacon_app:{owner['SB_RUNTIME_DB_PASSWORD']}@127.0.0.1:25432/starbeacon?sslmode=disable",
    "SB_NATS_URL": f"nats://{compose['SB_DEV_NATS_TOKEN']}@127.0.0.1:24222",
    "SB_REDIS_URL": f"redis://:{compose['SB_DEV_REDIS_PASSWORD']}@127.0.0.1:26379/0",
    "SB_ES_URL": "http://127.0.0.1:29200",
    "SB_NATS_REPLICAS": "1",
    "SB_NATS_NAMESPACE": "sb_dev",
    "SB_TLS_CA": str(local / "pki/ca.crt"),
    "SB_TLS_CERT": str(local / "pki/server.crt"),
    "SB_TLS_KEY": str(local / "pki/server.key"),
    "SB_ALLOWED_ORIGIN": "http://127.0.0.1:5174",
}
write("platform.env", shared)
write("login.env", {"SB_USERNAME": "admin", "SB_PASSWORD": owner["SB_BOOTSTRAP_PASSWORD"]})
print("开发配置位于 .local/，平台登录凭据位于 .local/login.env；现有文件保留。")
