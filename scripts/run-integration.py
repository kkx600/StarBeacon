#!/usr/bin/env python3
"""仅将本项目的开发配置传给真实依赖集成测试，不打印凭据。"""
import os
import pathlib
import shlex
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy()
for name in ["owner.env", "platform.env"]:
    for line in (root / ".local" / name).read_text().splitlines():
        key, value = line.split("=", 1)
        env[key] = shlex.split(value)[0]
if env.get("SB_MODE") != "development" or not all("127.0.0.1" in env[key] for key in ["SB_MIGRATION_DATABASE_URL", "SB_DATABASE_URL", "SB_NATS_URL", "SB_ES_URL"]):
    raise SystemExit("集成测试要求独立回环开发依赖。")
env["GOTOOLCHAIN"] = "local"
go = sys.argv[1] if len(sys.argv) > 1 else "go"
raise SystemExit(subprocess.call([go, "test", "-race", "-tags=integration", "-count=1", "-timeout=90s", "-v", "./tests/integration"], env=env, cwd=root))
