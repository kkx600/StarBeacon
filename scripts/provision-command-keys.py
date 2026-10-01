#!/usr/bin/env python3
"""将平台命令信任绑定到独立签名密钥；现有凭据保持原值。"""
import pathlib
import shlex
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
directory = root / ".local/commands"
private = directory / "command.key"
public = directory / "command.pub"
if not private.exists() and not public.exists():
    subprocess.run([str(root / "bin/starbeaconctl"), "command-keys", "--dir", str(directory)], check=True)
if not private.exists() or not public.exists():
    raise SystemExit("任务密钥不完整；请核对原信任配置，不自动覆盖。")
for filename, name, value in [("platform.env", "SB_COMMAND_SIGNING_KEY", private), ("collector.env", "SB_COMMAND_PUBLIC_KEY", public)]:
    path = root / ".local" / filename
    existing = path.read_text()
    if not any(line.startswith(name + "=") for line in existing.splitlines()):
        with path.open("a") as file:
            if existing and not existing.endswith("\n"):
                file.write("\n")
            file.write(name + "=" + shlex.quote(str(value)) + "\n")
print("平台任务签名与采集器公钥配置已就绪。")
