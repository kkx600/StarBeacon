#!/usr/bin/env python3
"""只解析环境赋值，不将环境文件作为 Shell 代码执行。"""
import os
import pathlib
import shlex
import sys

if len(sys.argv) < 3:
    raise SystemExit("用法: env-run.py <环境文件> <命令> [参数]")
values = dict(os.environ)
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    name, value = line.split("=", 1)
    if not name.replace("_", "").isalnum() or name[0].isdigit():
        raise SystemExit("环境变量名称不合法")
    parsed = shlex.split(value)
    values[name] = parsed[0] if parsed else ""
os.execvpe(sys.argv[2], sys.argv[2:], values)
