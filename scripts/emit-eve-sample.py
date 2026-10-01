#!/usr/bin/env python3
"""向独立开发 EVE 文件追加标记为验收样本的事件，不发送网络流量。"""
import datetime
import json
import os
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
path = root / ".local/eve.json"
if not path.parent.exists():
    raise SystemExit("请先执行 make dev-setup。")
event = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "event_type": "alert", "flow_id": 18446744073709551614,
    "src_ip": "192.0.2.10", "dest_ip": "198.51.100.20", "src_port": 54321, "dest_port": 80,
    "proto": "TCP", "app_proto": "http",
    "ether": {"src_mac": "02:00:00:00:00:10", "dest_mac": "02:00:00:00:00:20"},
    "http": {"http_method": "POST", "url": "/starbeacon/acceptance", "hostname": "test.example"},
    "alert": {"signature_id": 9100001, "rev": 1, "signature": "StarBeacon 工程验收样本", "severity": 1, "action": "allowed"},
}
with path.open("ab") as file:
    file.write((json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
    file.flush()
    os.fsync(file.fileno())
print("已向开发 EVE 来源追加一条工程验收样本。")
