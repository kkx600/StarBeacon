#!/usr/bin/env python3
"""在专属 Docker 网卡上运行实际采集链路；没有宿主网络或网络管理权限。"""
import hashlib
import json
import os
import pathlib
import subprocess
import time
import urllib.parse

def main():
    report_dir = pathlib.Path("/reports/capture")
    report_dir.mkdir(mode=0o755, exist_ok=True)
    # NET_RAW 用于本命名空间的原始套接字，SETFCAP 用于 UID 0 的隔离用户映射。
    # 两项权限都受本容器边界约束，规则验证子进程移除全部 capabilities。
    capability = next(line.split()[1] for line in pathlib.Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:"))
    if os.geteuid() != 0 or int(capability, 16) != ((1 << 13) | (1 << 31)):
        raise ValueError("网卡验收容器权限必须为 NET_RAW 与 SETFCAP")
    environment = dict(os.environ, SB_MODE="development", SB_TEST_SURICATA_BINARY="/usr/bin/suricata", SB_TEST_SURICATA_CONFIG="/etc/suricata/suricata.yaml", SB_TEST_MANAGEMENT_BINARY="/usr/local/bin/starbeaconctl")
    quote = urllib.parse.quote
    environment["SB_MIGRATION_DATABASE_URL"] = "postgres://starbeacon_owner:" + quote(environment.pop("POSTGRES_PASSWORD"), safe="") + "@postgres:5432/starbeacon?sslmode=disable"
    environment["SB_DATABASE_URL"] = "postgres://starbeacon_app:" + quote(environment["SB_RUNTIME_DB_PASSWORD"], safe="") + "@postgres:5432/starbeacon?sslmode=disable"
    environment["SB_REDIS_URL"] = "redis://:" + quote(environment.pop("REDIS_PASSWORD"), safe="") + "@redis:6379/0"
    environment["SB_NATS_URL"] = "nats://" + quote(environment.pop("NATS_TOKEN"), safe="") + "@nats:4222"
    environment["SB_ES_URL"] = "http://elasticsearch:9200"
    counters = report_dir / "cli-counters"
    if counters.exists():
        import shutil
        shutil.rmtree(counters)
    counters.mkdir(mode=0o755)
    environment["SB_TEST_BINARY_COVERDIR"] = str(counters)
    started = time.monotonic()
    path = report_dir / "go-capture.jsonl"
    with path.open("w") as output:
        result = subprocess.run(["go", "test", "-race", "-json", "-tags=integration,captureintegration", "-count=1", "-timeout=180s", "-coverpkg=./cmd/...,./internal/...", "-coverprofile=" + str(report_dir / "go-capture.cover"), "-run=^TestManagedCaptureNativeLiveHTTPEndToEnd$", "./tests/integration"], cwd="/source", env=environment, stdout=output, stderr=subprocess.STDOUT, timeout=240)
    evidence = [{"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in (path, report_dir / "go-capture.cover") if p.exists()]
    source = json.loads(pathlib.Path("/reports/source.json").read_text())
    report = {"schema_version": 1, "workspace_sha256": source["workspace_sha256"], "commit": source["commit"], "clean_commit": source["clean_commit"], "environment": "remote_docker", "project": os.environ["SB_ACCEPTANCE_PROJECT"], "scope": "managed_af_packet_live_http_to_search_and_notification", "status": "passed" if result.returncode == 0 else "failed", "exit_code": result.returncode, "duration_seconds": round(time.monotonic() - started, 3), "evidence": evidence}
    (report_dir / "capture.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return result.returncode

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("真实网卡验收执行失败，请检查专属报告。", file=__import__('sys').stderr)
        raise SystemExit(1)
