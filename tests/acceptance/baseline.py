#!/usr/bin/env python3
"""在独立依赖上执行 Go、真实通信链路和原生引擎测试，记录实际执行结果。"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from check_go_coverage import check_sources, merge_profiles, summarize

REPORTS = pathlib.Path("/reports")
ROOT = pathlib.Path("/source")

def execute(arguments, environment, name, timeout=600):
    started = time.monotonic()
    with (REPORTS / (name + ".jsonl")).open("w") as log:
        result = subprocess.run(arguments, env=environment, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    return {"name": name, "status": "passed" if result.returncode == 0 else "failed", "exit_code": result.returncode, "duration_seconds": round(time.monotonic() - started, 3)}

def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    # 每轮只保留本次产物，不能让旧合并报告或旧成功日志混入当前证据。
    for name in ("migrate.jsonl", "runtime-role.jsonl", "go-unit.jsonl", "go-integration.jsonl", "go-cli-format.jsonl", "pcap-inspection-benchmark.jsonl", "go-cli.cover", "go-unit.cover", "go-integration.cover", "go-merged.cover", "go-coverage.json", "baseline.json"):
        (REPORTS / name).unlink(missing_ok=True)
    counters = REPORTS / "go-cli-counters"
    if counters.exists():
        shutil.rmtree(counters)
    counters.mkdir(mode=0o700)
    environment = dict(os.environ, SB_MODE="development", SB_TEST_SURICATA_BINARY="/usr/bin/suricata", SB_TEST_SURICATA_CONFIG="/etc/suricata/suricata.yaml")
    quote = urllib.parse.quote
    owner = quote(environment.pop("POSTGRES_PASSWORD"), safe="")
    runtime = quote(environment["SB_RUNTIME_DB_PASSWORD"], safe="")
    environment["SB_MIGRATION_DATABASE_URL"] = f"postgres://starbeacon_owner:{owner}@postgres:5432/starbeacon?sslmode=disable"
    environment["SB_DATABASE_URL"] = f"postgres://starbeacon_app:{runtime}@postgres:5432/starbeacon?sslmode=disable"
    environment["SB_REDIS_URL"] = "redis://:" + quote(environment.pop("REDIS_PASSWORD"), safe="") + "@redis:6379/0"
    environment["SB_NATS_URL"] = "nats://" + quote(environment.pop("NATS_TOKEN"), safe="") + "@nats:4222"
    environment["SB_ES_URL"] = "http://elasticsearch:9200"
    environment["SB_TEST_MANAGEMENT_BINARY"] = "/usr/local/bin/starbeaconctl"
    environment["SB_TEST_BINARY_COVERDIR"] = str(counters)
    results = []
    for name in ("migrate", "runtime-role"):
        # 管理凭据仅用于初始化和作用域测试，不交给采集器或重放子进程。
        result = execute(["starbeaconctl", name], dict(environment, GOCOVERDIR=str(counters)), name)
        results.append(result)
        if result["status"] != "passed":
            break
    if all(item["status"] == "passed" for item in results):
        results.append(execute(["go", "test", "-race", "-json", "-count=1", "-timeout=240s", "-coverpkg=./cmd/...,./internal/...", "-coverprofile=/reports/go-unit.cover", "./cmd/...", "./internal/..."], environment, "go-unit"))
        # 包级预算覆盖顺序执行的整套集成用例；HTTP、上下文与子进程仍受各自期限约束。
        # 外层预算保留编译与退出整理时间，不将整套耗时解释为业务响应时限。
        results.append(execute(["go", "test", "-race", "-json", "-tags=integration", "-count=1", "-timeout=1200s", "-coverpkg=./cmd/...,./internal/...", "-coverprofile=/reports/go-integration.cover", "./tests/integration"], environment, "go-integration", timeout=1260))
    coverage = None
    if all(item["status"] == "passed" for item in results) and len(results) == 4:
        results.append(execute(["go", "tool", "covdata", "textfmt", "-i=" + str(counters), "-o=/reports/go-cli.cover"], environment, "go-cli-format"))
        if results[-1]["status"] == "passed":
            merged = merge_profiles([(REPORTS / name).read_text() for name in ("go-unit.cover", "go-integration.cover", "go-cli.cover")])
            coverage = summarize(merged)
            check_sources(coverage, ROOT)
            (REPORTS / "go-merged.cover").write_text(merged)
            (REPORTS / "go-coverage.json").write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n")
            # 无竞态检测器及覆盖插桩的离线解析基准单独记录，不混入功能覆盖率。
            results.append(execute(["go", "test", "-json", "-run=^$", "-bench=^BenchmarkInspectHTTP100K$", "-benchtime=1x", "-count=3", "-benchmem", "-timeout=60s", "./internal/replay"], environment, "pcap-inspection-benchmark"))
    source = json.loads((REPORTS / "source.json").read_text())
    evidence = []
    for path in sorted(p for p in REPORTS.iterdir() if p.suffix in (".jsonl", ".cover") or p.name == "go-coverage.json"):
        evidence.append({"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    report = {"schema_version": 1, "commit": source["commit"], "workspace_sha256": source["workspace_sha256"], "clean_commit": source["clean_commit"], "environment": "remote_docker", "mode": "development", "project": os.environ["SB_ACCEPTANCE_PROJECT"], "results": results, "evidence": evidence, "status": "passed" if all(item["status"] == "passed" for item in results) else "failed", "scope": "go_unit_native_suricata_and_dependency_integration"}
    if coverage is not None:
        report["coverage"] = {"covered": coverage["covered"], "total": coverage["total"], "percentage": coverage["percentage"], "minimum": 90, "qualified": coverage["percentage"] >= 90}
    (REPORTS / "baseline.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "results": results, "clean_commit": report["clean_commit"], "scope": report["scope"]}, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        reason = str(error).splitlines()[0][:256] if isinstance(error, ValueError) and str(error) else type(error).__name__
        print("独立依赖验收运行失败：" + reason + "；请检查报告目录中的执行日志。", file=sys.stderr)
        raise SystemExit(1)
