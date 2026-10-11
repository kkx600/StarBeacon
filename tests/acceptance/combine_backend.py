#!/usr/bin/env python3
"""合并同一源码的后端与实际网卡证据；该报告不代替全产品发布验收。"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from check_go_coverage import merge_profiles, summarize, check_sources, packages_without_tests


def verify_execution(source, baseline, capture, directory, root=pathlib.Path("/source")):
    if not isinstance(source, dict) or not isinstance(source.get("workspace_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", source["workspace_sha256"]) or not isinstance(source.get("commit"), str) or not re.fullmatch(r"[a-f0-9]{40}", source["commit"]) or not isinstance(source.get("project"), str) or not re.fullmatch(r"sbacc_[a-f0-9]{16}", source["project"]) or type(source.get("clean_commit")) is not bool:
        raise ValueError("源码身份格式无效")
    for report in (baseline, capture):
        if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != 1 or report.get("status") != "passed" or report.get("environment") != "remote_docker" or type(report.get("clean_commit")) is not bool:
            raise ValueError("后端或网卡实测没有通过")
        for key in ("workspace_sha256", "commit", "project", "clean_commit"):
            if key not in source or report.get(key) != source[key]:
                raise ValueError("验收证据与当前源码身份不一致")
    expected = {"migrate", "runtime-role", "go-unit", "go-integration", "go-cli-format", "pcap-inspection-benchmark"}
    rows = baseline.get("results", [])
    if not isinstance(rows, list) or len(rows) != len(expected) or any(not isinstance(row, dict) or not isinstance(row.get("name"), str) or row.get("status") != "passed" or type(row.get("exit_code")) is not int or row["exit_code"] != 0 for row in rows) or {row["name"] for row in rows} != expected:
        raise ValueError("基础执行阶段存在遗漏或失败")
    if capture.get("scope") != "managed_af_packet_live_http_to_search_and_notification" or type(capture.get("exit_code")) is not int or capture["exit_code"] != 0:
        raise ValueError("没有通过实际网卡链路")
    for report, evidence_root, required in ((baseline, directory, {"go-unit.jsonl", "go-integration.jsonl", "go-unit.cover", "go-integration.cover", "go-cli.cover"}), (capture, directory / "capture", {"go-capture.jsonl", "go-capture.cover"})):
        evidence = report.get("evidence", [])
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("缺少原始执行证据")
        paths = set()
        for row in evidence:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str) or row["path"] in ("", ".", "..") or pathlib.Path(row["path"]).name != row["path"] or row["path"] in paths:
                raise ValueError("证据路径越界")
            paths.add(row["path"])
            path = evidence_root / row["path"]
            if evidence_root.is_symlink() or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row.get("sha256"):
                raise ValueError("执行证据摘要不一致")
        if not required.issubset(paths):
            raise ValueError("执行证据遗漏原始日志或覆盖率")
    for path in (directory / "go-unit.jsonl", directory / "go-integration.jsonl", directory / "capture/go-capture.jsonl"):
        actions, skipped, no_test_output = [], [], set()
        for line in path.read_text().splitlines():
            if not line.startswith("{"):
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("原始 Go 执行记录格式无效")
            if row.get("Action") == "fail" or (row.get("Action") == "skip" and (row.get("Test") or path.name != "go-unit.jsonl")):
                raise ValueError("原始 Go 执行含有失败或跳过项")
            if row.get("Action") == "skip":
                if not isinstance(row.get("Package"), str):
                    raise ValueError("无测试包的执行身份缺失")
                skipped.append(row["Package"])
            if row.get("Action") == "output" and isinstance(row.get("Package"), str) and row.get("Output") == "?   \t" + row["Package"] + "\t[no test files]\n":
                no_test_output.add(row["Package"])
            if row.get("Test") and row.get("Action") == "pass":
                actions.append(row["Test"])
        # Go 对没有编译目标测试文件的包输出包级 skip；任何测试用例级 skip 仍拒绝。
        if skipped and (len(skipped) != len(set(skipped)) or not set(skipped).issubset(no_test_output) or not set(skipped).issubset(packages_without_tests(root))):
            raise ValueError("跳过记录不是已核验的无测试包")
        if not actions or (path.parent.name == "capture" and actions != ["TestManagedCaptureNativeLiveHTTPEndToEnd"]):
            raise ValueError("执行日志没有完整的测试通过记录")


def main():
    directory, root = pathlib.Path("/reports"), pathlib.Path("/source")
    target = directory / "backend.json"
    target.unlink(missing_ok=True)
    source = json.loads((directory / "source.json").read_text())
    baseline = json.loads((directory / "baseline.json").read_text())
    capture = json.loads((directory / "capture/capture.json").read_text())
    verify_execution(source, baseline, capture, directory, root)
    subprocess.run(["go", "tool", "covdata", "textfmt", "-i=/reports/capture/cli-counters", "-o=/reports/go-capture-cli.cover"], cwd=root, check=True, timeout=30)
    profiles = [directory / name for name in ("go-unit.cover", "go-integration.cover", "go-cli.cover", "capture/go-capture.cover", "go-capture-cli.cover")]
    merged = merge_profiles([path.read_text() for path in profiles])
    coverage = summarize(merged)
    check_sources(coverage, root)
    merged_path = directory / "go-live-merged.cover"
    merged_path.write_text(merged)
    (directory / "go-live-coverage.json").write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n")
    evidence = []
    for path in [directory / "baseline.json", directory / "capture/capture.json", merged_path, *profiles]:
        evidence.append({"path": path.relative_to(directory).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    report = {"schema_version": 1, **{key: source[key] for key in ("commit", "workspace_sha256", "project", "clean_commit")}, "environment": "remote_docker", "mode": "development", "scope": "backend_functional_and_live_af_packet", "status": "passed" if coverage["percentage"] >= 90 else "failed", "coverage": {"covered": coverage["covered"], "total": coverage["total"], "percentage": coverage["percentage"], "minimum": 90}, "evidence": evidence}
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "scope": report["scope"], "coverage": report["coverage"], "clean_commit": report["clean_commit"]}, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("后端实测证据或覆盖率未通过核对。", file=sys.stderr)
        raise SystemExit(1)
