#!/usr/bin/env python3
"""执行双端前端工程检查，冻结可复核源码和实际执行证据。"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

from check_acceptance import web_coverage
from source_snapshot import snapshot, verify

ROOT = pathlib.Path(__file__).resolve().parents[1]


def save(path: pathlib.Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def qualify(output: pathlib.Path, root: pathlib.Path = ROOT, max_workers: int = 1) -> dict:
    if type(max_workers) is not int or not 1 <= max_workers <= 4:
        raise ValueError("前端测试并行数须为 1–4")
    root, output = root.resolve(), output.absolute()
    if ".." in output.parts or not output.is_relative_to(root / ".local/acceptance") or output.is_symlink() or any(p.is_symlink() for p in output.parents):
        raise ValueError("证据目录必须位于本工程 .local/acceptance 内")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = snapshot(root)
    save(output / "source.json", manifest)
    report = {"schema_version": 1, "scope": "frontend_engineering_not_full_product_acceptance", "status": "running",
              "source_root": str(root), "source_sha256": manifest["source_sha256"],
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
              "clean_commit": not subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip(),
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "max_workers": max_workers, "steps": []}
    evidence = output / "frontend.json"
    save(evidence, report)
    tool_tests = [str(p.relative_to(root)) for p in sorted((root / "web/scripts").glob("*.test.mjs"))]
    steps = [
        ("tool-tests", ["node", "--test", "--test-reporter=tap", *tool_tests], 120),
        ("coverage", ["pnpm", "--dir", "web", "exec", "vitest", "run", "--coverage", f"--maxWorkers={max_workers}", "--reporter=default", "--reporter=json", "--outputFile=" + str(output / "tests.json"), "--coverage.reportsDirectory=" + str(output / "coverage")], 600),
        ("typecheck", ["pnpm", "--dir", "web", "typecheck"], 300),
        ("build", ["pnpm", "--dir", "web", "build"], 300),
    ]
    try:
        if not tool_tests:
            raise ValueError("前端工具测试目录为空")
        for name, command, deadline in steps:
            started = time.monotonic()
            with (output / (name + ".log")).open("xb") as log:
                result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=deadline)
            row = {"name": name, "exit_code": result.returncode, "duration_seconds": round(time.monotonic() - started, 3)}
            report["steps"].append(row)
            save(evidence, report)
            print(json.dumps(row), flush=True)
            if result.returncode != 0:
                raise ValueError("前端检查未通过：" + name)
            verify(root, manifest)
        tool_counts = {key: int(value) for key, value in re.findall(r"^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$", (output / "tool-tests.log").read_text(), re.MULTILINE)}
        if (tool_counts.get("tests", 0) <= 0 or tool_counts.get("tests") != tool_counts.get("pass")
                or any(tool_counts.get(key) != 0 for key in ("fail", "cancelled", "skipped", "todo"))):
            raise ValueError("存在未通过或未执行的前端工具用例")
        tests = json.loads((output / "tests.json").read_text())
        if (not tests.get("success") or type(tests.get("numPassedTests")) is not int or tests["numPassedTests"] <= 0
                or tests.get("numFailedTests") != 0 or tests.get("numPendingTests") != 0 or tests.get("numTodoTests", 0) != 0
                or tests.get("numTotalTests") != tests["numPassedTests"]):
            raise ValueError("存在未通过或未执行的前端用例")
        coverage = json.loads((output / "coverage/coverage-summary.json").read_text())
        percentages = web_coverage(coverage, str(root), root)
        if any(value < 90 for value in percentages.values()):
            raise ValueError("前端自有源码四项覆盖率未全部达到 90%")
        report.update(status="passed", tests=tests["numPassedTests"], tool_tests=tool_counts["tests"], test_files=len(tests["testResults"]), coverage=percentages)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report.update(status="failed", reason=str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report["evidence"] = [{"path": p.relative_to(output).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                              for p in sorted(output.rglob("*")) if p.is_file() and p != evidence]
        save(evidence, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--max-workers", type=int, choices=range(1, 5), default=1, help="按执行容器资源配置 1–4 个测试进程，不改变超时、覆盖率或用例范围")
    args = parser.parse_args()
    result = qualify(args.output, max_workers=args.max_workers)
    print(json.dumps({key: result[key] for key in ("status", "source_sha256", "scope")}, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("前端验收启动失败：" + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
