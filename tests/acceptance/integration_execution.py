"""使用 Go 官方用例清单分组顺序执行，拒绝遗漏、重复、跳过和混用覆盖率。"""
import collections
import hashlib
import json
import pathlib
import re
import time

from check_go_coverage import merge_profiles

INSTRUMENTATION_WARNING = "warning: no packages being tested depend on matches for pattern ./cmd/..."


def events(path):
    rows = []
    for line in path.read_text().splitlines():
        # main 包由独立 CLI 流程采集覆盖；Go 的未导入提示不是跳过测试。
        if line == INSTRUMENTATION_WARNING:
            continue
        if line.strip() and not line.startswith("{"):
            raise ValueError("Go 执行记录包含非 JSON 内容")
        if line.startswith("{"):
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("Go 执行记录格式无效")
            rows.append(row)
    return rows


def inventory(path):
    names = []
    for row in events(path):
        if row.get("Action") in ("fail", "skip"):
            raise ValueError("Go 用例清单生成失败")
        output = row.get("Output", "")
        if not isinstance(output, str):
            raise ValueError("Go 用例清单输出格式无效")
        value = output.strip()
        if value.startswith(("Test", "Example", "Fuzz")) and value.isidentifier():
            names.append(value)
    if not names or len(names) != len(set(names)):
        raise ValueError("Go 用例清单为空或重复")
    return sorted(names)


def verify_group(path, names):
    started, passed = collections.Counter(), collections.Counter()
    for row in events(path):
        if row.get("Action") in ("fail", "skip"):
            raise ValueError("集成执行含失败或跳过")
        name = row.get("Test")
        if isinstance(name, str) and "/" not in name:
            if row.get("Action") == "run":
                started[name] += 1
            if row.get("Action") == "pass":
                passed[name] += 1
    expected = collections.Counter(names)
    if started != expected or passed != expected:
        raise ValueError("集成执行存在遗漏、重复或未完成的用例")


def run(directory, environment, execute):
    started = time.monotonic()
    result = {"name": "go-integration", "status": "failed", "exit_code": 1, "strategy": "sequential_shards_v1"}
    manifest = {"schema_version": 1, "strategy": result["strategy"], "status": "failed", "tests": [], "groups": []}
    try:
        for path in directory.glob("go-integration*"):
            if path.name in ("go-integration.jsonl", "go-integration.cover", "go-integration-manifest.json") or re.fullmatch(r"go-integration-(?:inventory|[0-9]{2})\.(?:jsonl|cover)", path.name):
                path.unlink()
        args = ["go", "test", "-race", "-json", "-tags=integration", "-count=1", "-timeout=1200s", "-coverpkg=./cmd/...,./internal/..."]
        listing = execute([*args, "-list=^(Test|Example|Fuzz)", "-run=^$", "./tests/integration"], environment, "go-integration-inventory")
        result["inventory"] = listing
        if listing["status"] != "passed":
            result.update(exit_code=listing["exit_code"], timed_out=listing.get("timed_out", False))
            return result
        names = inventory(directory / "go-integration-inventory.jsonl")
        manifest["tests"] = names
        manifest["inventory_sha256"] = hashlib.sha256("\n".join(names).encode()).hexdigest()
        groups = [names[i::2] for i in range(2)] if len(names) > 64 else [names]
        for i, subset in enumerate(groups, 1):
            name = f"go-integration-{i:02d}"
            pattern = "^(" + "|".join(re.escape(value) for value in subset) + ")$"
            profile = directory / (name + ".cover")
            row = execute([*args, "-run=" + pattern, "-coverprofile=" + str(profile), "./tests/integration"], environment, name, timeout=1260)
            manifest["groups"].append({**row, "tests": subset, "log": name + ".jsonl", "coverage": profile.name})
            if row["status"] != "passed":
                result.update(exit_code=row["exit_code"], timed_out=row.get("timed_out", False))
                return result
            verify_group(directory / (name + ".jsonl"), subset)
        if sorted(value for group in manifest["groups"] for value in group["tests"]) != names:
            raise ValueError("集成执行范围与官方清单不一致")
        (directory / "go-integration.jsonl").write_bytes(b"".join((directory / g["log"]).read_bytes() for g in manifest["groups"]))
        (directory / "go-integration.cover").write_text(merge_profiles([(directory / g["coverage"]).read_text() for g in manifest["groups"]]))
        manifest["status"] = "passed"
        result.update(status="passed", exit_code=0, test_count=len(names), group_count=len(groups), inventory_sha256=manifest["inventory_sha256"])
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["reason"] = str(error) if isinstance(error, ValueError) else type(error).__name__
    finally:
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        (directory / "go-integration-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return result


def verify(directory: pathlib.Path, result: dict):
    manifest = json.loads((directory / "go-integration-manifest.json").read_text())
    names = inventory(directory / "go-integration-inventory.jsonl")
    expected = hashlib.sha256("\n".join(names).encode()).hexdigest()
    if (manifest.get("schema_version") != 1 or manifest.get("strategy") != "sequential_shards_v1" or manifest.get("status") != "passed"
            or manifest.get("tests") != names or manifest.get("inventory_sha256") != expected
            or result.get("inventory_sha256") != expected or result.get("test_count") != len(names)):
        raise ValueError("集成清单与执行结果不一致")
    groups = manifest.get("groups", [])
    expected_groups = [names[i::2] for i in range(2)] if len(names) > 64 else [names]
    if len(groups) != len(expected_groups) or result.get("group_count") != len(groups):
        raise ValueError("集成分组存在遗漏")
    for i, (group, subset) in enumerate(zip(groups, expected_groups), 1):
        stem = f"go-integration-{i:02d}"
        if group.get("tests") != subset or group.get("status") != "passed" or type(group.get("exit_code")) is not int or group["exit_code"] != 0 or group.get("log") != stem + ".jsonl" or group.get("coverage") != stem + ".cover":
            raise ValueError("集成分组身份或实际结果不完整")
        verify_group(directory / group["log"], subset)
    if (directory / "go-integration.jsonl").read_bytes() != b"".join((directory / g["log"]).read_bytes() for g in groups):
        raise ValueError("集成原始日志合并不一致")
    if (directory / "go-integration.cover").read_text() != merge_profiles([(directory / g["coverage"]).read_text() for g in groups]):
        raise ValueError("集成覆盖率合并不一致")
