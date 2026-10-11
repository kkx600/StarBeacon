#!/usr/bin/env python3
"""核对提交、全功能断言、覆盖率、屏幕矩阵与真实部署证据，缺失项拒绝发布。"""
import argparse
import hashlib
import json
import math
import pathlib
import re
import sys
from check_go_coverage import summarize, check_sources

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCREEN_WIDTHS = (1024, 1280, 1366, 1440, 1920, 2560, 3840)

def web_coverage(actual: dict, source_root: str, root: pathlib.Path) -> dict:
    origin = pathlib.PurePosixPath(source_root)
    if not origin.is_absolute() or ".." in origin.parts:
        raise ValueError("前端覆盖率必须记录执行环境的绝对源码根目录")
    included = {}
    for path, row in actual.items():
        if path == "total":
            continue
        source = pathlib.PurePosixPath(path)
        if not source.is_absolute() or ".." in source.parts or not source.is_relative_to(origin):
            raise ValueError("前端覆盖率包含源码根目录之外的路径")
        name = source.relative_to(origin).as_posix()
        if name in included or not name.startswith(("web/platform/src/", "web/collector/src/", "web/packages/shared/src/")):
            raise ValueError("前端覆盖率源码重复或不属于自有工程")
        included[name] = row
    for directory in ("web/platform/src", "web/collector/src", "web/packages/shared/src"):
        for source in (root / directory).rglob("*"):
            if source.suffix in (".vue", ".ts", ".mjs") and not source.name.endswith(".d.ts") and source.relative_to(root).as_posix() not in included:
                raise ValueError(f"前端覆盖率缺少源码：{source.relative_to(root)}")
    percentages = {}
    for metric in ("statements", "branches", "functions", "lines"):
        for row in [actual["total"], *included.values()]:
            values = row[metric]
            if any(type(values[name]) is not int for name in ("total", "covered", "skipped")) or not 0 <= values["covered"] <= values["total"] or values["skipped"] != 0:
                raise ValueError("前端覆盖率计数无效或存在跳过的覆盖块")
        total = actual["total"][metric]
        if total["total"] <= 0 or any(total[name] != sum(row[metric][name] for row in included.values()) for name in ("total", "covered")):
            raise ValueError("前端总覆盖率与各源码统计不一致")
        percentages[metric] = total["covered"] * 100 / total["total"]
    return percentages

def verify_evidence(directory: pathlib.Path, evidence: dict) -> None:
    if not isinstance(evidence, dict):
        raise ValueError("验收证据必须为路径与校验值对象")
    name, digest = evidence.get("path"), evidence.get("sha256")
    if not isinstance(name, str) or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("验收证据路径或校验值缺失")
    path = pathlib.Path(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("验收证据必须位于报告目录内")
    target = (directory / path).resolve()
    if not target.is_relative_to(directory.resolve()) or not target.is_file():
        raise ValueError(f"验收证据不存在或越界：{name}")
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise ValueError(f"验收证据校验值不一致：{name}")

def verify(report: dict, commit: str, catalog: dict, directory: pathlib.Path) -> list[str]:
    errors = []
    if not isinstance(report, dict) or not isinstance(catalog, dict):
        return ["验收报告和需求目录必须为对象"]
    if type(report.get("schema_version")) is not int or report.get("schema_version") != 1 or not re.fullmatch(r"[a-f0-9]{40}", commit) or report.get("commit") != commit:
        errors.append("验收报告与待发布的完整 Git 提交不一致")
    catalog_items = catalog.get("requirements")
    if not isinstance(catalog_items, list) or any(not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in catalog_items):
        return errors + ["需求目录格式无效"]
    expected = {item["id"] for item in catalog_items}
    document = (ROOT / "docs/功能覆盖与验收矩阵.md").read_text()
    if type(catalog.get("schema_version")) is not int or catalog.get("schema_version") != 1 or len(catalog_items) != 107 or len(expected) != 107 or expected != set(re.findall(r"SB-[A-Z]{2,3}-\d{3}", document)):
        errors.append("验收目录必须与产品矩阵中的全部 107 项需求一致")
    requirements = report.get("requirements", [])
    if not isinstance(requirements, list):
        return errors + ["需求验收记录格式无效"]
    ids = [item.get("id") for item in requirements if isinstance(item, dict) and isinstance(item.get("id"), str)]
    if len(ids) != len(requirements) or len(ids) != len(set(ids)) or set(ids) != expected:
        errors.append("验收记录必须完整且唯一地覆盖 107 项需求")
    for item in requirements:
        if not isinstance(item, dict):
            continue
        checks = item.get("checks", [])
        if item.get("status") != "passed" or not isinstance(checks, list) or not checks:
            errors.append(f"{item.get('id')} 缺少通过的真实功能断言")
            continue
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("name"), str) or not check["name"].strip() or check.get("status") != "passed" or check.get("execution") not in ("real_service", "real_browser", "real_engine"):
                errors.append(f"{item.get('id')} 存在跳过、模拟或未通过的验收项")
                continue
            try:
                verify_evidence(directory, check.get("evidence", {}))
            except (OSError, ValueError) as error:
                errors.append(f"{item.get('id')}：{error}")
    for scope, metrics in (("go", ("statements",)), ("web", ("statements", "branches", "functions", "lines"))):
        coverage_root = report.get("coverage")
        coverage = coverage_root.get(scope) if isinstance(coverage_root, dict) else None
        if not isinstance(coverage, dict):
            errors.append(f"{scope} 覆盖率记录格式无效")
            continue
        for metric in metrics:
            value = coverage.get(metric)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or not 90 <= value <= 100:
                errors.append(f"{scope} {metric} 覆盖率未达到 90%")
        try:
            verify_evidence(directory, coverage.get("evidence", {}))
            evidence_path = directory / coverage["evidence"]["path"]
            if scope == "go":
                actual = summarize(evidence_path.read_text())
                check_sources(actual, ROOT)
                if actual["percentage"] < 90 or abs(actual["percentage"] - coverage.get("statements", -1)) > 0.01:
                    errors.append("Go 报告与实际覆盖块不一致或低于 90%")
            else:
                actual = json.loads(evidence_path.read_text())
                percentages = web_coverage(actual, coverage.get("source_root", ""), ROOT)
                for metric in metrics:
                    percentage = percentages[metric]
                    if percentage < 90 or abs(percentage - coverage.get(metric, -1)) > 0.01:
                        errors.append(f"web {metric} 报告与原始统计不一致或低于 90%")
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(f"{scope} 覆盖率：{error}")
    deployment = report.get("deployment", {})
    if not isinstance(deployment, dict):
        deployment = {}
    if deployment.get("status") != "passed" or deployment.get("environment") != "remote_docker" or deployment.get("commit") != commit or not isinstance(deployment.get("project"), str) or not re.fullmatch(r"sbacc_[a-f0-9]{16}", deployment["project"]):
        errors.append("缺少同一提交在远程独立 Docker 项目中的验收")
    if deployment.get("mode") != "production" or any(deployment.get(name) is not True for name in ("tls_verified", "runtime_role_verified", "native_isolation_verified", "private_network_verified", "clean_commit")):
        errors.append("生产 TLS、最小数据库权限、原生重放隔离、独立网络及干净提交尚未全部核验")
    try:
        verify_evidence(directory, deployment.get("evidence", {}))
    except (OSError, ValueError) as error:
        errors.append(f"远程部署：{error}")
    screens = report.get("screens", [])
    if not isinstance(screens, list) or len(screens) != 2 * len(SCREEN_WIDTHS) or any(not isinstance(screen, dict) or screen.get("app") not in ("platform", "collector") or type(screen.get("width")) is not int or screen.get("width") not in SCREEN_WIDTHS for screen in screens):
        errors.append("PC 屏幕矩阵记录格式无效或包含遗漏、重复和未知规格")
        screens = screens if isinstance(screens, list) else []
    routes = json.loads((ROOT / "tests/acceptance/routes.json").read_text())
    for app in ("platform", "collector"):
        for width in SCREEN_WIDTHS:
            matches = [screen for screen in screens if isinstance(screen, dict) and screen.get("app") == app and screen.get("width") == width]
            if len(matches) != 1 or matches[0].get("status") != "passed" or type(matches[0].get("overflow_count")) is not int or matches[0].get("overflow_count") != 0 or type(matches[0].get("height")) is not int or matches[0].get("height", 0) < 768 or not matches[0].get("routes"):
                errors.append(f"{app} 缺少 {width}px 全路由布局与交互验收")
                continue
            cases = matches[0]["routes"]
            if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
                errors.append(f"{app} {width}px 路由验收格式无效")
                continue
            expected_routes = set(routes[app])
            if len(cases) != len(expected_routes) or any(not isinstance(case.get("path"), str) for case in cases) or {case.get("path") for case in cases if isinstance(case.get("path"), str)} != expected_routes:
                errors.append(f"{app} {width}px 存在遗漏或重复路由")
            if any(case.get("status") != "passed" or not isinstance(case.get("interactions"), list) or not case["interactions"] or any(not isinstance(check, dict) or not isinstance(check.get("name"), str) or not check["name"].strip() or check.get("status") != "passed" for check in case["interactions"]) for case in cases):
                errors.append(f"{app} {width}px 存在遗漏路由或失败交互")
            try:
                verify_evidence(directory, matches[0].get("evidence", {}))
            except (OSError, ValueError) as error:
                errors.append(f"{app} {width}px：{error}")
    return errors

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text())
        catalog = json.loads((ROOT / "tests/acceptance/requirements.json").read_text())
        errors = verify(report, args.commit, catalog, args.report.parent)
    except (OSError, ValueError, TypeError, KeyError) as error:
        errors = [f"验收报告无法核对：{error}"]
    if errors:
        print("发布验收未通过：\n" + "\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("107 项功能、90% 覆盖率、PC 屏幕矩阵与远程 Docker 验收通过")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
