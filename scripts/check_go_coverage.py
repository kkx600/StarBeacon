#!/usr/bin/env python3
"""检查自有 Go 代码的语句覆盖率；生成协议代码及测试数据生成器不计入。"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

MODULE = "github.com/kkx600/StarBeacon/"
EXCLUDED = ("api/sensor/", "internal/testpcap/")

def merge_profiles(profiles: list[str]) -> str:
    """仅合并同一源码布局的本次报告，拒绝旧修订或缺失模式的输入。"""
    if not profiles:
        raise ValueError("没有需要合并的覆盖率报告")
    mode = profiles[0].splitlines()[0] if profiles[0] else ""
    blocks, layouts = {}, {}
    for profile in profiles:
        lines = profile.splitlines()
        if not lines or lines[0] != mode:
            raise ValueError("覆盖率报告模式不一致")
        summarize(profile)
        layout = {}
        for line in lines[1:]:
            location, statements, count = line.split()
            statements, count = int(statements), int(count)
            source = location.rsplit(":", 1)[0]
            layout.setdefault(source, {})[location] = statements
            if location in blocks and blocks[location][0] != statements:
                raise ValueError("覆盖块语句数不一致")
            blocks[location] = (statements, count + blocks.get(location, (0, 0))[1])
        for source, positions in layout.items():
            if source in layouts and layouts[source] != positions:
                raise ValueError(f"覆盖率报告包含不同源码布局：{source}")
            layouts[source] = positions
    return mode + "\n" + "".join(f"{location} {statements} {count}\n" for location, (statements, count) in sorted(blocks.items()))

def summarize(profile: str) -> dict:
    lines = profile.splitlines()
    if not lines or lines[0] not in ("mode: set", "mode: count", "mode: atomic"):
        raise ValueError("覆盖率文件缺少有效模式")
    blocks = {}
    for line in lines[1:]:
        record = re.fullmatch(r"([^\s:]+):(\d+)\.(\d+),(\d+)\.(\d+) ([0-9]+) ([0-9]+)", line)
        if record is None:
            raise ValueError("覆盖率位置或计数格式无效")
        source, start_line, start_column, end_line, end_column, statements, count = record.groups()
        position = tuple(map(int, (start_line, start_column, end_line, end_column)))
        statements, count = int(statements), int(count)
        if min(position) < 1 or position[:2] > position[2:]:
            raise ValueError("覆盖率起止位置无效")
        location = source + ":" + ".".join((start_line, start_column)) + "," + ".".join((end_line, end_column))
        source = location.rsplit(":", 1)[0]
        if not source.startswith(MODULE):
            raise ValueError("覆盖率文件包含其他仓库的路径")
        path = source.removeprefix(MODULE)
        parts = pathlib.PurePosixPath(path)
        if parts.is_absolute() or ".." in parts.parts or "\\" in path or parts.suffix != ".go" or parts.as_posix() != path or parts.name.endswith("_test.go"):
            raise ValueError("覆盖率源码路径无效")
        if path.startswith(EXCLUDED):
            continue
        if not path.startswith(("cmd/", "internal/")):
            raise ValueError("覆盖率包含未声明的统计范围")
        key = location
        previous = blocks.get(key)
        if previous is not None and previous[0] != statements:
            raise ValueError("重复覆盖块的语句数不一致")
        blocks[key] = (statements, count > 0 or (previous is not None and previous[1]))
    files = {}
    for location, (statements, covered) in blocks.items():
        path = location.rsplit(":", 1)[0].removeprefix(MODULE)
        row = files.setdefault(path, {"covered": 0, "total": 0, "positions": []})
        coordinates = location.rsplit(":", 1)[1]
        row["positions"].append(tuple(map(int, re.split(r"[.,]", coordinates))))
        row["total"] += statements
        if covered:
            row["covered"] += statements
    total = sum(row["total"] for row in files.values())
    covered = sum(row["covered"] for row in files.values())
    if not total:
        raise ValueError("没有自有代码覆盖率记录")
    return {"covered": covered, "total": total, "percentage": covered * 100 / total, "files": dict(sorted(files.items())), "excluded": list(EXCLUDED)}

def compiled_packages(root: pathlib.Path) -> list[dict]:
    """由官方 Go 工具选择源码和测试文件，不自行解释平台或构建条件。"""
    if not (root / "go.mod").is_file():
        raise ValueError("缺少 Go module，不能核验测试文件身份")
    environment = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOPROXY="off", GOFLAGS="", CGO_ENABLED="0")
    try:
        result = subprocess.run([environment.get("SB_GO_BINARY", "go"), "list", "-mod=readonly", "-json", "./cmd/...", "./internal/..."], cwd=root, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("无法核对 Go 构建文件，请使用锁定工具链和已核验的本地模块") from error
    decoder, pending, selected = json.JSONDecoder(), result.stdout.strip(), []
    identities = set()
    while pending:
        try:
            package, offset = decoder.raw_decode(pending)
        except ValueError as error:
            raise ValueError("Go 构建文件清单格式无效") from error
        pending = pending[offset:].lstrip()
        if not isinstance(package, dict) or not isinstance(package.get("ImportPath"), str) or not package["ImportPath"].startswith(MODULE) or package.get("Error") or not isinstance(package.get("Dir"), str):
            raise ValueError("Go 构建文件清单身份无效")
        if package["ImportPath"] in identities:
            raise ValueError("Go 构建包身份重复")
        identities.add(package["ImportPath"])
        directory = pathlib.Path(package["Dir"])
        if directory.is_symlink() or not directory.resolve().is_relative_to(root.resolve()):
            raise ValueError("Go 构建目录越界")
        files = []
        for field in ("GoFiles", "CgoFiles", "TestGoFiles", "XTestGoFiles"):
            names = package.get(field, [])
            tests = field in ("TestGoFiles", "XTestGoFiles")
            if not isinstance(names, list) or any(not isinstance(name, str) or pathlib.PurePosixPath(name).name != name or "\\" in name or not name.endswith(".go") or name.endswith("_test.go") != tests for name in names):
                raise ValueError("Go 构建文件名称无效")
            files.extend(names)
        for name in files:
            path = directory / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("Go 构建文件不存在或不是普通文件")
            relative = path.resolve().relative_to(root.resolve()).as_posix()
            if not relative.startswith(("cmd/", "internal/")):
                raise ValueError("Go 构建文件不属于自有业务目录")
        selected.append(package)
    if not selected:
        raise ValueError("Go 构建文件清单为空")
    return selected


def compiled_sources(root: pathlib.Path) -> set[str]:
    if not (root / "go.mod").is_file():
        # 无 module 的隔离质量夹具不具备构建选择信息，仍检查全部源码。
        return {p.relative_to(root).as_posix() for folder in ("cmd", "internal") for p in (root / folder).rglob("*.go") if not p.name.endswith("_test.go")}
    return {(pathlib.Path(package["Dir"]) / name).resolve().relative_to(root.resolve()).as_posix() for package in compiled_packages(root) for field in ("GoFiles", "CgoFiles") for name in package.get(field, [])}


def packages_without_tests(root: pathlib.Path) -> set[str]:
    return {package["ImportPath"] for package in compiled_packages(root) if not package.get("TestGoFiles") and not package.get("XTestGoFiles")}


def check_sources(report: dict, root: pathlib.Path) -> None:
    for name, row in report["files"].items():
        source = root / name
        if source.is_symlink() or not source.resolve().is_relative_to(root.resolve()) or not source.is_file():
            raise ValueError(f"覆盖率包含不存在或越界的源码：{name}")
        lines = source.read_bytes().splitlines()
        for start_line, start_column, end_line, end_column in row["positions"]:
            if end_line > len(lines) or start_column > len(lines[start_line - 1]) + 1 or end_column > len(lines[end_line - 1]) + 1:
                raise ValueError(f"覆盖率位置超出实际源码：{name}")
    selected = compiled_sources(root)
    if any(path not in selected for path in report["files"]):
        raise ValueError("覆盖率报告包含其他构建目标的源码")
    # 本目标无测试的业务文件同样必须进入统计，不能删除零覆盖文件。
    for path in selected:
        if path.startswith(EXCLUDED):
            continue
        content = (root / path).read_text()
        if re.search(r"(?m)^func\s", content) and path not in report["files"]:
            raise ValueError(f"覆盖率缺少自有源码：{path}")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=pathlib.Path)
    parser.add_argument("--minimum", type=float, default=90)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if not 90 <= args.minimum <= 100:
        parser.error("正式门禁阈值必须在 90–100 之间")
    try:
        report = summarize(args.profile.read_text())
        check_sources(report, pathlib.Path(__file__).resolve().parents[1])
    except (OSError, ValueError) as error:
        print(f"覆盖率检查失败：{error}", file=sys.stderr)
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"Go 自有代码语句覆盖率：{report['percentage']:.2f}%（{report['covered']}/{report['total']}）")
    return 0 if report["percentage"] >= args.minimum else 1

if __name__ == "__main__":
    raise SystemExit(main())
