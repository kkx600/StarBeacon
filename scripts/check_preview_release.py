#!/usr/bin/env python3
"""核对工程预览发行来源与实际 ZIP；不授予正式产品验收资格。"""
import argparse
import json
import pathlib
import re
import subprocess

from check_package_acceptance import verify_archive

ROOT = pathlib.Path(__file__).resolve().parents[1]


def validate_identity(version, commit, repository, run_id):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-rc\.[1-9][0-9]*", version):
        raise ValueError("工程预览仅接受 v主版本.次版本.修订版本-rc.序号")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("必须绑定完整提交 SHA")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("仓库标识无效")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise ValueError("工程检查运行 ID 无效")


def verify_run(run, commit, repository, run_id):
    expected = {"id": int(run_id), "head_sha": commit, "head_branch": "main", "status": "completed",
                "conclusion": "success", "event": "push", "path": ".github/workflows/ci.yml"}
    if (not isinstance(run, dict) or any(run.get(key) != value for key, value in expected.items())
            or not isinstance(run.get("head_repository"), dict)
            or run["head_repository"].get("full_name") != repository):
        raise ValueError("必须提供本仓库 main 同一提交的成功工程检查运行")


def verify_packages(directory, version, commit):
    path = directory / "checksums.json"
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024:
        raise ValueError("预览发行清单不存在或体积无效")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != version or data.get("commit") != commit:
        raise ValueError("预览发行包提交或版本不一致")
    expected = {f"starbeacon-{bundle}-{version}-linux-amd64.zip": bundle for bundle in ("platform", "collector")}
    records = data.get("archives")
    if (not isinstance(records, list) or len(records) != 2
            or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in records)
            or {item["name"] for item in records} != set(expected)
            or {path.name for path in directory.glob("*.zip")} != set(expected)):
        raise ValueError("必须提供平台与采集器两个 Linux amd64 ZIP")
    for item in records:
        if (type(item.get("size")) is not int or not 0 < item["size"] <= 1024 ** 3
                or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])):
            raise ValueError("预览 ZIP 大小或摘要无效")
        verify_archive(directory / item["name"], item, data, expected[item["name"]], "amd64")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--directory", type=pathlib.Path)
    args = parser.parse_args()
    validate_identity(args.version, args.commit, args.repository, args.run_id)
    run = json.loads(subprocess.check_output(["gh", "api", f"repos/{args.repository}/actions/runs/{args.run_id}"], text=True))
    verify_run(run, args.commit, args.repository, args.run_id)
    if args.directory is not None:
        data = verify_packages(args.directory, args.version, args.commit)
        source = ROOT / "docs/releases" / (args.version + ".md")
        if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size <= 64 * 1024:
            raise ValueError("缺少同一提交的工程预览发行说明")
        notes = source.read_text(encoding="utf-8").replace(
            "](../", f"](https://github.com/{args.repository}/blob/{args.commit}/docs/")
        notes += (f"\n\n来源提交：`{args.commit}`。\n\n"
                  f"[同一提交的工程检查](https://github.com/{args.repository}/actions/runs/{args.run_id})。\n\n"
                  "两个 ZIP 已核对 SHA-256、Linux ELF、UPX 压缩及解压、实际版本启动、前端许可和 Go 依赖／SBOM。此检查不代表完整产品或生产环境验收。\n\n"
                  "| 文件 | SHA-256 |\n| --- | --- |\n")
        notes += "\n".join(f"| {item['name']} | `{item['sha256']}` |" for item in data["archives"]) + "\n"
        (args.directory / "notes.md").write_text(notes, encoding="utf-8")
    print("工程预览来源核对通过；正式发布门禁保持独立。")


if __name__ == "__main__":
    main()
