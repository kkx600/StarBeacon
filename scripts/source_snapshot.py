#!/usr/bin/env python3
"""为受版本管理的工程输入生成可跨机器复核的逐文件摘要。"""
import hashlib
import json
import pathlib
import subprocess

ALGORITHM = "sha256-path-size-sha256-v1"


def snapshot(root: pathlib.Path, scope: str = "web") -> dict:
    root = root.resolve()
    if scope != "web":
        raise ValueError("源码范围无效")
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", scope], cwd=root
    ).decode("utf-8").split("\0")
    selected = set(names) - {""}
    # 构建会读取被 .gitignore 忽略的本地源码；这些输入同样必须进入证据。
    for directory in ("platform/src", "collector/src", "packages/shared/src", "tests", "scripts"):
        selected.update(p.relative_to(root).as_posix() for p in (root / scope / directory).rglob("*"))
    for directory in ("", "platform", "collector", "packages/shared"):
        selected.update(p.relative_to(root).as_posix() for p in (root / scope / directory).glob("*")
                        if p.suffix in (".json", ".yaml", ".yml", ".ts", ".js", ".mjs", ".cjs", ".html"))
    files, digest = [], hashlib.sha256()
    for name in sorted(selected):
        relative = pathlib.PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or not name.startswith(scope + "/"):
            raise ValueError("源码路径不属于指定工程")
        source = root / relative
        if any(parent.is_symlink() for parent in (source, *source.parents) if parent != root and parent.is_relative_to(root)):
            raise ValueError("源码不能使用符号链接")
        if not source.exists():
            # Git 仍列出尚未提交的删除；当前快照只包含实际存在的输入。
            continue
        if source.is_dir():
            continue
        if not source.is_file() or not source.resolve().is_relative_to(root):
            raise ValueError("源码不是工程内的普通文件")
        content = source.read_bytes()
        row = {"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        files.append(row)
        digest.update(name.encode() + b"\0" + str(row["size"]).encode() + b"\0" + row["sha256"].encode() + b"\0")
    if not files:
        raise ValueError("工程源码清单为空")
    return {"schema_version": 1, "scope": scope, "algorithm": ALGORITHM, "source_sha256": digest.hexdigest(), "files": files}


def verify(root: pathlib.Path, manifest: dict) -> None:
    if not isinstance(manifest, dict) or manifest != snapshot(root, manifest.get("scope", "")):
        raise ValueError("当前工程源码与验收快照不一致")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=pathlib.Path)
    args = parser.parse_args()
    repository = pathlib.Path(__file__).resolve().parents[1]
    if args.verify:
        verify(repository, json.loads(args.verify.read_text()))
        print("工程源码快照一致")
    else:
        print(json.dumps(snapshot(repository), ensure_ascii=False, indent=2))
