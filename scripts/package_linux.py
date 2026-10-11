#!/usr/bin/env python3
"""构建、压缩和核验 Linux 发布包；平台与采集器分别产出一个 ZIP。"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile

from package_go_dependencies import collect as collect_go_dependencies

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROLES = {"platform": ("starbeacon", "starbeacon-ingest", "starbeacon-worker", "starbeaconctl"), "collector": ("starbeacon-agent",)}
ROLE_LABELS = {"starbeacon": "platform", "starbeacon-ingest": "ingest", "starbeacon-worker": "worker", "starbeacon-agent": "agent", "starbeaconctl": "starbeaconctl"}
UPX_VERSION = "5.2.1"
GO_VERSION = "1.26.8"

def run(arguments, **kwargs):
    return subprocess.check_output(arguments, text=True, cwd=ROOT, **kwargs).strip()

def stream_digest(stream):
    # Linux 构建环境可使用 Python 3.9；固定读取预算也适用于大体积 ZIP。
    checksum = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        checksum.update(block)
    return checksum.hexdigest()

def digest(path):
    with pathlib.Path(path).open("rb") as file:
        return stream_digest(file)

def frontend_licenses(content):
    if not 0 < len(content) <= 4 * 1024 * 1024:
        raise ValueError("前端许可目录体积无效")
    records = json.loads(content.decode("utf-8"))
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise ValueError("前端许可目录必须包含有界的依赖版本")
    seen = set()
    for record in records:
        if (not isinstance(record, dict) or any(not isinstance(record.get(key), str) or not record[key].strip() for key in ("name", "version", "identifier", "text"))
            or record["identifier"].upper() in ("UNKNOWN", "UNLICENSED") or len(record["text"].encode("utf-8")) > 1024 * 1024
            or record.get("sha256") != hashlib.sha256(record["text"].encode("utf-8")).hexdigest()):
            raise ValueError("前端依赖许可身份、原文或摘要无效")
        key = (record["name"], record["version"])
        if key in seen:
            raise ValueError("前端许可目录包含重复依赖版本")
        seen.add(key)
    return len(records)

def elf_arch(path):
    with pathlib.Path(path).open("rb") as file:
        header = file.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01":
        raise ValueError("发布文件必须为 64 位小端 Linux ELF")
    return {62: "amd64", 183: "arm64"}.get(struct.unpack("<H", header[18:20])[0])

def archive(source, target, epoch):
    # 文件权限、顺序和时间固定，不将符号链接或工作目录内容隐式装进发行包。
    timestamp = __import__("time").gmtime(max(315532800, epoch))[:6]
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("发布目录不能包含符号链接")
            if not path.is_file():
                continue
            info = zipfile.ZipInfo((pathlib.Path(source.name) / path.relative_to(source)).as_posix(), timestamp)
            info.create_system = 3
            executable = path.parent.name == "bin" and any(path.name in roles for roles in ROLES.values())
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(info, path.read_bytes())
    with zipfile.ZipFile(target) as result:
        if result.testzip() is not None:
            raise ValueError("ZIP 完整性检查失败")

def package(version, commit, arch, web_root, output, epoch, upx, commit_file, licenses_tool="go-licenses", sbom_tool="cyclonedx-gomod"):
    if platform.system() != "Linux" or {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine()) != arch:
        raise ValueError("压缩后的程序必须在相同架构 Linux 环境中完成启动核验")
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", version) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("版本必须为 v 开头的语义版本，提交必须为完整 SHA")
    environment = dict(os.environ, GOTOOLCHAIN="local", GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOWORK="off", GOFLAGS="", GOPROXY="off")
    if run(["go", "version"], env=environment).split()[2] != "go" + GO_VERSION:
        raise ValueError("Go 工具链与版本锁定不一致")
    if run([upx, "--version"]).splitlines()[0].split()[:2] != ["upx", UPX_VERSION]:
        raise ValueError("UPX 工具版本与锁定不一致")
    project_license = ROOT / "LICENSE"
    if project_license.is_symlink() or not project_license.is_file() or not 0 < project_license.stat().st_size <= 1024 * 1024:
        raise ValueError("项目许可文本不存在、类型无效或体积超限")
    if not project_license.read_text(encoding="utf-8").strip():
        raise ValueError("项目许可文本不能为空")
    run(["go", "mod", "verify"], env=environment)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.glob("starbeacon-*.zip")):
        raise ValueError("输出目录已有发行包，禁止隐式覆盖")
    produced = []
    with tempfile.TemporaryDirectory(prefix="starbeacon-package-") as scratch:
        work = pathlib.Path(scratch)
        for bundle, roles in ROLES.items():
            source = work / ("starbeacon-" + bundle)
            binaries = source / "bin"
            binaries.mkdir(parents=True)
            metadata = {"schema_version": 1, "version": version, "commit": commit, "os": "linux", "arch": arch, "go": GO_VERSION, "upx": UPX_VERSION, "binaries": {}}
            shutil.copyfile(project_license, source / "LICENSE")
            metadata["project_license"] = {"path": "LICENSE", "sha256": digest(source / "LICENSE")}
            for role in roles:
                binary = binaries / role
                flags = f"-s -w -buildid= -X github.com/kkx600/StarBeacon/internal/buildinfo.Version={version} -X github.com/kkx600/StarBeacon/internal/buildinfo.Commit={commit}"
                run(["go", "build", "-trimpath", "-ldflags", flags, "-o", str(binary), "./cmd/" + role], env=environment)
                if elf_arch(binary) != arch:
                    raise ValueError("构建架构不一致")
                original_digest, original_size = digest(binary), binary.stat().st_size
                build_info = run(["go", "version", "-m", str(binary)], env=environment)
                build_info = role + ": " + build_info.splitlines()[0].rsplit(": ", 1)[-1] + "\n" + "\n".join(build_info.splitlines()[1:])
                (binaries / (role + ".buildinfo.txt")).write_text(build_info + "\n")
                run([upx, "--best", "--lzma", "--no-progress", str(binary)])
                run([upx, "--test", str(binary)])
                result = run([str(binary), "--version"], timeout=10)
                if result != f"StarBeacon {ROLE_LABELS[role]} {version} ({commit})":
                    raise ValueError("压缩后的程序版本回读不一致")
                restored = work / (role + ".restored")
                shutil.copyfile(binary, restored)
                run([upx, "--decompress", "--no-progress", str(restored)])
                if digest(restored) != original_digest:
                    raise ValueError("UPX 解压不能恢复原始程序")
                restored.unlink()
                metadata["binaries"][role] = {"sha256": digest(binary), "uncompressed_sha256": original_digest, "size": binary.stat().st_size, "uncompressed_size": original_size, "version_check": "passed", "upx_check": "passed"}
            resolved_tools = [shutil.which(tool) for tool in (licenses_tool, sbom_tool)]
            if not all(resolved_tools):
                raise ValueError("缺少锁定版本的 Go 许可或 SBOM 工具")
            metadata["go_dependencies"] = collect_go_dependencies(ROOT, source, roles, metadata, environment, *resolved_tools, output / "dependency-diagnostics" / bundle, commit_file)
            web = web_root / ("platform" if bundle == "platform" else "collector") / "dist"
            if not (web / "index.html").is_file():
                raise ValueError("缺少前端生产构建")
            if any(path.is_symlink() for path in web.rglob("*")):
                raise ValueError("前端构建不能包含符号链接")
            shutil.copytree(web, source / "www")
            license_path = source / "www/third-party-licenses.json"
            license_count = frontend_licenses(license_path.read_bytes())
            metadata["frontend_licenses"] = {"path": "www/third-party-licenses.json", "sha256": digest(license_path), "count": license_count}
            proxy = ROOT / "deploy/nginx" / (bundle + ".conf")
            (source / "config").mkdir()
            shutil.copyfile(proxy, source / "config/nginx.conf")
            (source / "manifest.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
            (source / "README.md").write_text(f"# 星烽 StarBeacon {'主控平台' if bundle == 'platform' else '采集器'}\n\n版本：{version}；Linux {arch}。\n\n`bin/` 为 UPX 压缩的可执行程序，`www/` 为对应前端生产文件，`manifest.json` 记录来源、摘要与压缩核验，`LICENSE` 为本项目许可文本，`www/third-party-licenses.json` 记录实际打包前端依赖的许可原文与摘要。`dependencies/go.json` 绑定各程序的实际 Go 依赖、许可与需交付的源码；同目录的 `*.cdx.json` 为对应程序的 CycloneDX SBOM，`notices/` 和 `go-runtime/` 保留原文与 Go 运行时许可。依赖服务、检测引擎、TLS、身份与凭据应依据同一提交的部署说明配置；发行包不包含运行凭据。\n\n`config/nginx.conf` 为同源代理示例，应配置实际入口、TLS 与静态文件路径。\n")
            name = f"starbeacon-{bundle}-{version}-linux-{arch}.zip"
            target = output / name
            archive(source, target, epoch)
            produced.append({"name": name, "sha256": digest(target), "size": target.stat().st_size})
    (output / "checksums.json").write_text(json.dumps({"commit": commit, "version": version, "archives": produced}, indent=2) + "\n")
    return produced

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--arch", choices=("amd64", "arm64"), default="amd64")
    parser.add_argument("--web-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--upx", default="upx")
    parser.add_argument("--source-commit-file", type=pathlib.Path, required=True, help="git cat-file commit 输出的真实提交对象")
    parser.add_argument("--go-licenses", default="go-licenses")
    parser.add_argument("--cyclonedx-gomod", default="cyclonedx-gomod")
    args = parser.parse_args()
    try:
        result = package(args.version, args.commit, args.arch, args.web_root.resolve(), args.output.resolve(), args.epoch, args.upx, args.source_commit_file.resolve(), args.go_licenses, args.cyclonedx_gomod)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Linux 发布包构建失败：{error}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
