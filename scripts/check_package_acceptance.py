#!/usr/bin/env python3
"""发行包必须与远程端到端测试使用的压缩程序及 ZIP 完全一致。"""
import argparse
import hashlib
import json
import pathlib
import re
import stat
import struct
import sys
import zipfile

from check_acceptance import verify_evidence
from package_linux import ROLES, GO_VERSION, UPX_VERSION, stream_digest, frontend_licenses
from package_go_dependencies import verify_bundle as verify_go_dependencies

def verify_archive(path, record, checksums, bundle, arch):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != record["size"]:
        raise ValueError("发行包文件不存在、类型无效或大小不一致")
    with path.open("rb") as stream:
        if stream_digest(stream) != record["sha256"]:
            raise ValueError("ZIP 文件摘要与发行清单不一致")
    prefix = "starbeacon-" + bundle
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= 10000 or sum(item.file_size for item in entries) > 2 * 1024 ** 3:
            raise ValueError("ZIP 内容数量或解压体积超出发行限制")
        names = set()
        for entry in entries:
            name = pathlib.PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (entry.filename in names or entry.filename != name.as_posix() or "\\" in entry.filename
                or name.is_absolute() or ".." in name.parts or len(name.parts) < 2 or name.parts[0] != prefix
                or not stat.S_ISREG(mode) or entry.flag_bits & 1 or entry.file_size > 512 * 1024 ** 2):
                raise ValueError("ZIP 包含重复、越界、加密或非普通文件")
            names.add(entry.filename)
            executable = name.parent.as_posix() == prefix + "/bin" and name.name in ROLES[bundle]
            if stat.S_IMODE(mode) != (0o755 if executable else 0o644):
                raise ValueError("ZIP 文件权限与可执行程序用途不一致")
        if archive.testzip() is not None:
            raise ValueError("ZIP CRC 校验失败")
        required = {prefix + "/" + name for name in ("manifest.json", "LICENSE", "README.md", "www/index.html", "www/third-party-licenses.json", "config/nginx.conf")}
        if not required <= names:
            raise ValueError("发行包缺少清单、许可文件、部署说明、前端或代理配置")
        manifest_info = archive.getinfo(prefix + "/manifest.json")
        if manifest_info.file_size > 1024 * 1024:
            raise ValueError("发行清单体积无效")
        manifest = json.loads(archive.read(manifest_info))
        if (not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1
            or any(manifest.get(key) != value for key, value in {"version": checksums["version"], "commit": checksums["commit"], "os": "linux", "arch": arch, "go": GO_VERSION, "upx": UPX_VERSION}.items())
            or not isinstance(manifest.get("binaries"), dict) or set(manifest["binaries"]) != set(ROLES[bundle])):
            raise ValueError("发行清单版本、架构、工具链或程序集合不一致")
        license_record = manifest.get("project_license")
        if (not isinstance(license_record, dict) or set(license_record) != {"path", "sha256"}
            or license_record.get("path") != "LICENSE"
            or not isinstance(license_record.get("sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", license_record["sha256"]) is None):
            raise ValueError("项目许可清单缺失或无效")
        license_info = archive.getinfo(prefix + "/LICENSE")
        if not 0 < license_info.file_size <= 1024 * 1024:
            raise ValueError("项目许可文本体积无效")
        license_content = archive.read(license_info)
        if hashlib.sha256(license_content).hexdigest() != license_record["sha256"]:
            raise ValueError("项目许可文本与发行清单摘要不一致")
        try:
            if not license_content.decode("utf-8").strip():
                raise ValueError("项目许可文本不能为空")
        except UnicodeDecodeError as error:
            raise ValueError("项目许可文本必须为 UTF-8") from error
        frontend_record = manifest.get("frontend_licenses")
        if (not isinstance(frontend_record, dict) or set(frontend_record) != {"path", "sha256", "count"}
            or frontend_record.get("path") != "www/third-party-licenses.json"
            or not isinstance(frontend_record.get("sha256"), str) or re.fullmatch(r"[a-f0-9]{64}", frontend_record["sha256"]) is None
            or type(frontend_record.get("count")) is not int or not 1 <= frontend_record["count"] <= 1000):
            raise ValueError("前端许可清单缺失或无效")
        frontend_info = archive.getinfo(prefix + "/www/third-party-licenses.json")
        if not 0 < frontend_info.file_size <= 4 * 1024 * 1024:
            raise ValueError("前端许可目录体积无效")
        frontend_content = archive.read(frontend_info)
        if (hashlib.sha256(frontend_content).hexdigest() != frontend_record["sha256"]
            or frontend_licenses(frontend_content) != frontend_record["count"]):
            raise ValueError("前端许可原文与发行清单不一致")
        binary_names = {prefix + "/bin/" + role for role in ROLES[bundle]}
        if {name for name in names if name.startswith(prefix + "/bin/") and not name.endswith(".buildinfo.txt")} != binary_names:
            raise ValueError("发行包包含缺失或未声明的可执行程序")
        for role, binary in manifest["binaries"].items():
            if (not isinstance(binary, dict) or binary.get("upx_check") != "passed" or binary.get("version_check") != "passed"
                or any(not isinstance(binary.get(key), str) or re.fullmatch(r"[a-f0-9]{64}", binary[key]) is None for key in ("sha256", "uncompressed_sha256"))
                or any(type(binary.get(key)) is not int or binary[key] <= 0 for key in ("size", "uncompressed_size"))):
                raise ValueError("压缩程序核验记录无效")
            info = archive.getinfo(prefix + "/bin/" + role)
            with archive.open(info) as stream:
                actual_digest = stream_digest(stream)
            if info.file_size != binary["size"] or actual_digest != binary["sha256"]:
                raise ValueError("发行程序与清单摘要或大小不一致")
            with archive.open(info) as stream:
                header = stream.read(20)
            if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack("<H", header[18:20])[0] != {"amd64": 62, "arm64": 183}[arch]:
                raise ValueError("发行程序不是声明架构的 Linux ELF")
        def read_dependency(name):
            info = archive.getinfo(prefix + "/" + name)
            if info.file_size > 16 * 1024 * 1024:
                raise ValueError("依赖交付文件超限")
            return archive.read(info)
        verify_go_dependencies(read_dependency, {name[len(prefix) + 1:] for name in names}, manifest, ROLES[bundle])

def verify(report, checksums, directory, archives_directory):
    if not isinstance(report, dict) or not isinstance(checksums, dict):
        raise ValueError("发行包与验收记录必须为对象")
    if not isinstance(checksums.get("commit"), str) or not re.fullmatch(r"[a-f0-9]{40}", checksums["commit"]) or report.get("commit") != checksums["commit"]:
        raise ValueError("发行包与验收报告提交不一致")
    version = checksums.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", version):
        raise ValueError("发行包版本无效")
    expected = checksums.get("archives", [])
    actual = report.get("packages", [])
    if (not isinstance(expected, list) or not isinstance(actual, list) or len(expected) != 2 or len(actual) != 2
        or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in expected + actual)
        or len({item["name"] for item in expected}) != 2 or len({item["name"] for item in actual}) != 2
        or {item["name"] for item in actual} != {item["name"] for item in expected}):
        raise ValueError("必须核验主控平台与采集器两个 Linux ZIP")
    architectures = set()
    bundles = set()
    for archive in expected:
        name = re.fullmatch(r"starbeacon-(platform|collector)-" + re.escape(version) + r"-linux-(amd64|arm64)\.zip", archive["name"])
        if (name is None or type(archive.get("size")) is not int or not 0 < archive["size"] <= 1024 ** 3
            or not isinstance(archive.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", archive["sha256"])):
            raise ValueError("Linux ZIP 名称、大小或摘要无效")
        bundle, arch = name.groups()
        bundles.add(bundle)
        architectures.add(arch)
        matches = [item for item in actual if item.get("name") == archive.get("name")]
        if len(matches) != 1:
            raise ValueError("发行包验收记录重复或缺失")
        match = matches[0]
        if match.get("sha256") != archive.get("sha256") or match.get("status") != "passed" or match.get("execution") != "remote_docker" or match.get("binaries") != "upx_compressed" or match.get("version") != checksums.get("version"):
            raise ValueError("压缩发行包未完成真实远程端到端测试")
        verify_evidence(directory, match.get("evidence", {}))
        verify_archive(archives_directory / archive["name"], archive, checksums, bundle, arch)
    if bundles != {"platform", "collector"} or len(architectures) != 1:
        raise ValueError("必须提供同一 Linux 架构的平台与采集器两个包")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("checksums", type=pathlib.Path)
    args = parser.parse_args()
    try:
        verify(json.loads(args.report.read_text()), json.loads(args.checksums.read_text()), args.report.parent, args.checksums.parent)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError) as error:
        print(f"发行包验收失败：{error}", file=sys.stderr)
        return 1
    print("两个 UPX 压缩 Linux 发行包与远程端到端证据一致")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
