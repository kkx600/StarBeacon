#!/usr/bin/env python3
"""核对版本标签、实际 Linux ZIP 与发行说明，并发布 GitHub Release。

推送 v* 标签后由 .github/workflows/release.yml 调用。检查范围是工程检查与发行包结构，不代表完整产品或生产环境验收。
"""
import argparse
import hashlib
import json
import pathlib
import re
import stat
import struct
import subprocess
import sys
import zipfile

from package_linux import ROLES, GO_VERSION, UPX_VERSION, stream_digest, frontend_licenses
from package_go_dependencies import verify_bundle as verify_go_dependencies

ROOT = pathlib.Path(__file__).resolve().parents[1]
# 与 package_linux.py 的版本格式兼容，另外拒绝前导零与构建元数据，保证文件名和标签一一对应。
VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?")
COMMIT = re.compile(r"[a-f0-9]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
BUNDLES = ("platform", "collector")
ARCH = "amd64"


def validate_version(version):
    """返回是否为预发布版本；带 -rc.1 等后缀的标签发布为 GitHub Prerelease。"""
    if not isinstance(version, str) or len(version) > 64 or VERSION.fullmatch(version) is None:
        raise ValueError("版本标签必须为 v主版本.次版本.修订版本，可带 -rc.1 等预发布后缀")
    return "-" in version


def validate_identity(version, commit, repository):
    prerelease = validate_version(version)
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        raise ValueError("必须绑定完整提交 SHA")
    if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
        raise ValueError("仓库标识无效")
    return prerelease


def gh_api(path, method="GET"):
    """调用 GitHub REST API；令牌由 GH_TOKEN 提供，不写入日志或参数。"""
    arguments = ["gh", "api", path] + ([] if method == "GET" else ["-X", method])
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError(f"GitHub API 调用失败：{method} {path}：{result.stderr.strip()[:300]}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def run_gh(arguments):
    subprocess.run(arguments, check=True, timeout=1800)


def tag_commit(repository, version, api):
    """解析标签实际指向的提交，兼容附注标签；返回提交与解析过程经过的全部对象 SHA。"""
    reference = api(f"repos/{repository}/git/ref/tags/{version}")
    target = reference.get("object") if isinstance(reference, dict) else None
    chain = []
    for _ in range(4):
        if not isinstance(target, dict) or not isinstance(target.get("sha"), str) or COMMIT.fullmatch(target["sha"]) is None:
            break
        chain.append(target["sha"])
        if target.get("type") == "commit":
            return target["sha"], chain
        if target.get("type") != "tag":
            break
        annotated = api(f"repos/{repository}/git/tags/{target['sha']}")
        target = annotated.get("object") if isinstance(annotated, dict) else None
    raise ValueError(f"标签 {version} 没有指向有效提交")


def identity(version, repository, sha, api, branch="main"):
    """核对触发运行的标签仍指向本次提交，且该提交已合入发布分支。"""
    prerelease = validate_identity(version, sha, repository)
    commit, chain = tag_commit(repository, version, api)
    if sha not in chain:
        raise ValueError(f"标签 {version} 已指向其他提交，请以当前标签重新触发发布")
    comparison = api(f"repos/{repository}/compare/{branch}...{commit}")
    if not isinstance(comparison, dict) or comparison.get("status") not in ("behind", "identical"):
        raise ValueError(f"标签 {version} 指向的提交不在 {branch} 分支历史中，不能发布")
    return {"version": version, "commit": commit, "prerelease": "true" if prerelease else "false"}


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


def verify_packages(directory, version, commit):
    """核对发行清单、两个 ZIP 的名称集合、摘要与包内结构，返回发行清单。"""
    validate_version(version)
    path = directory / "checksums.json"
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024:
        raise ValueError("发行清单不存在或体积无效")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != version or data.get("commit") != commit:
        raise ValueError("发行包提交或版本与标签不一致")
    expected = {f"starbeacon-{bundle}-{version}-linux-{ARCH}.zip": bundle for bundle in BUNDLES}
    records = data.get("archives")
    if (not isinstance(records, list) or len(records) != len(expected)
            or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in records)
            or {item["name"] for item in records} != set(expected)
            or {item.name for item in directory.glob("*.zip")} != set(expected)):
        raise ValueError("必须提供平台与采集器两个 Linux amd64 ZIP")
    for item in records:
        if (type(item.get("size")) is not int or not 0 < item["size"] <= 1024 ** 3
                or not isinstance(item.get("sha256"), str) or re.fullmatch(r"[a-f0-9]{64}", item["sha256"]) is None):
            raise ValueError("发行 ZIP 大小或摘要无效")
        verify_archive(directory / item["name"], item, data, expected[item["name"]], ARCH)
    return data


def release_notes(directory, data, version, commit, repository, run_url, root=ROOT):
    """生成发行说明：优先使用 docs/releases/<版本>.md，并附加来源提交、工作流运行与 SHA-256。"""
    prerelease = validate_identity(version, commit, repository)
    if not isinstance(run_url, str) or re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/" + re.escape(repository) + r"/actions/runs/[1-9][0-9]{0,19}", run_url) is None:
        raise ValueError("工作流运行地址无效")
    server = run_url.split("/" + repository + "/actions/runs/")[0]
    documents = f"{server}/{repository}/blob/{commit}/docs/"
    source = root / "docs/releases" / (version + ".md")
    if source.exists() or source.is_symlink():
        if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size <= 64 * 1024:
            raise ValueError("发行说明文件类型或体积无效")
        notes = source.read_text(encoding="utf-8").rstrip().replace("](../", "](" + documents)
    else:
        kind = "预发布版本，用于隔离环境的安装与功能验证。" if prerelease else "正式版本。"
        notes = (f"# StarBeacon {version}\n\n{kind}主控平台与采集器各提供一个 Linux amd64 ZIP，Go 程序经 UPX 压缩，"
                 "包内含对应前端、Nginx 同源代理示例、版本清单、项目与依赖许可及 CycloneDX SBOM，不含运行凭据。\n\n"
                 f"ZIP 不是一键安装的完整运行环境，PostgreSQL、Elasticsearch、Redis、NATS、对象存储、Suricata、TLS 与身份凭据按[工程实现与开发]({documents}工程实现与开发.md)配置。")
    notes += (f"\n\n## 构建与核验\n\n来源提交：`{commit}`。[本次发布的工程检查与打包运行]({run_url})。\n\n"
              "发布前同一工作流完成 Go 构建、测试、静态检查与集成测试编译，前端测试、覆盖率、类型检查与构建，以及原型检查；"
              "两个 ZIP 已核对 SHA-256、Linux ELF、UPX 压缩与解压、实际版本回读、项目与前端许可及 Go 依赖与 SBOM。"
              f"这些检查不代表完整产品或生产环境验收，功能范围与缺口见[功能实现与验收状态]({documents}功能实现与验收状态.md)。\n\n"
              "| 文件 | SHA-256 |\n| --- | --- |\n")
    notes += "\n".join(f"| {item['name']} | `{item['sha256']}` |" for item in data["archives"]) + "\n"
    target = directory / "notes.md"
    target.write_text(notes, encoding="utf-8")
    return target


def publish(directory, version, commit, repository, api=gh_api, gh=run_gh):
    """复核下载的发行包后创建 Release；清理失败运行留下的同版本草稿，已发布版本不覆盖。"""
    prerelease = validate_identity(version, commit, repository)
    data = verify_packages(directory, version, commit)
    notes = directory / "notes.md"
    if notes.is_symlink() or not notes.is_file() or not 0 < notes.stat().st_size <= 128 * 1024:
        raise ValueError("缺少发行说明")
    if tag_commit(repository, version, api)[0] != commit:
        raise ValueError(f"标签 {version} 已指向其他提交，停止发布")
    releases = api(f"repos/{repository}/releases?per_page=100")
    if not isinstance(releases, list):
        raise ValueError("无法读取现有 Release")
    for release in releases:
        if not isinstance(release, dict) or release.get("tag_name") != version:
            continue
        if release.get("draft") is not True:
            raise ValueError(f"{version} 已发布，不能覆盖；请使用新的版本标签")
        if type(release.get("id")) is not int or release["id"] <= 0:
            raise ValueError("草稿 Release 标识无效")
        api(f"repos/{repository}/releases/{release['id']}", method="DELETE")
    files = [str(directory / item["name"]) for item in data["archives"]] + [str(directory / "checksums.json")]
    arguments = ["gh", "release", "create", version, *files, "--repo", repository, "--verify-tag",
                 "--title", f"StarBeacon {version}", "--notes-file", str(notes)]
    if prerelease:
        arguments += ["--prerelease", "--latest=false"]
    gh(arguments)
    return arguments


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("identity", help="核对标签与提交，按 GITHUB_OUTPUT 格式输出版本信息")
    check.add_argument("--version", required=True)
    check.add_argument("--repository", required=True)
    check.add_argument("--sha", required=True, help="触发运行的 GITHUB_SHA")
    check.add_argument("--branch", default="main")
    for name in ("verify", "notes", "publish"):
        command = commands.add_parser(name)
        command.add_argument("--version", required=True)
        command.add_argument("--commit", required=True)
        command.add_argument("--directory", type=pathlib.Path, required=True)
        if name != "verify":
            command.add_argument("--repository", required=True)
        if name == "notes":
            command.add_argument("--run-url", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "identity":
            result = identity(args.version, args.repository, args.sha, gh_api, args.branch)
            print("\n".join(f"{key}={value}" for key, value in result.items()))
        elif args.command == "verify":
            data = verify_packages(args.directory, args.version, args.commit)
            print(f"发行包核对通过：{', '.join(item['name'] for item in data['archives'])}")
        elif args.command == "notes":
            validate_identity(args.version, args.commit, args.repository)
            data = verify_packages(args.directory, args.version, args.commit)
            print(f"已生成发行说明：{release_notes(args.directory, data, args.version, args.commit, args.repository, args.run_url)}")
        else:
            publish(args.directory, args.version, args.commit, args.repository)
            print(f"已发布 StarBeacon {args.version}")
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"发布核对失败：{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
