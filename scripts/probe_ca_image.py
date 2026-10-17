#!/usr/bin/env python3
"""分发固定摘要的官方 CA 镜像；镜像分发记录不代替部署和产品验收。"""
import argparse
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile

from init_step_ca import IMAGE

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/probe-ca-image.yml"
ARTIFACT = "starbeacon-probe-ca-image-linux-amd64"
ARCHIVE = "image.tar.gz"
SHA = re.compile(r"sha256:[a-f0-9]{64}")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_origin(run, artifacts, repository, commit, run_id):
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise ValueError("提交或镜像分发运行标识无效")
    if (not isinstance(run, dict) or str(run.get("id")) != run_id or run.get("head_sha") != commit
            or run.get("head_branch") != "main" or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("event") != "workflow_dispatch" or run.get("path") != WORKFLOW or not isinstance(run.get("head_repository"), dict)
            or run.get("head_repository", {}).get("full_name") != repository):
        raise ValueError("镜像须来自本仓库 main 指定提交的成功分发运行")
    if not isinstance(artifacts, dict) or not isinstance(artifacts.get("artifacts"), list):
        raise ValueError("镜像制品目录无效")
    matches = [row for row in artifacts["artifacts"] if isinstance(row, dict) and row.get("name") == ARTIFACT]
    if len(matches) != 1 or matches[0].get("expired") is not False:
        raise ValueError("缺少唯一且未过期的官方 CA 镜像制品")
    origin = matches[0].get("workflow_run", {})
    if (not isinstance(origin, dict) or str(origin.get("id")) != run_id
            or origin.get("head_sha") != commit or origin.get("head_branch") != "main"):
        raise ValueError("镜像制品与分发运行不一致")


def verify_image(metadata):
    expected = IMAGE.split(":0.30.2@", 1)[0] + "@" + IMAGE.split("@", 1)[1]
    if (not isinstance(metadata, dict) or metadata.get("Os") != "linux" or metadata.get("Architecture") != "amd64"
            or not SHA.fullmatch(str(metadata.get("Id", ""))) or not isinstance(metadata.get("RepoDigests"), list)
            or expected not in metadata["RepoDigests"] or not isinstance(metadata.get("RootFS"), dict)
            or metadata["RootFS"].get("Type") != "layers"):
        raise ValueError("官方 CA 镜像摘要或架构不符")
    layers = metadata.get("RootFS", {}).get("Layers", [])
    if not isinstance(layers, list) or not 1 <= len(layers) <= 64 or any(not SHA.fullmatch(str(layer)) for layer in layers):
        raise ValueError("官方 CA 镜像层记录无效")
    return {key: metadata[key] for key in ("Id", "Os", "Architecture", "RepoDigests", "RootFS")}


def archive_identity(archive, image):
    small, digests, sizes = {}, {}, {}
    total = 0
    # Docker save 的外层只包含普通元数据和层文件，不展开镜像文件系统。
    with tarfile.open(archive, "r|gz") as bundle:
        for member in bundle:
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or member.name in sizes or not (member.isdir() or member.isfile()):
                raise ValueError("镜像归档成员不符合约束")
            if member.isdir():
                continue
            if len(sizes) >= 512 or member.size < 0:
                raise ValueError("镜像归档成员数量无效")
            total += member.size
            if total > 2 * 1024 ** 3:
                raise ValueError("镜像归档展开体积超限")
            digest, data = hashlib.sha256(), bytearray()
            with bundle.extractfile(member) as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    if member.size <= 1024 * 1024:
                        data.extend(block)
            digests[member.name], sizes[member.name] = "sha256:" + digest.hexdigest(), member.size
            if member.size <= 1024 * 1024:
                small[member.name] = bytes(data)
    def document(name):
        if name not in small:
            raise ValueError("镜像归档缺少受限元数据")
        return json.loads(small[name])
    saved = document("manifest.json")
    if not isinstance(saved, list) or len(saved) != 1 or not isinstance(saved[0], dict):
        raise ValueError("镜像归档必须包含唯一的 Docker 保存记录")
    row = saved[0]
    config_name, layers = row.get("Config"), row.get("Layers")
    if not isinstance(config_name, str) or not isinstance(layers, list) or any(not isinstance(layer, str) for layer in layers):
        raise ValueError("镜像配置或层引用无效")
    config = document(config_name)
    config_digest = digests[config_name]
    if (not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "amd64"
            or config.get("rootfs") != {"type": "layers", "diff_ids": image["RootFS"]["Layers"]}
            or [digests.get(layer) for layer in layers] != image["RootFS"]["Layers"]):
        raise ValueError("镜像配置或层内容与来源记录不同")
    identifiers = {config_digest}
    manifest_digest = None
    if "index.json" in small:
        index = document("index.json")
        descriptors = index.get("manifests") if isinstance(index, dict) else None
        if not isinstance(descriptors, list) or len(descriptors) != 1 or not isinstance(descriptors[0], dict):
            raise ValueError("镜像归档必须包含唯一 OCI 清单")
        descriptor = descriptors[0]
        manifest_digest = descriptor.get("digest")
        if not SHA.fullmatch(str(manifest_digest)):
            raise ValueError("镜像 OCI 清单摘要无效")
        name = "blobs/sha256/" + manifest_digest.split(":")[1]
        manifest = document(name)
        if digests[name] != manifest_digest or descriptor.get("size") != sizes[name] or not isinstance(manifest, dict):
            raise ValueError("镜像 OCI 清单内容摘要不同")
        configuration, references = manifest.get("config"), manifest.get("layers")
        if (not isinstance(configuration, dict) or configuration.get("digest") != config_digest
                or configuration.get("size") != sizes[config_name] or not isinstance(references, list)
                or any(not isinstance(layer, dict) for layer in references)
                or [layer.get("digest") for layer in references] != image["RootFS"]["Layers"]
                or [layer.get("size") for layer in references] != [sizes[layer] for layer in layers]):
            raise ValueError("镜像 OCI 清单未绑定实际配置和全部层")
        identifiers.add(manifest_digest)
    if image["Id"] not in identifiers:
        raise ValueError("来源引擎的镜像 ID 未绑定归档内容")
    return {"config_digest": config_digest, "save_manifest_digest": manifest_digest, "load_ids": sorted(identifiers)}


def verify_loaded(metadata, verified):
    if (not isinstance(metadata, dict) or metadata.get("Id") not in verified.get("content_identity", {}).get("load_ids", [])
            or any(metadata.get(key) != verified.get(key) for key in ("Os", "Architecture", "RootFS"))):
        raise ValueError("导入后的镜像内容身份不同")
    return metadata["Id"]


def export(directory):
    directory = directory.absolute()
    if (".." in directory.parts or not directory.is_relative_to(ROOT / ".local/acceptance")
            or directory.exists() or directory.is_symlink() or any(parent.is_symlink() for parent in directory.parents)):
        raise ValueError("镜像输出须使用全新的工程验收目录")
    env = os.environ
    repository, commit, run_id = (env.get(key, "") for key in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID"))
    if (env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or env.get("GITHUB_WORKFLOW_REF") != repository + "/" + WORKFLOW + "@refs/heads/main"
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id)):
        raise ValueError("镜像导出仅允许 main 分支的手动分发工作流")
    subprocess.run(["docker", "pull", "--platform", "linux/amd64", IMAGE], check=True, timeout=240)
    observed = json.loads(subprocess.check_output(["docker", "image", "inspect", IMAGE], timeout=30))
    if not isinstance(observed, list) or len(observed) != 1:
        raise ValueError("镜像检查结果不唯一")
    image = verify_image(observed[0])
    directory.mkdir(mode=0o755, parents=True)
    temporary = directory / "image.tar"
    try:
        # save 保留全部层及文件能力；容器文件系统 export 不适用于镜像分发。
        subprocess.run(["docker", "image", "save", "--output", str(temporary), image["Id"]], check=True, timeout=180)
        with temporary.open("rb") as source, (directory / ARCHIVE).open("xb") as target:
            with gzip.GzipFile(filename="", mode="wb", fileobj=target, compresslevel=1, mtime=0) as compressed:
                shutil.copyfileobj(source, compressed, length=1024 * 1024)
    finally:
        temporary.unlink(missing_ok=True)
    archive = directory / ARCHIVE
    report = {"schema_version": 1, "scope": "official_probe_ca_image_distribution", "repository": repository,
              "commit": commit, "run_id": run_id, "workflow": WORKFLOW, "requested_image": IMAGE, "image": image,
              "archive": {"name": ARCHIVE, "size": archive.stat().st_size, "sha256": sha256(archive)}}
    with (directory / "image.json").open("x") as target:
        json.dump(report, target, indent=2)
        target.write("\n")
    print(json.dumps({"status": "exported", "image_id": image["Id"], "archive_sha256": report["archive"]["sha256"]}))


def verify(directory, origin, repository, commit, run_id):
    if not isinstance(origin, dict):
        raise ValueError("镜像制品来源记录无效")
    verify_origin(origin.get("run"), origin.get("artifacts"), repository, commit, run_id)
    directory = directory.absolute()
    if directory.is_symlink() or any(parent.is_symlink() for parent in directory.parents):
        raise ValueError("镜像制品目录不能使用符号链接")
    for name in ("image.json", ARCHIVE):
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("镜像制品不完整")
    report = json.loads((directory / "image.json").read_text())
    if (not isinstance(report, dict) or report.get("schema_version") != 1 or report.get("scope") != "official_probe_ca_image_distribution"
            or report.get("repository") != repository or report.get("commit") != commit or report.get("run_id") != run_id
            or report.get("workflow") != WORKFLOW or report.get("requested_image") != IMAGE):
        raise ValueError("镜像分发记录与指定来源不符")
    image = verify_image(report.get("image"))
    archive = directory / ARCHIVE
    expected = report.get("archive", {})
    if (not isinstance(expected, dict) or expected.get("name") != ARCHIVE or type(expected.get("size")) is not int or not 1 <= expected["size"] <= 1024 ** 3
            or expected["size"] != archive.stat().st_size or not re.fullmatch(r"[a-f0-9]{64}", str(expected.get("sha256", "")))
            or expected["sha256"] != sha256(archive)):
        raise ValueError("镜像归档内容摘要不符")
    image["content_identity"] = archive_identity(archive, image)
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("export")
    create.add_argument("--directory", type=pathlib.Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--directory", type=pathlib.Path, required=True)
    check.add_argument("--origin", type=pathlib.Path, required=True)
    for name in ("repository", "commit", "run-id"):
        check.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        if args.command == "export":
            export(args.directory)
        else:
            image = verify(args.directory, json.loads(args.origin.read_text()), args.repository, args.commit, args.run_id)
            print(json.dumps({"status": "verified", "image_id": image["Id"], "platform": "linux/amd64", "content_identity": image["content_identity"]}))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print("探针 CA 镜像分发未完成：" + (str(error) if isinstance(error, ValueError) else type(error).__name__))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
