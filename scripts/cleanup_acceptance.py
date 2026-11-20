#!/usr/bin/env python3
"""按项目归属清理验收文件；业务状态与当前、回退制品独立保护。"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
PRIVATE_PARTS = {"data", "pki", "trust", "credentials", "identity", "wal", "state"}
PRIVATE_SUFFIXES = {".env", ".key", ".pem", ".crt", ".db", ".sqlite", ".bolt", ".wal"}
TTL_SECONDS = 48 * 3600
CACHE_BASE = pathlib.Path("/var/lib/starbeacon-acceptance")


def version_key(value):
    match = VERSION.fullmatch(value)
    if not match:
        raise ValueError("版本必须符合语义化版本格式")
    major, minor, patch = map(int, match.groups()[:3])
    pre = match.group(4)
    identifiers = tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre.split(".")) if pre else ()
    if pre and any(not x or (x.isdigit() and len(x) > 1 and x.startswith("0")) for x in pre.split(".")):
        raise ValueError("预发布版本标识无效")
    return major, minor, patch, int(pre is None), identifiers


def previous_versions(values, current):
    current_key = version_key(current)
    unique = {version_key(v): v for v in sorted(values)
              if version_key(v) < current_key and (not current_key[3] or version_key(v)[3])}
    earlier = [unique[key] for key in sorted(unique, reverse=True)]
    return [current, *earlier[:1]]


def read_json(path):
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("清理元数据不是有界普通文件")
    return json.loads(path.read_text())


def safe_directory(path):
    path = path.absolute()
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("清理目录不得越界或包含符号链接")
    if not path.is_dir():
        raise ValueError("清理目录不存在")
    return path


def regular_files(directory):
    for base, directories, files in os.walk(directory, followlinks=False):
        directories[:] = [d for d in directories if not pathlib.Path(base, d).is_symlink()]
        for name in files:
            path = pathlib.Path(base, name)
            if not path.is_symlink() and path.is_file():
                yield path


def beneath(path, parent):
    return path == parent or parent in path.parents


def state_file(path):
    try:
        value = read_json(path)
        return isinstance(value, dict) and (
            all(isinstance(value.get(k), str) for k in ("host", "project", "directory"))
            or value.get("scope") in {"development_ui_review", "isolated_live_capture_ui_review"}
        )
    except (OSError, ValueError, UnicodeError):
        return False


def complete_bundle(directory):
    try:
        records = read_json(directory / "checksums.json")["archives"]
        for record in records:
            name = record["name"]
            if not isinstance(name, str) or pathlib.PurePosixPath(name).name != name or "\\" in name or not name.endswith(".zip"):
                return False
            path = directory / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size != record["size"]:
                return False
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != record["sha256"]:
                return False
        return len(records) == 2 and len({r["name"] for r in records}) == 2
    except (OSError, ValueError, KeyError, TypeError):
        return False


def default_version(root):
    tags = subprocess.check_output(["git", "tag", "--list", "v*"], cwd=root, text=True).splitlines()
    versions = []
    for tag in tags:
        try:
            version_key(tag)
            versions.append(tag)
        except ValueError:
            continue
    if not versions:
        raise ValueError("没有可核对的版本标签，请使用 --current-version 指定当前版本")
    return max(versions, key=version_key)


def file_identity(path, directory):
    info = path.lstat()
    return {"path": path.relative_to(directory).as_posix(), "bytes": info.st_size,
            "device": info.st_dev, "inode": info.st_ino, "mtime_ns": info.st_mtime_ns}


def local_plan(root=ROOT, *, current=None, keep=(), now=None):
    root = safe_directory(pathlib.Path(root))
    directory = safe_directory(root / ".local/acceptance")
    if current is None:
        try:
            current = default_version(root)
        except ValueError:
            current = None
    if current is not None:
        version_key(current)
    now = time.time() if now is None else now
    files = list(regular_files(directory))
    protected = []
    for name in keep:
        path = pathlib.Path(name)
        if ".." in path.parts:
            raise ValueError("保留路径不得包含父目录跳转")
        path = path.absolute() if path.is_absolute() else (root / path).absolute()
        if not beneath(path, directory) or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("保留路径必须位于本项目验收目录且不含链接")
        protected.append(path)
    # 部署状态保留定位信息及凭据，不因其最初生成于旧版本而失去恢复依据。
    protected += [p for p in files if p.parent == directory and p.suffix == ".json" and state_file(p)]
    report_sets = []
    packages = {}
    for path in files:
        if path.name in {"backend.json", "frontend.json"} or path.name.endswith(("-backend.json", "-frontend.json")):
            try:
                value = read_json(path)
                source = value.get("workspace_sha256", value.get("source_sha256"))
                if value.get("status") == "passed" and isinstance(source, str) and re.fullmatch(r"[a-f0-9]{64}", source):
                    report_sets.append((path.stat().st_mtime_ns, source, path))
            except (OSError, ValueError, AttributeError):
                pass
        if path.name == "checksums.json":
            try:
                value = read_json(path)
                version_key(value["version"])
                if isinstance(value.get("archives"), list) and len(value["archives"]) == 2:
                    packages.setdefault(value["version"], []).append(path.parent)
            except (OSError, ValueError, KeyError, TypeError):
                pass
    retained = previous_versions(packages, current) if current is not None else []
    retained_directories = []
    protected.extend(p for version, entries in packages.items()
                     if current is None or version_key(version) > version_key(current) for p in entries)
    for version in retained:
        directories = [p for name, entries in packages.items() if version_key(name) == version_key(version) for p in entries]
        if directories:
            chosen = max(directories, key=lambda p: (complete_bundle(p), p.joinpath("checksums.json").stat().st_mtime_ns, str(p)))
            if chosen == directory:
                raise ValueError("发行包清单不得直接占用验收根目录")
            retained_directories.append(chosen)
            protected.append(chosen)
    report_sources, retained_reports = {"backend": set(), "frontend": set()}, []
    selected_reports = set()
    for _, source, path in sorted(report_sets, reverse=True):
        kind = "frontend" if path.name.endswith("frontend.json") else "backend"
        if source in report_sources[kind] or len(report_sources[kind]) >= 2:
            continue
        report_sources[kind].add(source)
        selected_reports.add(path)
        # 平铺摘要和完整原始报告可能分别回传；每份保留结果同时保留一份同源原始目录。
        nested = [entry for entry in report_sets if entry[1] == source and entry[2].parent != directory
                  and ("frontend" if entry[2].name.endswith("frontend.json") else "backend") == kind]
        if nested:
            selected_reports.add(max(nested)[2])
    for path in sorted(selected_reports):
        if path.parent == directory:
            prefix = path.name.removesuffix("-backend.json").removesuffix("-frontend.json")
            siblings = [p for p in files if p.parent == directory and p.name.startswith(prefix + "-")]
            protected.extend(siblings)
        else:
            protected.append(path.parent)
        retained_reports.append(path.relative_to(directory).as_posix())
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    tracked = {root / p for p in raw if p}
    protected_paths = set(protected)
    versioned_paths = {p for entries in packages.values() for p in entries}
    # 刚创建的解包目录可能包含保留旧修改时间的成员，不能仅凭成员时间将其判作旧日志。
    protected_paths.update(p for p in directory.iterdir()
                           if p.is_dir() and not p.is_symlink() and p not in versioned_paths
                           and p.stat().st_mtime > now - TTL_SECONDS)
    deletions, retained_count, protected_bytes = [], 0, 0
    for path in files:
        relative = path.relative_to(directory)
        identity = file_identity(path, directory)
        parents = (path, *path.parents)
        preserve = (path in tracked or path.suffix in PRIVATE_SUFFIXES
                    or any(part in PRIVATE_PARTS for part in relative.parts)
                    or any(p in protected_paths for p in parents)
                    or (not any(p in versioned_paths for p in parents)
                        and path.stat().st_mtime > now - TTL_SECONDS))
        if preserve:
            retained_count += 1
            protected_bytes += identity["bytes"]
        else:
            deletions.append(identity)
    return {"schema_version": 1, "kind": "local_acceptance", "directory": str(directory),
            "current_version": current, "retained_versions": retained,
            "retained_package_directories": [str(p.relative_to(directory)) for p in retained_directories],
            "retained_report_sets": retained_reports, "protected_files": retained_count,
            "protected_bytes": protected_bytes, "grace_hours": 48,
            "files": deletions, "planned_bytes": sum(p["bytes"] for p in deletions)}


def apply_files(plan):
    directory = safe_directory(pathlib.Path(plan["directory"]))
    before = shutil.disk_usage(directory).free
    deleted, skipped, size = 0, [], 0
    for expected in plan["files"]:
        relative = pathlib.PurePosixPath(expected["path"])
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("清理文件路径越界")
        path = directory.joinpath(relative)
        try:
            if any(p.is_symlink() for p in (path, *path.parents)) or not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("文件类型已变化")
            if file_identity(path, directory) != expected:
                raise ValueError("文件身份已变化")
            # 私有工程目录由当前用户控制；打开父目录并以相对路径删除，防止父路径在检查后被替换。
            parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in relative.parts[:-1]:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    os.close(parent_fd)
                    parent_fd = next_fd
                actual = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (expected["device"], expected["inode"], expected["bytes"], expected["mtime_ns"]):
                    raise ValueError("删除前文件身份已变化")
                os.unlink(path.name, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            deleted += 1
            size += expected["bytes"]
        except (OSError, ValueError) as error:
            skipped.append({"path": expected["path"], "reason": type(error).__name__})
    # 仅回收已空的普通目录；保留凭据和身份的分支自然保持。
    for base, directories, _ in os.walk(directory, topdown=False, followlinks=False):
        for name in directories:
            path = pathlib.Path(base, name)
            if (path.is_symlink() or any(part in PRIVATE_PARTS for part in path.relative_to(directory).parts)
                    or path.stat().st_mtime > time.time() - TTL_SECONDS):
                continue
            try:
                path.rmdir()
            except OSError:
                pass
    return {"status": "passed" if not skipped else "partial", "deleted_files": deleted,
            "deleted_logical_bytes": size, "skipped": skipped,
            "disk_free_before": before, "disk_free_after": shutil.disk_usage(directory).free}


def docker_command(arguments, *, timeout=30):
    return subprocess.check_output(["docker", *arguments], text=True, stderr=subprocess.PIPE, timeout=timeout)


def docker_containers(command):
    ids = command(["container", "ls", "-aq", "--no-trunc"]).split()
    containers = []
    template = '{"Id":{{json .Id}},"Image":{{json .Image}},"Name":{{json .Name}},"State":{{json .State}},"Labels":{{json .Config.Labels}}}'
    for identity in ids:
        containers.append(json.loads(command(["container", "inspect", "--format", template, identity])))
    return containers


def docker_inventory(command=docker_command):
    command(["version", "--format", "{{.Server.Version}}"], timeout=15)
    containers = docker_containers(command)
    ids = sorted(set(command(["image", "ls", "-aq", "--no-trunc"]).split()))
    images = []
    template = '{"Id":{{json .Id}},"Parent":{{json .Parent}},"RepoTags":{{json .RepoTags}},"Created":{{json .Created}},"Size":{{json .Size}},"Labels":{{json .Config.Labels}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}'
    for identity in ids:
        images.append(json.loads(command(["image", "inspect", "--format", template, identity])))
    return containers, images


def owned_repository(tag):
    repository = tag.rsplit(":", 1)[0]
    return repository.startswith(("starbeacon/", "starbeacon-"))


def docker_plan(containers, images, *, now=None):
    now = time.time() if now is None else now
    referenced = {c["Image"] for c in containers}
    protected = set(referenced)
    groups = {}
    candidates = []
    for image in images:
        tags, labels = image.get("RepoTags") or [], image.get("Labels") or {}
        owned = bool(tags) and all(owned_repository(t) for t in tags)
        owned = owned or (not tags and bool(re.fullmatch(r"[a-f0-9]{64}", labels.get("io.starbeacon.acceptance.source", ""))))
        if not owned:
            protected.add(image["Id"])
            continue
        candidates.append(image)
        try:
            if datetime.datetime.fromisoformat(image["Created"].replace("Z", "+00:00")).timestamp() > now - TTL_SECONDS:
                protected.add(image["Id"])
        except (ValueError, TypeError, KeyError):
            protected.add(image["Id"])
        for repository in {t.rsplit(":", 1)[0] for t in tags} or {"starbeacon/untagged"}:
            groups.setdefault((repository, image.get("Os"), image.get("Architecture")), []).append(image)
    for group in groups.values():
        def rank(image):
            versions = []
            for tag in image.get("RepoTags") or []:
                try:
                    versions.append(version_key(tag.rsplit(":", 1)[1]))
                except ValueError:
                    pass
            return bool(versions), max(versions) if versions else ()
        def key(image):
            return *rank(image), image["Created"], image["Id"]
        ordered = sorted(group, key=key, reverse=True)
        # 旧的停止容器可以继续引用历史镜像，但不能因此回收已准备的较新发行版本。
        current = ordered[0]
        protected.add(current["Id"])
        earlier = [i for i in ordered if (rank(i) < rank(current) if rank(current)[0] else key(i) < key(current))
                   and (not rank(current)[0] or not rank(current)[1][3] or (rank(i)[0] and rank(i)[1][3]))]
        if earlier:
            protected.add(earlier[0]["Id"])
    # 镜像父层可能没有标签；保留回退镜像的祖先，禁止隐式回收共享层。
    by_id = {i["Id"]: i for i in images}
    pending = list(protected)
    while pending:
        parent = by_id.get(pending.pop(), {}).get("Parent")
        if parent and parent not in protected:
            protected.add(parent)
            pending.append(parent)
    return {"kind": "docker", "images": [i for i in candidates if i["Id"] not in protected],
            "protected_images": sorted(protected), "container_count": len(containers),
            "shared_build_cache": "not_project_scoped_not_deleted", "volumes": "protected"}


def expired_oneoffs(containers, *, now=None):
    now = time.time() if now is None else now
    result = []
    for container in containers:
        labels = container.get("Labels") or {}
        state = container.get("State") or {}
        project = labels.get("com.docker.compose.project", "")
        if not (re.fullmatch(r"sbacc_[a-f0-9]{16}(?:_r[1-9][0-9]{0,2})?", project)
                and container.get("Name", "").startswith("/" + project + "-")
                and labels.get("com.docker.compose.oneoff", "").lower() == "true"
                and state.get("Status") == "exited"):
            continue
        try:
            finished = datetime.datetime.fromisoformat(state["FinishedAt"].replace("Z", "+00:00")).timestamp()
            if finished <= now - TTL_SECONDS:
                result.append(container)
        except (ValueError, TypeError, KeyError):
            continue
    return result


def cleanup_docker(*, apply=False, command=docker_command, audit=None):
    try:
        containers, images = docker_inventory(command)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"kind": "docker", "status": "unavailable", "reason": "Docker 不可用，未启动服务或删除镜像"}
    old_containers = expired_oneoffs(containers)
    container_results = []
    if apply and old_containers:
        if audit:
            audit({"status": "planned", "containers": old_containers})
        for candidate in old_containers:
            fresh = {c["Id"]: c for c in docker_containers(command)}
            if candidate["Id"] not in {c["Id"] for c in expired_oneoffs(list(fresh.values()))}:
                container_results.append({"container": candidate["Id"], "status": "protected_changed_state"})
                continue
            try:
                command(["container", "rm", candidate["Id"]], timeout=60)
                container_results.append({"container": candidate["Id"], "status": "removed"})
            except (OSError, subprocess.SubprocessError):
                container_results.append({"container": candidate["Id"], "status": "skipped_changed_or_referenced"})
        containers = docker_containers(command)
    plan = docker_plan(containers, images)
    plan["expired_containers"] = old_containers
    plan["status"] = "planned"
    if not apply:
        return plan
    if audit:
        audit({"status": "planned", "plan": plan})
    results = []
    for image in plan["images"]:
        try:
            live = docker_containers(command)
            if any(c["Image"] == image["Id"] for c in live):
                results.append({"image": image["Id"], "status": "protected_new_reference"})
                continue
            refs = image.get("RepoTags") or [image["Id"]]
            for reference in refs:
                observed = json.loads(command(["image", "inspect", "--format", "{{json .Id}}", reference]))
                if observed != image["Id"]:
                    raise ValueError("镜像标签已改变")
                command(["image", "rm", "--no-prune", reference], timeout=60)
            results.append({"image": image["Id"], "status": "removed"})
        except (OSError, ValueError, subprocess.SubprocessError):
            results.append({"image": image["Id"], "status": "skipped_changed_or_referenced"})
    plan["results"] = results
    plan["container_results"] = container_results
    plan["status"] = "passed" if all(r["status"] == "removed" for r in [*results, *container_results]) else "partial"
    return plan


def cleanup_build_cache(directory, project, *, apply=False, emit=None):
    """仅回收有持久归属标记的验收编译缓存，不回收 Docker 共享构建层。"""
    if not re.fullmatch(r"sbacc_[a-f0-9]{16}", project):
        raise ValueError("验收项目标识无效")
    directory = pathlib.Path(directory)
    if directory != CACHE_BASE / project:
        raise ValueError("编译缓存只能位于持久验收项目目录")
    safe_directory(directory)
    owner = read_json(directory / "owner.json")
    if owner != {"schema_version": 1, "project": project, "storage": "persistent"}:
        raise ValueError("验收项目归属标记不匹配")
    # 冷编译及测试期间均存在 go 父进程；保守拒绝与任何 Go 工具并行回收缓存。
    for process in ("go", "compile", "link"):
        result = subprocess.run(["pgrep", "-x", process], capture_output=True, timeout=10)
        if result.returncode == 0:
            return {"kind": "build_cache", "status": "busy", "reason": "存在运行中的 Go 工具进程"}
        if result.returncode != 1:
            raise ValueError("无法核对编译进程，保留缓存")
    cache_names = ("go-build-cache", "capture-go-build-cache")
    rows = []
    before = shutil.disk_usage(directory).free
    for name in cache_names:
        path = directory / name
        if not path.exists():
            continue
        safe_directory(path)
        info = path.stat()
        rows.append({"name": name, "device": info.st_dev, "inode": info.st_ino,
                     "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)})
    plan = {"kind": "build_cache", "status": "planned", "project": project,
            "directory": str(directory), "caches": rows, "disk_free_before": before}
    if not apply:
        return plan
    # 持久记录先于重命名和删除；中断后隔离目录仍有明确项目归属与来源。
    journal = directory / "cleanup"
    if journal.is_symlink():
        raise ValueError("清理记录目录不得为链接")
    journal.mkdir(mode=0o700, exist_ok=True)
    journal_path = journal / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".json")
    with journal_path.open("x") as file:
        os.fchmod(file.fileno(), 0o600)
        json.dump(plan, file, ensure_ascii=False)
        file.flush()
        os.fsync(file.fileno())
    results = []
    for row in rows:
        path = directory / row["name"]
        current = path.lstat()
        if path.is_symlink() or (current.st_dev, current.st_ino) != (row["device"], row["inode"]):
            results.append({"name": row["name"], "status": "protected_changed_identity"})
            continue
        quarantine = directory / (".cleanup-" + row["name"] + "-" + os.urandom(8).hex())
        row["quarantine"] = quarantine.name
        with journal_path.open("w") as file:
            json.dump(plan, file, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())
        os.rename(path, quarantine)
        path.mkdir(mode=row["mode"])
        os.chmod(path, row["mode"])
        os.chown(path, row["uid"], row["gid"])
        if emit:
            emit({"phase": "cache_detached", "name": row["name"]})
        try:
            subprocess.run(["rm", "-rf", "--", str(quarantine)], check=True, timeout=1800)
            results.append({"name": row["name"], "status": "removed"})
        except (OSError, subprocess.SubprocessError) as error:
            results.append({"name": row["name"], "status": "pending", "quarantine": str(quarantine), "reason": type(error).__name__})
        if emit:
            emit({"phase": "cache_removed", "name": row["name"], "disk_free": shutil.disk_usage(directory).free})
    plan.update(status="passed" if all(r["status"] == "removed" for r in results) else "partial",
                results=results, disk_free_after=shutil.disk_usage(directory).free)
    with journal_path.open("w") as file:
        json.dump(plan, file, ensure_ascii=False, indent=2)
        file.write("\n")
    return plan


def verify_remote_project(directory, project):
    if not isinstance(project, str) or not re.fullmatch(r"sbacc_[a-f0-9]{16}", project):
        raise ValueError("远程验收项目标识无效")
    if not directory or pathlib.Path(directory) != CACHE_BASE / project:
        raise ValueError("远程验收项目目录不匹配")
    path = safe_directory(pathlib.Path(directory))
    if read_json(path / "owner.json") != {"schema_version": 1, "project": project, "storage": "persistent"}:
        raise ValueError("远程验收项目归属标记不匹配")


def remote_project(host):
    candidates = []
    for path in (ROOT / ".local/acceptance").glob("*.json"):
        try:
            value = read_json(path)
            project = value.get("project")
            directory = value.get("directory")
            if (value.get("host") == host and isinstance(project, str)
                    and re.fullmatch(r"sbacc_[a-f0-9]{16}", project)
                    and directory == str(CACHE_BASE / project)):
                candidates.append((path.stat().st_mtime_ns, project, directory))
        except (OSError, ValueError, AttributeError):
            continue
    if not candidates:
        raise ValueError("没有可核对的远程项目状态，请明确 --project 和 --directory")
    _, project, directory = max(candidates)
    return project, directory


def save_report(root, value):
    directory = root / ".local/cleanup"
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise ValueError("清理记录目录不得包含符号链接")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_directory(directory)
    name = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".json"
    path = directory / name
    with path.open("x") as file:
        os.fchmod(file.fileno(), 0o600)
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    return path


def cleanup_local(root=ROOT, *, apply=False, current=None, keep=()):
    plan = local_plan(root, current=current, keep=keep)
    result = {"status": "planned", "plan": plan}
    report = save_report(pathlib.Path(root), result)
    if apply:
        result["result"] = apply_files(plan)
        result["status"] = result["result"]["status"]
        with tempfile.NamedTemporaryFile(mode="w", dir=report.parent, prefix=".cleanup-", delete=False) as file:
            temporary = pathlib.Path(file.name)
            os.fchmod(file.fileno(), 0o600)
            json.dump(result, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(report)
    return report, result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["local", "docker", "cache"])
    parser.add_argument("--apply", action="store_true", help="按生成清单执行；省略时只生成计划")
    parser.add_argument("--current-version")
    parser.add_argument("--keep", action="append", default=[], help="保护本项目验收目录内的文件或目录")
    parser.add_argument("--host", help="通过已配置的 SSH 主机执行 Docker 清理，不启动远程服务")
    parser.add_argument("--directory", help="专属远程编译缓存的持久项目目录")
    parser.add_argument("--project", help="专属远程验收项目标识")
    args = parser.parse_args(argv)
    if args.host:
        if args.kind not in {"docker", "cache"} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.host):
            parser.error("SSH 主机仅用于远程资源清理，必须是已配置的安全主机别名")
        command = ["python3", "-", args.kind, *(["--apply"] if args.apply else [])]
        if bool(args.directory) != bool(args.project):
            parser.error("远程清理的项目与目录必须成对提供")
        project, directory = (args.project, args.directory) if args.project else remote_project(args.host)
        command += ["--directory", directory, "--project", project]
        try:
            response = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", args.host, shlex.join(command)],
                                      input=pathlib.Path(__file__).read_text(), text=True, capture_output=True, timeout=3700)
            if response.returncode not in (0, 2):
                result = {"kind": args.kind, "status": "unavailable", "reason": "远程入口或项目执行环境不可用，未取得清理结果", "remote_exit_code": response.returncode}
            else:
                result = json.loads(response.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            result = {"kind": args.kind, "status": "unverified", "reason": "远程清理未取得可核对的结果", "error": type(error).__name__}
        result["host"] = args.host
        report = save_report(ROOT, result)
        print(json.dumps({"status": result["status"], "report": str(report)}, ensure_ascii=False))
        return 0 if result["status"] in {"planned", "passed"} else 2
    if args.kind == "cache":
        if not args.directory or not args.project:
            parser.error("缓存清理需要明确项目与持久目录")
        result = cleanup_build_cache(args.directory, args.project, apply=args.apply)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] in {"passed", "planned"} else 2
    if args.kind == "docker":
        if globals().get("__file__") == "<stdin>":
            try:
                verify_remote_project(args.directory, args.project)
            except (OSError, ValueError):
                print(json.dumps({"kind": "docker", "status": "unavailable", "reason": "远程项目归属无法核验，未清理 Docker 资源"}, ensure_ascii=False))
                return 2
        audit_root = pathlib.Path.home() / ".cache/starbeacon" if globals().get("__file__") == "<stdin>" else ROOT
        result = cleanup_docker(apply=args.apply, audit=lambda value: save_report(audit_root, value))
        # 标准输入执行时仅返回资源结果，清理报告由本地控制端持久保存。
        if globals().get("__file__") != "<stdin>":
            result["report"] = str(save_report(ROOT, result))
        print(json.dumps(result, ensure_ascii=False))
        return 2 if result["status"] in {"unavailable", "partial"} else 0
    report, result = cleanup_local(current=args.current_version, keep=args.keep, apply=args.apply)
    print(json.dumps({"status": result["status"], "report": str(report),
                      "retained_versions": result["plan"]["retained_versions"],
                      "planned_files": len(result["plan"]["files"]), "planned_bytes": result["plan"]["planned_bytes"],
                      **result.get("result", {})}, ensure_ascii=False))
    return 0 if result["status"] in {"planned", "passed"} else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit("验收清理未完成：" + type(error).__name__)
