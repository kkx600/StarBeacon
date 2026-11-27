#!/usr/bin/env python3
"""同步当前工作区，在远程执行关口二的指定组并回传报告。"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

import remote_acceptance as acceptance
from cleanup_acceptance import cleanup_local, save_report
from source_snapshot import snapshot, verify

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACCEPTANCE_DIR = ROOT / ".local/acceptance"
GROUPS = ("backend", "frontend", "contract")
ERRORS = (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError)
AS_RUNNER = '''
if [ "$(id -u)" = 0 ]; then
    exec runuser -u nobody -- "$@"
fi
exec "$@"
'''
INITIALIZE = '''
import pathlib, shutil, subprocess, sys
staging = pathlib.Path(sys.argv[1])
source = staging / "source"
source.mkdir()
def git(*arguments, **kwargs):
    subprocess.run(["git", *arguments], cwd=source, check=True, **kwargs)
git("init", "-q")
with (staging / "base.pack").open("rb") as pack:
    git("index-pack", "--stdin", stdin=pack)
commit = sys.argv[2]
(source / ".git/shallow").write_text(commit + "\\n")
git("reset", "--hard", "--quiet", commit)
patch = staging / "worktree.patch"
if patch.stat().st_size:
    git("apply", "--binary", str(patch))
pending = staging / "pending"
if pending.exists():
    shutil.copytree(pending, source, dirs_exist_ok=True)
reports = staging / "reports"
reports.mkdir()
shutil.copyfile(staging / "source.json", reports / "source.json")
'''


def git(*arguments, **options):
    return subprocess.run(["git", *arguments], cwd=ROOT, check=True, **options)


def prepare_source(destination, *, frontend):
    """传送浅版本的原始提交、已跟踪文件差异及未跟踪源码，保留真实提交号。"""
    commit = git("rev-parse", "HEAD", stdout=subprocess.PIPE, text=True).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("当前提交号无效")
    objects = git("rev-list", "--objects", "--no-object-names", "--max-count=1", commit, stdout=subprocess.PIPE).stdout
    patch = git("diff", "--binary", "--no-ext-diff", "--no-textconv", commit, "--", stdout=subprocess.PIPE).stdout
    untracked = git("ls-files", "--others", "--exclude-standard", "-z", stdout=subprocess.PIPE).stdout
    paths = sorted(set(untracked.decode().split("\0")) - {""})
    digest = hashlib.sha256(commit.encode() + b"\0" + hashlib.sha256(patch).digest())
    pack = destination.with_suffix(".pack")
    with pack.open("xb") as output:
        git("-c", "pack.threads=2", "pack-objects", "--stdout", "--window=0", input=objects, stdout=output)
    with tarfile.open(destination, "w") as archive:
        archive.add(pack, arcname="base.pack")
        acceptance.archive_bytes(archive, "worktree.patch", patch)
        for name in paths:
            relative = pathlib.PurePosixPath(name)
            path = ROOT / relative
            if relative.is_absolute() or ".." in relative.parts or path.is_symlink() or not path.is_file():
                raise ValueError(f"未跟踪源码路径无效：{name}")
            data = path.read_bytes()
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            acceptance.archive_bytes(archive, "pending/" + name, data, mode=mode)
            digest.update(name.encode() + b"\0" + str(mode).encode() + b"\0" + hashlib.sha256(data).digest())
        identity = {"commit": commit, "workspace_sha256": digest.hexdigest(), "clean_commit": not patch and not paths}
        acceptance.archive_bytes(archive, "source.json", (json.dumps(identity) + "\n").encode())
        if frontend:
            acceptance.archive_bytes(archive, "web-source.json", (json.dumps(snapshot(ROOT)) + "\n").encode())
    return identity


def runner_ssh(host, arguments, **options):
    return acceptance.ssh(host, ["sh", "-c", AS_RUNNER, "starbeacon-validation", *arguments], **options)


def step(directory, report, name, action):
    started = time.monotonic()
    row = {"name": name, "status": "passed", "log": name + ".log"}
    with (directory / row["log"]).open("wb") as log:
        try:
            action(log)
        except ERRORS as error:
            row["status"] = "failed"
            row["error"] = str(error)
            log.write((f"验收步骤失败：{error}\n").encode())
    row["duration_seconds"] = round(time.monotonic() - started, 3)
    report.append(row)
    outcome = "通过" if row["status"] == "passed" else "失败"
    print(f"{directory.name}/{name}  {outcome}  {row['duration_seconds']:.2f} 秒", flush=True)
    return row["status"] == "passed"


def command(directory, report, name, arguments, *, timeout=None):
    return step(directory, report, name, lambda log: subprocess.run(
        arguments, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout,
    ))


def backend_checks(args, output, result, expected_source=None):
    output.mkdir()
    steps = result["steps"]
    state = args.backend_state.absolute()
    state.parent.mkdir(parents=True, exist_ok=True)
    script = ROOT / "scripts/remote_acceptance.py"

    def run(name, *arguments):
        return command(output, steps, name, [sys.executable, str(script), name, "--state", str(state), *arguments])

    with state.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not state.exists() and not run("stage", "--host", args.host):
            return False
        if acceptance.read_state(state)["host"] != args.host:
            raise ValueError("后端状态文件与指定 SSH 主机不同")
        if not run("sync"):
            return False
        observed = acceptance.read_state(state)
        result["source_sha256"] = observed["workspace_sha256"]
        result["commit"] = observed["commit"]
        if expected_source is not None and (observed["commit"], observed["workspace_sha256"]) != expected_source:
            raise ValueError("同步期间后端源码发生变化，请重新执行整轮验收")

        ready = args.backend_build != "cached" or run("build-cached")
        location = "loaded" if args.backend_build == "cached" else "remote"
        passed = ready and run("run", "--build-location", location)
        fetched = run("fetch", "--report-output", str(output))
        return passed and fetched


def run_remote_checks(args, output, groups, results, frozen_source=None):
    output.mkdir()
    sync = []
    results["workspace"] = {"steps": sync}
    runtime = None
    identity = None
    fetched = False
    try:
        with tempfile.TemporaryDirectory(prefix="starbeacon-validation-") as scratch:
            archive = pathlib.Path(scratch) / "source.tar"

            def synchronize(log):
                nonlocal runtime, identity
                if frozen_source is None:
                    bundle = archive
                    identity = prepare_source(bundle, frontend="frontend" in groups)
                else:
                    bundle, identity = frozen_source
                runtime = runner_ssh(args.host, ["mktemp", "-d", "/var/tmp/starbeacon-validation-XXXXXXXXXXXX"],
                                     stdout=subprocess.PIPE, stderr=log, timeout=30).stdout.decode().strip()
                if not re.fullmatch(r"/var/tmp/starbeacon-validation-[A-Za-z0-9]{12}", runtime):
                    raise ValueError("远程临时目录格式无效")
                results["workspace"].update(remote_directory=runtime, source_sha256=identity["workspace_sha256"],
                                            commit=identity["commit"], clean_commit=identity["clean_commit"])
                with bundle.open("rb") as source:
                    runner_ssh(args.host, ["tar", "-xf", "-", "-C", runtime], stdin=source, stderr=log, timeout=300)
                runner_ssh(args.host, ["python3", "-c", INITIALIZE, runtime, identity["commit"]],
                           stdout=log, stderr=subprocess.STDOUT, timeout=300)

            if not step(output, sync, "sync", synchronize):
                return False
        for group in groups:
            result = results[group]
            directory = output / group
            directory.mkdir()
            remote_script = runtime + "/source/scripts/remote_validation.py"
            arguments = ["python3", remote_script, "--worker", group, "--toolchain-path", args.toolchain_path]
            if group == "frontend":
                arguments.extend(["--frontend-workers", str(args.frontend_workers)])
            passed = step(directory, result["steps"], "run", lambda log: runner_ssh(
                args.host, arguments,
                stdout=log, stderr=subprocess.STDOUT, timeout=2400,
            ))
            result.update(status="passed" if passed else "failed",
                          duration_seconds=result["steps"][-1]["duration_seconds"])

        def fetch(log):
            report = runner_ssh(args.host, ["tar", "-czf", "-", "-C", runtime, "reports"],
                                stdout=subprocess.PIPE, stderr=log, timeout=300).stdout
            acceptance.store_report_bundle(report, output, identity["workspace_sha256"])

        fetched = step(output, sync, "fetch", fetch)
        return fetched and all(results[group]["status"] == "passed" for group in groups)
    finally:
        if fetched:
            step(output, sync, "cleanup", lambda log: runner_ssh(
                args.host, ["rm", "-rf", "--", runtime], stdout=log, stderr=subprocess.STDOUT, timeout=120,
            ))


def worker(group, toolchain_path, frontend_workers=2):
    staging = ROOT.parent
    evidence = staging / "reports" / group
    evidence.mkdir()
    if toolchain_path:
        os.environ["PATH"] = toolchain_path + os.pathsep + os.environ["PATH"]
    os.environ["GOTOOLCHAIN"] = "local"
    local_frontend = pathlib.Path(".local/acceptance/frontend")
    if group == "frontend":
        verify(ROOT, json.loads((staging / "web-source.json").read_text()))
        checks = [
            ("toolchain", ["sh", "-c", "node --version && pnpm --version"]),
            ("web-install", ["pnpm", "--dir", "web", "install", "--frozen-lockfile"]),
            ("prototype-install", ["pnpm", "--dir", "prototype", "install", "--frozen-lockfile"]),
            ("web-format", ["pnpm", "--dir", "web", "format:check"]),
            ("prototype-format", ["pnpm", "--dir", "prototype", "format:check"]),
            ("frontend", [sys.executable, "scripts/qualify_frontend.py", "--output", str(local_frontend), "--max-workers", str(frontend_workers)]),
            ("prototype-tests", ["node", "--test", "--test-reporter=tap",
                               *(str(p.relative_to(ROOT)) for p in sorted((ROOT / "prototype/scripts").glob("*.test.mjs")))]),
            *((name, ["pnpm", "--dir", "prototype", name]) for name in
              ("check:coverage", "check:workspaces", "check:collector", "check:theme", "build", "check:screenshots")),
        ]
    else:
        os.environ.setdefault("GOCACHE", str(staging / "go-cache"))
        os.environ.setdefault("GOPATH", str(staging / "go"))
        checks = [
            ("toolchain", ["make", "check-toolchain"]),
            ("alignment", [sys.executable, "scripts/check_alignment.py", "--check"]),
            ("quality-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests/quality", "-v"]),
            ("script-tests", [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-v"]),
        ]
    results = []
    passed = False
    try:
        passed = all(command(evidence, results, name.replace(":", "-"), arguments, timeout=1200)
                     for name, arguments in checks)
        for row in results:
            name = row["name"]
            if name in ("quality-tests", "script-tests", "prototype-tests"):
                log = (evidence / row["log"]).read_text(errors="replace")
                if re.search(r"(?m)^# (?:skipped|todo|cancelled) [1-9]\d*$|^OK \(.*(?:skipped|expected failures)=\d+", log):
                    row["status"] = "failed"
                    row["error"] = "有测试被跳过或未执行"
                    passed = False
        return 0 if passed else 1
    finally:
        if group == "frontend" and (ROOT / local_frontend).is_dir():
            shutil.move(ROOT / local_frontend, evidence / "frontend-evidence")
        (evidence / "steps.json").write_text(json.dumps({"status": "passed" if passed else "failed", "steps": results},
                                                        ensure_ascii=False, indent=2) + "\n")


def inspect_remote_docker(args, output, report):
    backend_steps = report["groups"].get("backend", {}).get("steps", [])
    if any(row["name"] == "fetch" and row["status"] == "passed" for row in backend_steps):
        return
    options = []
    try:
        state = acceptance.read_state(args.backend_state)
        if state["host"] == args.host and state["directory"] == acceptance.PERSISTENT_DIRECTORY + "/" + state["project"]:
            options = ["--directory", state["directory"], "--project", state["project"]]
    except (OSError, ValueError):
        pass
    report["cleanup"] = []
    completed = command(output, report["cleanup"], "docker-cleanup", [
        sys.executable, str(ROOT / "scripts/cleanup_acceptance.py"), "docker", "--host", args.host, "--apply", *options,
    ])
    if not completed:
        record = save_report(ROOT, {"status": "unverified", "kind": "docker", "host": args.host,
                                    "reason": "远程 Docker 检查未完成", "log": str(output / "docker-cleanup.log")})
        print(f"远程 Docker 检查待完成：{record}")


def run_selected_groups(args, output, report):
    groups = report["groups"]
    remote_groups = [group for group in groups if group != "backend"]
    frozen_source = None
    expected_backend = None
    passed = True
    with tempfile.TemporaryDirectory(prefix="starbeacon-validation-") as scratch:
        if "backend" in groups and remote_groups:
            archive = pathlib.Path(scratch) / "source.tar"

            def freeze(log):
                nonlocal frozen_source, expected_backend
                before = acceptance.snapshot_sources()[1]
                identity = prepare_source(archive, frontend="frontend" in remote_groups)
                if acceptance.snapshot_sources()[1] != before:
                    raise ValueError("冻结期间后端源码发生变化，请重新执行验收")
                expected_backend = (identity["commit"], before)
                frozen_source = (archive, identity)
                log.write((json.dumps(identity) + "\n").encode())

            report["preparation"] = []
            if not step(output, report["preparation"], "freeze", freeze):
                return False
        if "backend" in groups:
            result = groups["backend"]
            mark = time.monotonic()
            try:
                passed = backend_checks(args, output / "backend", result, expected_backend)
            except ERRORS as error:
                passed = False
                result["error"] = str(error)
                print(f"后端验收失败：{error}", file=sys.stderr)
            result.update(status="passed" if passed else "failed", duration_seconds=round(time.monotonic() - mark, 3))
        if remote_groups:
            passed = run_remote_checks(args, output / "host", remote_groups, groups, frozen_source) and passed
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=(*GROUPS, "all"), default=os.environ.get("SB_CHECK_GROUP", "all"))
    parser.add_argument("--host", default=os.environ.get("SB_CHECK_HOST", "home_dev"))
    parser.add_argument("--toolchain-path", default=os.environ.get("SB_CHECK_TOOLCHAIN_PATH", ""),
                        help="远程主机上已安装的工具链目录，以冒号分隔")
    parser.add_argument("--backend-state", type=pathlib.Path,
                        default=os.environ.get("SB_CHECK_BACKEND_STATE", str(ACCEPTANCE_DIR / "remote.json")))
    parser.add_argument("--backend-build", choices=("remote", "cached"), default=os.environ.get("SB_CHECK_BACKEND_BUILD", "remote"))
    parser.add_argument("--frontend-workers", type=int, choices=range(1, 5), default=os.environ.get("SB_CHECK_FRONTEND_WORKERS", "2"),
                        help="前端执行进程数，默认 2，范围 1–4")
    parser.add_argument("--worker", choices=("frontend", "contract"), help=argparse.SUPPRESS)
    args = parser.parse_args()

    if not 1 <= args.frontend_workers <= 4:
        parser.error("前端执行进程数须为 1–4")
    if args.worker:
        return worker(args.worker, args.toolchain_path, args.frontend_workers)
    if args.group not in (*GROUPS, "all") or args.backend_build not in ("remote", "cached"):
        parser.error("验收组或后端构建方式无效")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.host) or args.host.startswith("-"):
        parser.error("SSH 主机标识无效")
    groups = GROUPS if args.group == "all" else (args.group,)
    ACCEPTANCE_DIR.mkdir(parents=True, exist_ok=True)
    output = pathlib.Path(tempfile.mkdtemp(prefix="remote-check-", dir=ACCEPTANCE_DIR))
    report = {"schema_version": 1, "status": "failed", "host": args.host, "groups": {group: {"status": "not_run", "steps": []} for group in groups},
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    started = time.monotonic()
    try:
        print(f"远程验收报告目录：{output}", flush=True)
        passed = run_selected_groups(args, output, report)
        report["status"] = "passed" if passed else "failed"
    finally:
        report["duration_seconds"] = round(time.monotonic() - started, 3)
        try:
            inspect_remote_docker(args, output, report)
        except ERRORS as error:
            print(f"远程 Docker 检查待完成：{error}", file=sys.stderr)
        (output / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        try:
            state = args.backend_state.absolute()
            keep = [output, state] if state.is_relative_to(ACCEPTANCE_DIR) else [output]
            record, _ = cleanup_local(ROOT, apply=True, keep=keep)
            print(f"验收清理记录：{record}")
        except ERRORS as error:
            print(f"本机验收清理待完成：{error}", file=sys.stderr)
        print(f"验收报告：{output / 'validation.json'}")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ERRORS as error:
        raise SystemExit(f"远程验收未完成：{error}")
