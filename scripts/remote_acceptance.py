#!/usr/bin/env python3
"""在指定 SSH 主机建立独立 Docker 验收项目；不改动宿主软件或既有项目。"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import secrets
import shlex
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATHS = ("go.mod", "go.sum", "cmd", "internal", "migrations", "api/sensor", "tests", "scripts/check_go_coverage.py", "scripts/init_step_ca.py", "deploy/step-ca", "deploy/Dockerfile.acceptance", "deploy/Dockerfile.acceptance.dockerignore", "deploy/security")
STEP_CA_IMAGE = "cr.smallstep.com/smallstep/step-ca:0.30.2@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270"

DEPENDENCY_IMAGES = {
    "postgres": "public.ecr.aws/docker/library/postgres:18.6@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722",
    "redis": "public.ecr.aws/docker/library/redis:8.10.2@sha256:7ef5b5cec96495a04ca7feff88a9492efeab8053fb284d24bdd73344c9245a48",
    "nats": "public.ecr.aws/docker/library/nats:2.15.0@sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c",
    "elasticsearch": "docker.elastic.co/elasticsearch/elasticsearch:9.5.4",
}

def configure_runner(state, definition):
    """镜像架构和隔离策略只作用于当前项目的执行容器。"""
    for name, image in DEPENDENCY_IMAGES.items():
        definition["services"][name]["image"] = image
        definition["services"][name]["platform"] = "linux/amd64"
    runner = definition["services"]["runner"]
    if state.get("step_ca_image"):
        definition["services"]["step-ca"] = step_ca_service(state)
        runner.setdefault("environment",{}).update(SB_TEST_STEP_CA_URL="https://step-ca:9000",SB_TEST_STEP_CA_ROOT="/run/probe-ca/root_ca.crt",SB_TEST_STEP_CA_JWK="/run/probe-ca/provisioner.jwk")
        runner.setdefault("depends_on",{})["step-ca"]={"condition":"service_healthy"}
        mounts=runner.setdefault("volumes",[])
        for name in ("root_ca.crt","provisioner.jwk"):
            mount=state["directory"]+"/pki/platform/"+name+":/run/probe-ca/"+name+":ro"
            if mount not in mounts:mounts.append(mount)
    runner["platform"] = "linux/amd64"
    # 原生隔离器的已退出后代由 PID 1 回收，不让长期观测耗尽容器 PID 配额。
    runner["init"] = True
    runner["security_opt"] = ["no-new-privileges:true", "seccomp=" + state["directory"] + "/bubblewrap-seccomp.json", "apparmor=" + state["project"] + "_runner", "systempaths=unconfined"]
    capture = json.loads(json.dumps(runner))
    capture.pop("build", None)
    if state.get("step_ca_image"):
        for key in ("SB_TEST_STEP_CA_URL","SB_TEST_STEP_CA_ROOT","SB_TEST_STEP_CA_JWK"):
            capture.get("environment",{}).pop(key,None)
        capture["volumes"]=[v for v in capture.get("volumes",[]) if ":/run/probe-ca/" not in v]
    capture["user"] = "0:0"
    # UID 0 的隔离用户命名空间映射要求 SETFCAP；验证子进程使用 --cap-drop ALL。
    capture["cap_add"] = ["NET_RAW", "SETFCAP"]
    capture["entrypoint"] = ["python3", "/source/tests/acceptance/capture.py"]
    capture["environment"]["SB_TEST_CAPTURE_ENDPOINT"] = "http://capture-fixture:8088"
    capture["depends_on"]["capture-fixture"] = {"condition": "service_started"}
    definition["services"]["capture-runner"] = capture
    definition["services"]["capture-fixture"] = {"image": runner["image"], "platform": "linux/amd64", "entrypoint": ["python3", "/source/tests/acceptance/http_fixture.py"], "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "mem_limit": "64m", "cpus": "0.25", "pids_limit": 32, "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=8m"]}

def configure_security(state):
    """加载独立命名的验收策略，拒绝覆盖与本项目无关的宿主策略。"""
    profile = state["project"] + "_runner"
    path = state["directory"] + "/runner.apparmor"
    template = (ROOT / "deploy/security/acceptance.apparmor").read_text()
    data = template.replace("STARBEACON_ACCEPTANCE_PROFILE", profile).encode()
    profiles = ssh(state["host"], ["cat", "/sys/kernel/security/apparmor/profiles"], stdout=subprocess.PIPE, timeout=15).stdout.decode()
    exists = any(line.partition(" ")[0] == profile for line in profiles.splitlines())
    if exists and state.get("apparmor_profile") != profile:
        raise ValueError("同名宿主策略已存在，拒绝覆盖")
    if exists:
        prior = ssh(state["host"], ["cat", path], stdout=subprocess.PIPE, timeout=15).stdout
        # 旧策略必须位于当前私有目录并具有固定的独立策略名。
        if ("profile " + profile + " ").encode() not in prior:
            raise ValueError("已有验收策略身份无法核对")
    ssh(state["host"], ["tee", path], input=data, stdout=subprocess.DEVNULL, timeout=15)
    ssh(state["host"], ["apparmor_parser", "--skip-kernel-load", "--skip-cache", path], timeout=15)
    ssh(state["host"], ["apparmor_parser", "--replace" if exists else "--add", "--skip-cache", path], timeout=15)
    ssh(state["host"], ["tee", state["directory"] + "/bubblewrap-seccomp.json"], input=(ROOT / "deploy/security/bubblewrap-seccomp.json").read_bytes(), stdout=subprocess.DEVNULL, timeout=15)
    state["apparmor_profile"] = profile
    state["apparmor_sha256"] = hashlib.sha256(data).hexdigest()

def verify_native_host(state):
    """镜像平台不能证明宿主架构；模拟运行不授予原生验收资格。"""
    observed = ssh(state["host"], ["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"], stdout=subprocess.PIPE, timeout=15).stdout.decode().strip()
    if observed not in ("linux/x86_64", "linux/amd64"):
        raise ValueError("验收宿主必须为原生 Linux amd64")
    return observed

def verify_architecture(state):
    """拒绝通过模拟运行依赖，避免把模拟器错误当成产品错误。"""
    verify_native_host(state)
    for image in [*DEPENDENCY_IMAGES.values(), image_name(state), *([state["step_ca_image"]] if state.get("step_ca_image") else [])]:
        observed = ssh(state["host"], ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image], stdout=subprocess.PIPE, timeout=15).stdout.decode().strip()
        if observed != "linux/amd64":
            raise ValueError("验收依赖的原生架构不一致")

def snapshot_sources():
    """摘要和归档使用同一份字节快照，避免编辑期间产生证据与镜像不一致。"""
    sources = []
    for name in SOURCE_PATHS:
        source = ROOT / name
        sources.extend([source] if source.is_file() else source.rglob("*"))
    files = {}
    checksum = hashlib.sha256()
    for source in sorted(set(sources)):
        if "__pycache__" in source.parts or source.suffix == ".pyc":
            continue
        if source.is_symlink():
            raise ValueError("验收源代码不能包含符号链接")
        if not source.is_file():
            continue
        name = source.relative_to(ROOT).as_posix()
        data = source.read_bytes()
        files[name] = data
        checksum.update(name.encode() + b"\0" + data + b"\0")
    return files, checksum.hexdigest()

def archive_bytes(archive, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size, info.mode = len(data), mode
    archive.addfile(info, io.BytesIO(data))

def image_name(state):
    return "starbeacon/acceptance:" + state["project"]

def verify_image(state):
    labels = json.loads(ssh(state["host"], ["docker", "image", "inspect", "--format", "{{json .Config.Labels}}", image_name(state)], stdout=subprocess.PIPE).stdout)
    if not isinstance(labels, dict) or labels.get("io.starbeacon.acceptance.source") != state["workspace_sha256"] or labels.get("org.opencontainers.image.revision") != state["commit"]:
        raise ValueError("验收镜像标识与源代码摘要不一致")

def build_local(state):
    files, digest = snapshot_sources()
    if digest != state["workspace_sha256"]:
        raise ValueError("工作区源代码已经改变，请同步验收快照后构建")
    if ssh(state["host"], ["uname", "-m"], stdout=subprocess.PIPE).stdout.strip() != b"x86_64":
        raise ValueError("当前原生引擎验收镜像仅用于 Linux amd64 主机")
    with tempfile.TemporaryDirectory(prefix="starbeacon-image-") as scratch:
        context = pathlib.Path(scratch)
        for name, data in files.items():
            destination = context / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        # 使用上游镜像目录列出的 HTTPS 下载源，包仍由 AlmaLinux 签名校验。
        subprocess.run(["docker", "build", "--platform", "linux/amd64", "--progress", "plain", "--build-arg", "SB_ALMA_REPOSITORY=https://mirror.sjtu.edu.cn/almalinux/9.8", "--build-arg", "SB_GO_PROXY=https://goproxy.cn", "--build-arg", "SB_SOURCE_SHA256=" + digest, "--build-arg", "SB_SOURCE_COMMIT=" + state["commit"], "-f", str(context / "deploy/Dockerfile.acceptance"), "-t", image_name(state), str(context)], check=True, timeout=1800)
    save = subprocess.Popen(["docker", "save", image_name(state)], stdout=subprocess.PIPE)
    compress = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=subprocess.PIPE)
    save.stdout.close()
    try:
        ssh(state["host"], ["docker", "load"], stdin=compress.stdout, timeout=1800)
        compress.stdout.close()
        if compress.wait(timeout=30) != 0 or save.wait(timeout=30) != 0:
            raise ValueError("验收镜像传输没有完整结束")
    finally:
        for process in (compress, save):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=30)
    verify_image(state)

def build_cached(state, download_modules=False):
    """仅复用本项目已核验的运行依赖，源码目录整体替换，模块缺失时拒绝离线构建。"""
    files, checksum = snapshot_sources()
    if checksum != state["workspace_sha256"]:
        raise ValueError("工作区源代码已经改变，请同步验收快照后构建")
    dependency_hash = hashlib.sha256(b"".join(files[name] for name in ("go.mod", "go.sum", "deploy/Dockerfile.acceptance"))).hexdigest()
    dependency_image = "starbeacon/acceptance-dependencies:" + state["project"] + "-" + dependency_hash[:16]
    cached = ssh(state["host"], ["docker", "image", "ls", "--quiet", "--no-trunc", dependency_image], stdout=subprocess.PIPE, timeout=15).stdout.decode().strip()
    metadata = json.loads(ssh(state["host"], ["docker", "image", "inspect", dependency_image if cached else image_name(state)], stdout=subprocess.PIPE, timeout=15).stdout)
    if cached and (len(metadata) != 1 or metadata[0].get("Config", {}).get("Labels", {}).get("io.starbeacon.acceptance.dependencies") != dependency_hash):
        raise ValueError("依赖缓存标签与锁定模块不一致")
    # 固定依赖基座，不把每轮验收源码层串成不断增长的镜像祖先链。
    seen = set()
    while not cached and len(metadata) == 1 and len(metadata[0].get("RootFS", {}).get("Layers", [])) > 64:
        current = metadata[0]
        parent = current.get("Config", {}).get("Labels", {}).get("io.starbeacon.acceptance.base", "")
        if current.get("Architecture") != "amd64" or current.get("Os") != "linux" or not re.fullmatch(r"[a-f0-9]{64}", current.get("Config", {}).get("Labels", {}).get("io.starbeacon.acceptance.source", "")) or not re.fullmatch(r"sha256:[a-f0-9]{64}", parent) or parent in seen:
            raise ValueError("依赖缓存祖先链缺少合法来源或包含循环")
        seen.add(parent)
        if len(seen) > 128:
            raise ValueError("依赖缓存祖先链超出检查上限")
        metadata = json.loads(ssh(state["host"], ["docker", "image", "inspect", parent], stdout=subprocess.PIPE, timeout=15).stdout)
    if len(metadata) != 1 or metadata[0].get("Architecture") != "amd64" or metadata[0].get("Os") != "linux":
        raise ValueError("缓存验收镜像架构无效")
    labels = metadata[0].get("Config", {}).get("Labels", {})
    if not isinstance(labels, dict) or not re.fullmatch(r"[a-f0-9]{64}", labels.get("io.starbeacon.acceptance.source", "")):
        raise ValueError("缓存镜像缺少本项目来源标签")
    original = metadata[0]["Id"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", original):
        raise ValueError("缓存镜像身份无效")
    base = "starbeacon/acceptance-base:" + state["project"] + "-" + original[-16:]
    # 已登记的同一基座无需反复修改 Docker 元数据。
    existing = ssh(state["host"], ["docker", "image", "ls", "--quiet", "--no-trunc", base], stdout=subprocess.PIPE, timeout=30).stdout.decode().strip()
    if existing != original:
        ssh(state["host"], ["docker", "image", "tag", original, base], timeout=60)
    modules = "GOPROXY=https://goproxy.cn GODEBUG=http2client=0 timeout 300 go mod download && " if download_modules else ""
    definition = f'''FROM {base}
USER 0:0
RUN rm -rf /source
WORKDIR /source
COPY . .
RUN {modules}GOPROXY=off go mod verify && SB_BUILD_GO_CACHE=$(mktemp -d /tmp/starbeacon-go-cache-XXXXXXXX) && CGO_ENABLED=0 GOPROXY=off GOCACHE="$SB_BUILD_GO_CACHE" go build -trimpath -cover -covermode=atomic -coverpkg=./cmd/...,./internal/... -o /usr/local/bin/ ./cmd/... && rm -rf -- "$SB_BUILD_GO_CACHE"
USER 65532:65532
LABEL org.opencontainers.image.revision={state["commit"]} io.starbeacon.acceptance.source={checksum} io.starbeacon.acceptance.base={original} io.starbeacon.acceptance.dependencies={dependency_hash}
ENTRYPOINT ["python3", "/source/tests/acceptance/baseline.py"]
'''
    context = state["directory"] + "/source-" + checksum
    ssh(state["host"], ["tee", context + "/Dockerfile.cached"], input=definition.encode(), stdout=subprocess.DEVNULL, timeout=15)
    ssh(state["host"], ["docker", "build", "--builder", "default", "--pull=false", "--network=" + ("default" if download_modules else "none"), "--progress=plain", "-f", context + "/Dockerfile.cached", "-t", image_name(state), context], timeout=600)
    verify_image(state)
    if not cached:
        # 构建中已下载或离线核验全部锁定模块；基座只在成功后登记。
        ssh(state["host"], ["docker", "image", "tag", image_name(state), dependency_image], timeout=15)

def ssh(host, arguments, **options):
    command = shlex.join([str(value) for value in arguments])
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", host, command], check=True, **options)

def read_state(path):
    state = json.loads(path.read_text())
    if not isinstance(state, dict) or any(not isinstance(state.get(key), str) for key in ("host", "project", "directory", "commit", "workspace_sha256")) or not re.fullmatch(r"[A-Za-z0-9_.-]+", state["host"]) or state["host"].startswith("-") or not re.fullmatch(r"sbacc_[a-f0-9]{16}", state["project"]) or state["directory"] != "/tmp/starbeacon-acceptance-" + state["project"] or not re.fullmatch(r"[a-f0-9]{40}", state["commit"]) or not re.fullmatch(r"[a-f0-9]{64}", state["workspace_sha256"]):
        raise ValueError("验收项目标识无效，拒绝操作其他目录或 Compose 项目")
    return state

def compose(state, command, **options):
    return ssh(state["host"], ["docker", "compose", "--env-file", state["directory"] + "/dependencies.env", "-p", state["project"], "-f", state["directory"] + "/compose.json", *command], **options)

def store_report_bundle(data, output, expected_source):
    """完整替换本轮报告，保留旧证据；失败运行不得继承已不存在的成功报告。"""
    if not re.fullmatch(r"[a-f0-9]{64}", expected_source) or len(data) > 256 * 1024 * 1024:
        raise ValueError("报告包身份或大小无效")
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError("报告目标不是本项目的普通目录")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = output / "reports"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError("报告目录不是普通目录")
    with tempfile.TemporaryDirectory(dir=output, prefix=".report-staging-") as temporary:
        staging = pathlib.Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = archive.getmembers()
            total = 0
            paths = set()
            for member in members:
                path = pathlib.PurePosixPath(member.name)
                if path.is_absolute() or not path.parts or path.parts[0] != "reports" or ".." in path.parts or member.name in paths or not (member.isfile() or member.isdir()):
                    raise ValueError("报告成员路径或类型无效")
                paths.add(member.name)
                total += member.size
                if len(paths) > 5000 or total > 1024 * 1024 * 1024:
                    raise ValueError("报告成员超过处理预算")
            archive.extractall(staging, filter="data")
        reports = staging / "reports"
        source = json.loads((reports / "source.json").read_text())
        if source.get("workspace_sha256") != expected_source:
            raise ValueError("回传报告不是当前源码快照")
        for name in ("baseline.json", "backend.json", "capture/capture.json"):
            path = reports / name
            if path.exists() and json.loads(path.read_text()).get("workspace_sha256") != expected_source:
                raise ValueError("回传报告包含其他源码的组合结论")
        prior = output / ("reports-history-" + secrets.token_hex(8))
        existed = target.exists()
        if existed:
            target.replace(prior)
        try:
            reports.replace(target)
        except OSError:
            if existed:
                prior.replace(target)
            raise
    return target

def run_backend(state):
    """功能与网卡测试依次使用同一镜像和专属依赖，拒绝并发更换测试数据。"""
    running = compose(state, ["ps", "--status", "running", "-q", "runner", "capture-runner"], stdout=subprocess.PIPE, timeout=15)
    if running.stdout.strip():
        raise ValueError("验收执行器仍在运行，不能并发重用测试数据")
    # 失败运行不得沿用上一次通过报告。只清除本项目的组合结论，原始证据保留。
    stale = ("backend.json", "go-live-merged.cover", "go-live-coverage.json", "go-capture-cli.cover", "capture/capture.json")
    ssh(state["host"], ["rm", "-f", *(state["directory"] + "/reports/" + name for name in stale)], timeout=15)
    for name, owner in (("go-build-cache", "65532:65532"), ("capture-go-build-cache", "0:0")):
        cache = state["directory"] + "/" + name
        ssh(state["host"], ["mkdir", "-p", "-m", "700", cache], timeout=15)
        ssh(state["host"], ["chown", owner, cache], timeout=15)
    # 编译与测试二进制启动独立准备；不让冷编译争用原生命令的业务期限。
    # 不执行用例、不生成通过报告；实际测试仍以 -count=1 和原期限重新执行。
    compose(state, ["run", "--rm", "--no-deps", "--volume", state["directory"] + "/go-build-cache:/tmp/go-cache", "--entrypoint", "go", "runner", "test", "-race", "-json", "-count=1", "-coverpkg=./cmd/...,./internal/...", "-run=^$", "./cmd/...", "./internal/..."], timeout=600)
    # 观察预算覆盖单元、两组顺序集成及覆盖整理，不改变各业务请求和用例的期限。
    # 两组各保留 1260 秒外层预算，另留编译、单元及退出整理时间。
    compose(state, ["run", "--rm", "--no-deps", "--volume", state["directory"] + "/go-build-cache:/tmp/go-cache", "runner"], timeout=3000)
    try:
        compose(state, ["up", "-d", "--no-build", "capture-fixture"], timeout=60)
        compose(state, ["run", "--rm", "--no-deps", "--volume", state["directory"] + "/capture-go-build-cache:/tmp/go-cache", "--entrypoint", "go", "capture-runner", "test", "-race", "-json", "-count=1", "-tags=integration,captureintegration", "-coverpkg=./cmd/...,./internal/...", "-run=^$", "./tests/integration"], timeout=600)
        compose(state, ["run", "--rm", "--no-deps", "--volume", state["directory"] + "/capture-go-build-cache:/tmp/go-cache", "capture-runner"], timeout=360)
    finally:
        compose(state, ["stop", "capture-fixture"], timeout=30)
        compose(state, ["rm", "-f", "-v", "capture-fixture"], timeout=30)
    compose(state, ["run", "--rm", "--no-deps", "--entrypoint", "python3", "runner", "/source/tests/acceptance/combine_backend.py"], timeout=180)

def step_ca_service(state):
    base=state["directory"]+"/pki/ca"
    return {
        "image":state["step_ca_image"],"platform":"linux/amd64","user":"1000:1000",
        "entrypoint":["/usr/local/bin/step-ca"],"command":["--password-file","/home/step/secrets/password","/home/step/config/ca.json"],
        "read_only":True,"cap_drop":["ALL"],"cap_add":["NET_BIND_SERVICE"],"security_opt":["no-new-privileges:true"],
        "pids_limit":128,"mem_limit":"512m","cpus":"1",
        "tmpfs":["/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777","/home/step:rw,noexec,nosuid,nodev,size=1m,mode=0555"],
        "volumes":[base+"/"+name+":/home/step/"+name+("" if name=="db" else ":ro") for name in ("config","certs","secrets","templates","db")],
        "healthcheck":{"test":["CMD","step","ca","health","--ca-url","https://localhost:9000","--root","/home/step/certs/root_ca.crt"],"interval":"3s","timeout":"3s","retries":30},
    }

def prepare_step_ca(state,image=STEP_CA_IMAGE):
    try:
        ssh(state["host"],["docker","image","inspect",image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    except subprocess.CalledProcessError:
        ssh(state["host"],["docker","pull",image],timeout=180)
    metadata=json.loads(ssh(state["host"],["docker","image","inspect",image],stdout=subprocess.PIPE,timeout=15).stdout)
    if len(metadata)!=1 or metadata[0].get("Os")!="linux" or metadata[0].get("Architecture")!="amd64":
        raise ValueError("探针 CA 验收要求已核验的原生 Linux amd64 镜像")
    version=ssh(state["host"],["docker","run","--rm","--network","none","--cap-drop","ALL","--cap-add","NET_BIND_SERVICE","--security-opt","no-new-privileges:true","--entrypoint","step-ca",metadata[0]["Id"],"--version"],stdout=subprocess.PIPE,timeout=30).stdout.decode()
    if not re.search(r"\b0\.30\.2\b",version):raise ValueError("探针 CA 版本必须为 0.30.2")
    state["step_ca_image"]=metadata[0]["Id"]
    state["step_ca_requested_image"]=image
    state["step_ca_version"]=version.strip()
    ssh(state["host"],["python3",state["directory"]+"/scripts/init_step_ca.py","--directory",state["directory"]+"/pki","--image",state["step_ca_image"],"--uid","1000","--gid","1000","--platform-uid","65532","--platform-gid","65532"],stdout=subprocess.DEVNULL,timeout=210)

def stage(host, path, step_ca_image=STEP_CA_IMAGE):
    if path.exists() or not re.fullmatch(r"[A-Za-z0-9_.-]+", host) or host.startswith("-"):
        raise ValueError("状态文件已经存在或 SSH 主机标识无效")
    project = "sbacc_" + secrets.token_hex(8)
    directory = "/tmp/starbeacon-acceptance-" + project
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    clean = not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(prefix="starbeacon-staging-") as scratch:
        work = pathlib.Path(scratch)
        archive = work / "source.tar.gz"
        files, digest = snapshot_sources()
        with tarfile.open(archive, "w:gz") as output:
            for name, data in files.items():
                archive_bytes(output, name, data)
            report = work / "source.json"
            report.write_text(json.dumps({"commit": commit, "workspace_sha256": digest, "clean_commit": clean, "project": project}, indent=2) + "\n")
            output.add(report, arcname="reports/source.json")
            environment = work / "dependencies.env"
            environment.write_text("\n".join(f"{key}={secrets.token_hex(24)}" for key in ("POSTGRES_PASSWORD", "SB_RUNTIME_DB_PASSWORD", "REDIS_PASSWORD", "NATS_TOKEN")) + "\n")
            environment.chmod(0o600)
            output.add(environment, arcname="dependencies.env")
            nats = work / "nats.conf"
            nats.write_text('port: 4222\nauthorization { token: $NATS_TOKEN }\njetstream { store_dir: /data; max_file_store: 512MB; max_memory_store: 64MB; sync_interval: always }\nmax_payload: 4MB\n')
            output.add(nats, arcname="nats.conf")
            definition = {
                "services": {
                    "postgres": {"image": DEPENDENCY_IMAGES["postgres"], "environment": {"POSTGRES_USER": "starbeacon_owner", "POSTGRES_DB": "starbeacon", "POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}"}, "volumes": ["postgres:/var/lib/postgresql"], "healthcheck": {"test": ["CMD", "pg_isready", "-U", "starbeacon_owner", "-d", "starbeacon"], "interval": "3s", "timeout": "2s", "retries": 60}, "mem_limit": "1g", "cpus": "2"},
                    "redis": {"image": DEPENDENCY_IMAGES["redis"], "environment": {"REDIS_PASSWORD": "${REDIS_PASSWORD}"}, "command": ["sh", "-c", 'exec redis-server --appendonly yes --requirepass "$REDIS_PASSWORD"'], "volumes": ["redis:/data"], "mem_limit": "512m", "cpus": "1"},
                    "nats": {"image": DEPENDENCY_IMAGES["nats"], "environment": {"NATS_TOKEN": "${NATS_TOKEN}"}, "command": ["-c", "/config/nats.conf"], "volumes": ["./nats.conf:/config/nats.conf:ro", "nats:/data"], "mem_limit": "512m", "cpus": "1"},
                    "elasticsearch": {"image": DEPENDENCY_IMAGES["elasticsearch"], "environment": {"discovery.type": "single-node", "xpack.security.enabled": "false", "ES_JAVA_OPTS": "-Xms512m -Xmx512m"}, "volumes": ["elasticsearch:/usr/share/elasticsearch/data"], "healthcheck": {"test": ["CMD-SHELL", "curl --fail --silent 'http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=2s' >/dev/null"], "interval": "5s", "timeout": "4s", "retries": 60}, "mem_limit": "2g", "cpus": "2"},
                    "runner": {"image": "starbeacon/acceptance:" + project, "build": {"context": ".", "dockerfile": "deploy/Dockerfile.acceptance"}, "environment": {**{key: "${" + key + "}" for key in ("POSTGRES_PASSWORD", "SB_RUNTIME_DB_PASSWORD", "REDIS_PASSWORD", "NATS_TOKEN")}, "SB_ACCEPTANCE_PROJECT": project}, "volumes": ["./reports:/reports"], "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "tmpfs": ["/tmp:rw,exec,nosuid,nodev,size=4g,mode=1777"], "mem_limit": "6g", "cpus": "4", "pids_limit": 1024, "depends_on": {"postgres": {"condition": "service_healthy"}, "elasticsearch": {"condition": "service_healthy"}, "redis": {"condition": "service_started"}, "nats": {"condition": "service_started"}}}
                },
                "networks": {"default": {"internal": True}},
                "volumes": {name: {} for name in ("postgres", "redis", "nats", "elasticsearch")}
            }
            definition_path = work / "compose.json"
            definition_path.write_text(json.dumps(definition, indent=2) + "\n")
            output.add(definition_path, arcname="compose.json")
        ssh(host, ["mkdir", "-m", "700", directory])
        with archive.open("rb") as file:
            ssh(host, ["tar", "-xzf", "-", "--no-same-owner", "-C", directory], stdin=file)
        ssh(host, ["chmod", "777", directory + "/reports"])
    state = {"schema_version": 1, "host": host, "project": project, "directory": directory, "commit": commit, "workspace_sha256": digest, "clean_commit": clean}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as file:
        json.dump(state, file, indent=2)
        file.write("\n")
    path.chmod(0o600)
    configure_security(state)
    prepare_step_ca(state,step_ca_image)
    configure_runner(state, definition)
    ssh(host, ["tee", directory + "/compose.json"], input=(json.dumps(definition, indent=2) + "\n").encode(), stdout=subprocess.DEVNULL, timeout=15)
    path.write_text(json.dumps(state, indent=2) + "\n")
    print(json.dumps(state, ensure_ascii=False, indent=2))

def sync(path):
    state = read_state(path)
    definition = json.loads(ssh(state["host"], ["cat", state["directory"] + "/compose.json"], stdout=subprocess.PIPE).stdout)
    runners = [name for name in ("runner", "capture-runner") if name in definition["services"]]
    result = compose(state, ["ps", "--status", "running", "-q", *runners], stdout=subprocess.PIPE)
    if result.stdout.strip():
        raise ValueError("验收执行器仍在运行，不能更换其源代码")
    files, digest = snapshot_sources()
    state.update(workspace_sha256=digest, commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), clean_commit=not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    context = "source-" + digest
    if definition["services"]["runner"]["image"] != "starbeacon/acceptance:" + state["project"]:
        raise ValueError("远程执行器镜像不属于当前验收项目")
    definition["services"]["runner"]["build"]["context"] = "./" + context
    configure_security(state)
    configure_runner(state, definition)
    with tempfile.TemporaryDirectory(prefix="starbeacon-staging-") as scratch:
        work = pathlib.Path(scratch)
        archive = work / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, data in files.items():
                archive_bytes(output, context + "/" + name, data)
            for name, contents in (("compose.json", definition), ("reports/source.json", state)):
                metadata = work / pathlib.Path(name).name
                metadata.write_text(json.dumps(contents, indent=2) + "\n")
                output.add(metadata, arcname=name)
        with archive.open("rb") as file:
            ssh(state["host"], ["tar", "-xzf", "-", "--no-same-owner", "-C", state["directory"]], stdin=file)
    path.write_text(json.dumps(state, indent=2) + "\n")
    print(json.dumps({"project": state["project"], "workspace_sha256": state["workspace_sha256"], "clean_commit": state["clean_commit"]}, indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stage", "sync", "build-local", "build-cached", "run", "fetch", "status"))
    parser.add_argument("--build-location", choices=("remote", "local", "loaded"), default="remote")
    parser.add_argument("--host", default="home_dev")
    parser.add_argument("--download-modules", action="store_true", help="缓存构建时下载锁定模块，并验证 Go 模块摘要")
    parser.add_argument("--step-ca-image",default=STEP_CA_IMAGE,help="独立 CA 镜像；验收可指定已校验上游发行文件构建的预载镜像，并记录实际镜像身份")
    parser.add_argument("--state", type=pathlib.Path, default=ROOT / ".local/acceptance/remote.json")
    args = parser.parse_args()
    if args.action == "stage":
        stage(args.host, args.state,args.step_ca_image)
        return
    if args.action == "sync":
        sync(args.state)
        return
    state = read_state(args.state)
    if args.action == "build-local":
        build_local(state)
    elif args.action == "build-cached":
        build_cached(state,args.download_modules)
    elif args.action == "run":
        definition = json.loads(ssh(state["host"], ["cat", state["directory"] + "/compose.json"], stdout=subprocess.PIPE).stdout)
        context = definition["services"]["runner"]["build"]["context"]
        if context != "." and context != "./source-" + state["workspace_sha256"]:
            raise ValueError("构建上下文与源码摘要不一致")
        source = state["directory"] + ("" if context == "." else "/" + context.removeprefix("./"))
        if args.build_location == "local":
            build_local(state)
        elif args.build_location == "remote":
            ssh(state["host"], ["docker", "build", "--builder", "default", "--progress", "plain", "--build-arg", "SB_SOURCE_SHA256=" + state["workspace_sha256"], "--build-arg", "SB_SOURCE_COMMIT=" + state["commit"], "-f", source + "/deploy/Dockerfile.acceptance", "-t", image_name(state), source], timeout=1800)
        verify_image(state)
        compose(state, ["up", "-d", "--wait", "--wait-timeout", "300", "postgres", "redis", "nats", "elasticsearch", *(["step-ca"] if state.get("step_ca_image") else [])])
        verify_architecture(state)
        run_backend(state)
    elif args.action == "status":
        compose(state, ["ps", "--all", "--format", "json"])
    else:
        output = args.state.parent / state["project"]
        result = ssh(state["host"], ["tar", "-czf", "-", "-C", state["directory"], "reports"], stdout=subprocess.PIPE)
        reports = store_report_bundle(result.stdout, output, state["workspace_sha256"])
        print(f"验收报告：{reports}")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(f"远程验收未完成：{type(error).__name__}；项目状态保留在本地状态文件中。")
