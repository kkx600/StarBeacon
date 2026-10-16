#!/usr/bin/env python3
"""在专属 Docker 命名空间对照验证隔离器进程回收；保留失败对照和原始证据。"""
import argparse
import hashlib
import json
import pathlib
import secrets
import subprocess
import sys

import remote_acceptance as remote

TESTS = {
    "TestNativeSandboxRepeatedExitDoesNotExhaustProcesses",
    "TestNativeSandboxCancellationReapsNamespaceChildren",
}
SELECTOR = "^TestNativeSandbox(RepeatedExitDoesNotExhaustProcesses|CancellationReapsNamespaceChildren)$"


def test_results(raw):
    """仅采纳 Go 结构化事件；包通过或其他测试不能替代指定用例。"""
    results = {}
    for line in raw.decode(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        name = event.get("Test") if isinstance(event, dict) else None
        if name in TESTS and event.get("Action") in {"pass", "fail", "skip"}:
            if name in results:
                raise ValueError("指定用例出现重复结束事件")
            results[name] = event["Action"]
    return results


def service_definition(state, image_id, cache, binaries, init, pids_limit=96):
    """对照只改变 init；权限、命名空间和进程预算保持一致。"""
    return {
        "image": image_id,
        "platform": "linux/amd64",
        "init": init,
        "user": "65532:65532",
        "network_mode": "none",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": [
            "no-new-privileges:true",
            "seccomp=" + state["directory"] + "/bubblewrap-seccomp.json",
            "apparmor=" + state["project"] + "_runner",
            "systempaths=unconfined",
        ],
        "pids_limit": pids_limit,
        "mem_limit": "4g",
        "cpus": "2",
        "tmpfs": ["/tmp:rw,exec,nosuid,nodev,size=2g,mode=1777"],
        "volumes": [cache + ":/tmp/go-cache", binaries + ":/tmp/lifecycle-bin:ro"],
        "working_dir": "/source",
        "environment": {
            "GOCACHE": "/tmp/go-cache",
            "GOPROXY": "off",
            "GOTOOLCHAIN": "local",
            "GOMAXPROCS": "2",
            "SB_TEST_SURICATA_BINARY": "/usr/bin/suricata",
            "SB_TEST_SURICATA_CONFIG": "/etc/suricata/suricata.yaml",
        },
        # 与工程运行器一样由 Python 管理直接子进程，Docker init 回收被接管的后代。
        "entrypoint": ["python3", "-c", "import subprocess,sys;sys.exit(subprocess.call(sys.argv[1:]))"],
        "command": ["/tmp/lifecycle-bin/test2json", "-t", "-p", "github.com/kkx600/StarBeacon/internal/agent", "/tmp/lifecycle-bin/agent.test", "-test.v=test2json", "-test.count=1", "-test.timeout=120s", "-test.run=" + SELECTOR],
    }


def inspect(state, name):
    return json.loads(remote.ssh(state["host"], ["docker", "inspect", "--format", "{{json .}}", name], stdout=subprocess.PIPE, timeout=30).stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    state = remote.read_state(arguments.state)
    if remote.snapshot_sources()[1] != state["workspace_sha256"]:
        raise ValueError("本机源码与验收镜像快照不一致")
    native_host = remote.verify_native_host(state)
    remote.verify_image(state)
    image = json.loads(remote.ssh(state["host"], ["docker", "image", "inspect", "--format", "{{json .}}", remote.image_name(state)], stdout=subprocess.PIPE, timeout=30).stdout)
    if image["Os"] != "linux" or image["Architecture"] != "amd64":
        raise ValueError("验证要求原生 Linux amd64 镜像")
    arguments.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_id = secrets.token_hex(6)
    suffix = state["workspace_sha256"][:12] + "-" + run_id
    cache = state["directory"] + "/lifecycle-go-build-cache"
    binaries = state["directory"] + "/lifecycle-bin-" + suffix
    definition_path = state["directory"] + "/lifecycle-" + suffix + ".json"
    # 缓存只复用编译产物；-count=1 与独立日志保证每次重新执行实际用例。
    prepare_cache = """import os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1])
try:
 p.mkdir(mode=0o700);os.chown(p,65532,65532)
except FileExistsError:
 s=p.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=65532 or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('专属编译缓存身份不一致')
"""
    remote.ssh(state["host"], ["python3", "-c", prepare_cache, cache], timeout=30)
    remote.ssh(state["host"], ["mkdir", "-m", "700", binaries], timeout=30)
    remote.ssh(state["host"], ["chown", "65532:65532", binaries], timeout=30)
    warm = service_definition(state, image["Id"], cache, binaries, True, 256)
    warm["volumes"][-1] = binaries + ":/tmp/lifecycle-bin"
    # Go 可按需构建 test2json；准备阶段固定实际工具和测试 ELF，受限阶段不调用编译器。
    warm["command"] = ["python3", "-c", """import pathlib,shutil,subprocess
root=pathlib.Path('/tmp/lifecycle-bin')
subprocess.run(['go','test','-c','-race','-o',str(root/'agent.test'),'./internal/agent'],check=True)
tool=pathlib.Path(subprocess.check_output(['go','tool','-n','test2json'],text=True).strip())
if not tool.is_absolute() or not tool.is_file():raise ValueError('Go test2json 工具未生成')
shutil.copyfile(tool,root/'test2json');(root/'test2json').chmod(0o755)
"""]
    definitions = {"warm": warm, "control": service_definition(state, image["Id"], cache, binaries, False), "fixed": service_definition(state, image["Id"], cache, binaries, True)}
    encoded = (json.dumps({"services": definitions}, indent=2) + "\n").encode()
    remote.ssh(state["host"], ["tee", definition_path], input=encoded, stdout=subprocess.DEVNULL, timeout=30)
    (arguments.output / "services.json").write_bytes(encoded)
    records, artifact = [], None
    inventory = """import hashlib,json,pathlib,stat,sys
r=pathlib.Path(sys.argv[1]);out={}
for name in ['agent.test','test2json']:
 p=r/name;s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or not s.st_mode&0o111:raise ValueError('编译制品不是可执行普通文件')
 out[name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':s.st_size}
print(json.dumps(out))
"""
    for phase in ("warm", "control", "fixed"):
        name = state["project"] + "-lifecycle-" + suffix + "-" + phase
        observed_exit = None
        observation_timeout = False
        with (arguments.output / (phase + ".jsonl")).open("xb") as log:
            try:
                result = remote.ssh(state["host"], ["docker", "compose", "-p", state["project"], "-f", definition_path, "run", "--no-deps", "--name", name, phase], stdout=log, stderr=subprocess.STDOUT, timeout=600 if phase == "warm" else 180)
                observed_exit = result.returncode
            except subprocess.CalledProcessError as error:
                observed_exit = error.returncode
            except subprocess.TimeoutExpired:
                observation_timeout = True
        actual = inspect(state, name)
        raw = (arguments.output / (phase + ".jsonl")).read_bytes()
        tests = test_results(raw)
        runtime = actual["State"]
        definition = definitions[phase]
        mount = next((m for m in actual["Mounts"] if m["Destination"] == "/tmp/lifecycle-bin"), {})
        consistent = (
            not runtime["Running"] and not runtime["OOMKilled"]
            and actual["Image"] == image["Id"]
            and actual["HostConfig"].get("Init") is definition["init"]
            and actual["HostConfig"]["PidsLimit"] == definition["pids_limit"]
            and actual["HostConfig"]["NetworkMode"] == "none"
            and actual["HostConfig"]["ReadonlyRootfs"]
            and not actual["HostConfig"]["Privileged"]
            and not actual["HostConfig"].get("PidMode")
            and actual["HostConfig"].get("CapDrop") == ["ALL"]
            and actual["Config"]["User"] == "65532:65532"
            and actual["Config"]["Cmd"] == definition["command"]
            and actual["Config"]["Entrypoint"] == definition["entrypoint"]
            and mount.get("Source") == binaries and mount.get("RW") is (phase == "warm")
        )
        if phase == "control":
            # 失败必须来自实际隔离执行与 PID 耗尽／未回收，而不是编译或依赖缺失。
            expected = any(tests.get(name) == "fail" for name in TESTS) and any(marker in raw for marker in [b"Resource temporarily unavailable", b"resource temporarily unavailable", "未回收子进程".encode()])
            qualified = consistent and observed_exit not in (None, 0) and runtime["ExitCode"] != 0 and expected
        else:
            qualified = consistent and observed_exit == 0 and runtime["ExitCode"] == 0 and (phase == "warm" or tests == {name: "pass" for name in TESTS})
        record = {"phase": phase, "qualified": bool(qualified), "container": name, "container_id": actual["Id"], "image_id": actual["Image"], "observed_exit_code": observed_exit, "actual_exit_code": runtime["ExitCode"], "observation_timed_out": observation_timeout, "oom_killed": runtime["OOMKilled"], "running": runtime["Running"], "init": actual["HostConfig"].get("Init"), "pids_limit": actual["HostConfig"]["PidsLimit"], "tests": tests, "log_sha256": hashlib.sha256(raw).hexdigest()}
        records.append(record)
        (arguments.output / (phase + ".json")).write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(record, ensure_ascii=False), flush=True)
        if not qualified:
            raise ValueError("进程生命周期对照阶段未满足条件，原始容器与日志已保留")
        current = json.loads(remote.ssh(state["host"], ["python3", "-c", inventory, binaries], stdout=subprocess.PIPE, timeout=30).stdout)
        if artifact is not None and current != artifact:
            raise ValueError("对照执行期间测试或 JSON 工具制品发生变化")
        artifact = current
        (arguments.output / "binaries.json").write_text(json.dumps(artifact, indent=2) + "\n")
    report = {"schema_version": 1, "status": "passed", "scope": "native_sandbox_process_reaping_not_complete_product_acceptance", "workspace_sha256": state["workspace_sha256"], "commit": state["commit"], "image_id": image["Id"], "native_host": native_host, "run_id": run_id, "definition_path": definition_path, "binary_directory": binaries, "binaries": artifact, "services_sha256": hashlib.sha256(encoded).hexdigest(), "phases": records}
    (arguments.output / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("进程回收验证未通过：" + str(error).splitlines()[0][:256], file=sys.stderr)
        raise SystemExit(1)
