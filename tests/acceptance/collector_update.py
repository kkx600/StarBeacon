#!/usr/bin/env python3
"""在专属 Docker 容器验证采集器签名升级；仅在原生 Linux root 验收主机执行。"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import time
import zipfile


def sha(path):
    with pathlib.Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--build-cache", type=pathlib.Path, help="专属 root 编译缓存；不复用业务测试结果")
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r"sha256:[a-f0-9]{64}", args.image) or not re.fullmatch(r"[a-f0-9]{64}", args.source) or not re.fullmatch(r"[a-f0-9]{40}", args.commit):
        raise ValueError("原生维护验收身份无效")
    identity = "sbupd_" + secrets.token_hex(8)
    base = pathlib.Path("/tmp/starbeacon-collector-update-" + identity)
    base.mkdir(mode=0o755)
    os.chmod(base, 0o755)
    logs = base / "reports"
    logs.mkdir(mode=0o700)
    root, data, config = (base / name for name in ("program", "data", "config"))
    for path in (data, config, base / "build", base / "cache"):
        path.mkdir(mode=0o755)
    build_cache = args.build_cache or base / "cache"
    if not build_cache.is_absolute() or build_cache.resolve(strict=True) != build_cache or not build_cache.is_dir() or build_cache.stat().st_uid != 0 or build_cache.stat().st_mode & 0o022:
        raise ValueError("编译缓存必须为 root 专属的实际绝对目录")
    data.chmod(0o700)
    os.chown(data, 65532, 65532)
    container = "starbeacon-collector-" + identity
    result = {"schema_version": 1, "scope": "collector_signed_agent_update_docker_offline_wal", "status": "running", "workspace_sha256": args.source, "commit": args.commit, "clean_commit": False, "image_id": args.image, "instance": identity, "directory": str(base), "results": [], "boundaries": ["主机 systemd 服务仅核对生成内容，未执行宿主机安装", "既有 WAL 由实际 EVE 读取器与固定试验路由构造；不授予真实平台注册、路由或持久 ACK 资格", "Agent 程序切换会中断捕获；不升级系统镜像、检测引擎或数据格式", "验收程序为同源码原生 ELF，未授予当前 Linux UPX ZIP 或正式 Release 资格"]}

    def save():
        path = logs / "result.json"
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        path.chmod(0o600)

    def run(name, command, expected=0, timeout=180):
        started = time.monotonic()
        completed = subprocess.run([str(item) for item in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        for stream, raw in (("stdout", completed.stdout), ("stderr", completed.stderr)):
            with (logs / (name + "." + stream)).open("xb") as file:
                file.write(raw)
        row = {"name": name, "exit_code": completed.returncode, "expected_exit_code": expected, "seconds": round(time.monotonic() - started, 3), "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest()}
        result["results"].append(row)
        save()
        if completed.returncode != expected:
            raise ValueError(name + " 的真实退出状态不符合预期；保留原始输出")
        return completed.stdout

    def inspect():
        return json.loads(subprocess.check_output(["docker", "inspect", container]))[0]

    try:
        system = subprocess.check_output(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"], text=True).strip()
        metadata = json.loads(subprocess.check_output(["docker", "image", "inspect", args.image]))[0]
        if system not in ("linux/x86_64", "linux/amd64") or metadata["Architecture"] != "amd64" or metadata["Os"] != "linux" or metadata["Config"]["Labels"].get("io.starbeacon.acceptance.source") != args.source:
            raise ValueError("镜像或宿主与源码及原生架构不匹配")
        result["host_platform"] = system
        # 所有构建挂载仅属于本次私有目录；不向在线服务或测试采集器挂载 Docker socket。
        for version in (1, 2):
            label = f"v0.1.0-maint.{version}"
            run(f"build-{version}", ["docker", "run", "--rm", "--init", "--read-only", "--user", "0:0", "--network", "none", "--cap-drop=ALL", "--pids-limit=512", "--memory=6g", "--cpus=4", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=1g", "--mount", f"type=bind,src={base / 'build'},dst=/out", "--mount", f"type=bind,src={build_cache},dst=/cache", "--env", "GOCACHE=/cache", "--env", "GOPROXY=off", "--env", "CGO_ENABLED=0", "--entrypoint", "/usr/local/go/bin/go", args.image, "build", "-trimpath", "-ldflags", f"-s -w -X github.com/kkx600/StarBeacon/internal/buildinfo.Version={label} -X github.com/kkx600/StarBeacon/internal/buildinfo.Commit={args.commit}", "-o", f"/out/agent-{version}", "./cmd/starbeacon-agent"], timeout=600)
        run("build-wal-fixture", ["docker", "run", "--rm", "--init", "--read-only", "--user", "0:0", "--network", "none", "--cap-drop=ALL", "--pids-limit=512", "--memory=4g", "--cpus=4", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=1g", "--mount", f"type=bind,src={base / 'build'},dst=/out", "--mount", f"type=bind,src={build_cache},dst=/cache", "--env", "GOCACHE=/cache", "--env", "GOPROXY=off", "--env", "CGO_ENABLED=0", "--entrypoint", "/usr/local/go/bin/go", args.image, "build", "-trimpath", "-o", "/out/wal-fixture", "./tests/acceptance/fixtures/collector_wal"], timeout=600)
        agent = base / "build/agent-1"
        agent.chmod(0o755)
        run("release-keys", [agent, "maintenance", "keys", "--key-dir", base / "release-keys"])
        run("fixture-pki", ["docker", "run", "--rm", "--init", "--read-only", "--user", "0:0", "--network", "none", "--cap-drop=ALL", "--mount", f"type=bind,src={config},dst=/fixture", "--entrypoint", "/usr/local/bin/starbeaconctl", args.image, "dev-pki", "--dir", "/fixture/pki"])
        for source, target in (("ca.crt", "ca.crt"), ("server.crt", "agent.crt"), ("server.key", "agent.key")):
            shutil.copyfile(config / "pki" / source, config / target)
            os.chown(config / target, 65532, 65532)
            (config / target).chmod(0o600)
        run("command-keys", ["docker", "run", "--rm", "--init", "--read-only", "--user", "0:0", "--network", "none", "--cap-drop=ALL", "--mount", f"type=bind,src={config},dst=/fixture", "--entrypoint", "/usr/local/bin/starbeaconctl", args.image, "command-keys", "--dir", "/fixture/trust"])
        shutil.copyfile(config / "trust/command.pub", config / "command.pub")
        (config / "command.pub").chmod(0o644)
        password = secrets.token_hex(24)
        (config / "password").write_text(password)
        (config / "password").chmod(0o600)
        os.chown(config / "password", 65532, 65532)
        event = {"timestamp": "2026-10-16T00:00:00.000000+0000", "event_type": "alert", "flow_id": 1001, "src_ip": "198.51.100.1", "dest_ip": "192.0.2.10", "src_port": 50321, "dest_port": 80, "proto": "TCP", "alert": {"signature_id": 1000001, "signature": "StarBeacon 维护验证", "severity": 2, "category": "维护验证"}}
        (data / "eve.json").write_text(json.dumps(event) + "\n")
        os.chown(data / "eve.json", 65532, 65532)
        def wal_inspect(name, mode):
            return json.loads(run(name, ["docker", "run", "--rm", "--init", "--read-only", "--network", "none", "--cap-drop=ALL", "--user", "65532:65532", "--mount", f"type=bind,src={data},dst={data}", "--mount", f"type=bind,src={base / 'build/wal-fixture'},dst=/wal-fixture,readonly", "--entrypoint", "/wal-fixture", args.image, "-mode", mode, "-directory", data]))
        original_wal = wal_inspect("seed-existing-wal", "seed")
        if original_wal["pending"] != 1:
            raise ValueError("既有 WAL 试验材料没有包含单条事件")
        values = {"SB_MODE": "production", "SB_STATE_PATH": str(data / "agent.db"), "SB_EVE_PATH": str(data / "eve.json"), "SB_REPLAY_DIR": str(data / "samples"), "SB_REPLAY_BYTES": "104857600", "SB_HTTP_ADDR": "127.0.0.1:28081", "SB_ALLOWED_ORIGIN": "https://127.0.0.1:28081", "SB_LOCAL_PASSWORD_FILE": str(config / "password"), "SB_TLS_CA": str(config / "ca.crt"), "SB_TLS_CERT": str(config / "agent.crt"), "SB_TLS_KEY": str(config / "agent.key"), "SB_COMMAND_PUBLIC_KEY": str(config / "command.pub"), "SB_TENANT_ID": "tenant_update", "SB_SENSOR_ID": "sensor_update", "SB_REGISTRATION_ID": "registration_update", "SB_PLATFORM_ADDR": "127.0.0.1:29999", "SB_INGEST_ADDR": "127.0.0.1:29998", "SB_CAPTURE_MANAGED": "false", "SB_PACKET_CAPTURE": "false"}
        (config / "agent.env").write_text("\n".join(key + "=" + value for key, value in values.items()) + "\n")
        (config / "agent.env").chmod(0o600)
        deployment = {"schema_version": 1, "instance": identity, "mode": "docker", "root": str(root), "data_dir": str(data), "config_dir": str(config), "public_key": str(base / "release-keys/release.pub"), "uid": 65532, "gid": 65532, "ready_url": "https://127.0.0.1:28081/readyz", "ready_ca": str(config / "ca.crt"), "docker_image": args.image, "docker_network": "none", "retention_days": 180}
        deployment_path = base / "deployment.json"
        deployment_path.write_text(json.dumps(deployment))
        deployment_path.chmod(0o600)
        credentials_digest = {p.name: sha(p) for p in config.iterdir() if p.is_file()}

        def bundle(number, binary):
            version = f"v0.1.0-maint.{number}"
            archive = base / f"collector-{number}.zip"
            manifest = {"schema_version": 1, "version": version, "commit": args.commit, "os": "linux", "arch": "amd64", "binaries": {"starbeacon-agent": {"sha256": sha(binary), "size": binary.stat().st_size}}}
            with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as zip:
                zip.write(binary, "starbeacon-collector/bin/starbeacon-agent")
                zip.writestr("starbeacon-collector/manifest.json", json.dumps(manifest))
                zip.writestr("starbeacon-collector/www/index.html", "<html>StarBeacon</html>")
            proof = run(f"sign-{number}", [agent, "maintenance", "sign", "--archive", archive, "--key", base / "release-keys/release.key", "--generation", str(number), "--version", version, "--commit", args.commit])
            proof_path = base / f"proof-{number}.json"
            proof_path.write_bytes(proof)
            return archive, proof_path

        def apply(number, revision, expected=0):
            archive, proof = bundles[number]
            raw = run(f"apply-{number}", [agent, "maintenance", "apply", "--config", deployment_path, "--archive", archive, "--proof", proof, "--request-id", "update_" + str(number), "--expected-revision", str(revision)], expected=expected, timeout=240)
            return json.loads(raw)

        def health(name):
            code = "import json,ssl,urllib.request,pathlib; origin='https://127.0.0.1:28081'; ctx=ssl.create_default_context(cafile=" + repr(str(config / "ca.crt")) + "); ctx.minimum_version=ssl.TLSVersion.TLSv1_3; password=pathlib.Path(" + repr(str(config / "password")) + ").read_text(); body=json.dumps({'username':'admin','password':password}).encode(); req=urllib.request.Request(origin+'/api/local/v1/auth/login',data=body,headers={'Origin':origin,'Content-Type':'application/json'}); res=urllib.request.urlopen(req,context=ctx); cookie=res.headers['Set-Cookie'].split(';')[0]; req=urllib.request.Request(origin+'/api/local/v1/health',headers={'Cookie':cookie}); print(urllib.request.urlopen(req,context=ctx).read().decode())"
            return json.loads(run(name, ["docker", "exec", "--user", "65532:65532", container, "/usr/bin/python3", "-c", code]))

        bundles = {n: bundle(n, base / f"build/agent-{n}" if n in (1, 2) else base / "build/wal-fixture") for n in range(1, 5)}
        first = apply(1, 0)
        time.sleep(1)
        first_health = health("health-install")
        inode = (data / "agent.db").stat().st_ino
        if first["operation"]["phase"] != "committed" or first_health["wal_pending"] != 1:
            raise ValueError("实际采集器没有启动并保存离线事件")
        second = apply(2, 1)
        second_health = health("health-update")
        second_id = inspect()["Id"]
        duplicate = run("apply-2-confirm", [agent, "maintenance", "apply", "--config", deployment_path, "--archive", bundles[2][0], "--proof", bundles[2][1], "--request-id", "update_2", "--expected-revision", "1"])
        if json.loads(duplicate)["revision"] != 2 or inspect()["Id"] != second_id:
            raise ValueError("原请求确认重复替换了运行实例")
        cleanup_command = [agent, "maintenance", "cleanup", "--config", deployment_path]
        snapshot = (root / "state.json").read_bytes()
        preview = json.loads(run("cleanup-active-preview", cleanup_command))
        active = json.loads(run("cleanup-active-execute", [*cleanup_command, "--execute"]))
        if preview["executed"] or active["releases_removed"] or active["receipts_removed"] or len(active["protected_releases"]) != 2 or inspect()["Id"] != second_id or (root / "state.json").read_bytes() != snapshot:
            raise ValueError("维护回收影响了有效版本、冻结记录或运行实例")
        environment = (config / "agent.env").read_bytes()
        (config / "agent.env").write_bytes(environment + b"# changed outside maintenance\n")
        try:
            run("configuration-drift", [agent, "maintenance", "apply", "--config", deployment_path, "--archive", bundles[3][0], "--proof", bundles[3][1], "--request-id", "configuration_drift", "--expected-revision", "2"], expected=1)
            if inspect()["Id"] != second_id:
                raise ValueError("配置漂移中断了原服务")
        finally:
            (config / "agent.env").write_bytes(environment)
        invalid = json.loads(bundles[3][1].read_text())
        invalid["signature"] = "AA=="
        invalid_path = base / "invalid-proof.json"
        invalid_path.write_text(json.dumps(invalid))
        run("invalid-signature", [agent, "maintenance", "apply", "--config", deployment_path, "--archive", bundles[3][0], "--proof", invalid_path, "--request-id", "invalid_signature", "--expected-revision", "2"], expected=1)
        if inspect()["Id"] != second_id:
            raise ValueError("无效签名中断了原服务")
        restored = apply(3, 2, expected=1)
        if restored["operation"]["phase"] != "restored" or restored["current"]["proof"]["generation"] != 2:
            raise ValueError("失败版本没有恢复前版本")
        health("health-restored")
        command = [str(agent), "maintenance", "apply", "--config", str(deployment_path), "--archive", str(bundles[4][0]), "--proof", str(bundles[4][1]), "--request-id", "update_4", "--expected-revision", "3"]
        with (logs / "interrupt.stdout").open("xb") as stdout, (logs / "interrupt.stderr").open("xb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    state = json.loads((root / "state.json").read_text())
                    if state["operation"]["id"] == "update_4" and state["operation"]["phase"] == "starting" and subprocess.check_output(["docker", "container", "ls", "--all", "--filter", "name=^/" + container + "$", "--format", "{{.ID}}"]).strip():
                        break
                    if process.poll() is not None:
                        raise ValueError("未抵达中断验证阶段")
                    time.sleep(0.1)
                else:
                    raise ValueError("等待中断阶段超时")
                process.kill()
                process.wait(timeout=10)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        result["interrupt_exit_code"] = process.returncode
        raw = run("boot-refuses-interruption", [agent, "maintenance-boot", "--root", root], expected=1)
        interrupted_state = (root / "state.json").read_bytes()
        run("cleanup-refuses-interruption", [*cleanup_command, "--execute"], expected=1)
        if (root / "state.json").read_bytes() != interrupted_state:
            raise ValueError("回收改写了未知维护的恢复依据")
        recovered = json.loads(run("recover", [agent, "maintenance", "recover", "--config", deployment_path], timeout=180))
        if recovered["operation"]["phase"] != "restored" or recovered["current"]["proof"]["generation"] != 2:
            raise ValueError("中断恢复没有核验前版本")
        rolled = json.loads(run("rollback", [agent, "maintenance", "rollback", "--config", deployment_path, "--request-id", "rollback_1", "--expected-revision", "4"], timeout=180))
        final_health = health("health-rollback")
        if rolled["current"]["proof"]["generation"] != 1 or rolled["max_generation"] != 4 or final_health["version"] != "v0.1.0-maint.1" or second_health["version"] != "v0.1.0-maint.2" or final_health["wal_pending"] != 1 or (data / "agent.db").stat().st_ino != inode:
            raise ValueError("版本回退、代次水位或 WAL 恢复不一致")
        if credentials_digest != {p.name: sha(p) for p in config.iterdir() if p.is_file()}:
            raise ValueError("升级修改了身份或运行配置")
        observed = inspect()
        top = subprocess.check_output(["docker", "top", container, "-eo", "pid,comm"], text=True).splitlines()[1:]
        processes = [line.split()[0] for line in top if line.split()[-1] == "starbeacon-agen" or line.split()[-1] == "starbeacon-agent"]
        if len(processes) != 1:
            raise ValueError("运行的采集器进程身份不唯一")
        status = dict(line.split(":", 1) for line in pathlib.Path("/proc", processes[0], "status").read_text().splitlines() if ":" in line)
        for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            if int(status[field].strip(), 16) != 1 << 13:
                raise ValueError("采集器实际能力与 NET_RAW 约束不匹配")
        if set(status["Uid"].split()) != {"65532"} or set(status["Gid"].split()) != {"65532"} or status["NoNewPrivs"].strip() != "1":
            raise ValueError("采集器实际身份或权限约束不匹配")
        if any(m["RW"] and m["Destination"] != str(data) for m in observed["Mounts"]):
            raise ValueError("受管业务目录之外仍有可写卷")
        if not observed["HostConfig"]["Init"] or not observed["HostConfig"]["ReadonlyRootfs"] or observed["HostConfig"]["NetworkMode"] != "none" or observed["HostConfig"]["Privileged"]:
            raise ValueError("隔离约束不匹配")
        # 只对本轮专属档案构造一致的历史时间；不调整宿主时钟，不冒充实际经过 180 天。
        timestamp_keys = {"issued_at", "expires_at", "staged_at", "retain_until", "started_at", "finished_at"}
        def historical(value):
            if isinstance(value, list):
                return [historical(item) for item in value]
            if not isinstance(value, dict):
                return value
            result = {}
            for key, item in value.items():
                if key in timestamp_keys and isinstance(item, str):
                    item = (datetime.datetime.fromisoformat(item.replace('Z', '+00:00')) - datetime.timedelta(days=181)).isoformat()
                result[key] = historical(item)
            return result
        historic_files = [root / "state.json", *(root / "operations").glob("*.json"), *(root / "releases").glob("*/.maintenance-retention.json")]
        for file in historic_files:
            file.write_text(json.dumps(historical(json.loads(file.read_text()))) + "\n")
        result["expiry_fixture"] = {"shifted_days": 181, "actual_wall_clock_days_waited": 0, "files": len(historic_files), "scope": "dedicated_maintenance_metadata_only"}
        current_id = inspect()["Id"]
        preview = json.loads(run("cleanup-expired-preview", cleanup_command))
        cleaned = json.loads(run("cleanup-expired-execute", [*cleanup_command, "--execute"]))
        repeated = json.loads(run("cleanup-expired-repeat", [*cleanup_command, "--execute"]))
        if len(preview["release_candidates"]) != 2 or cleaned["releases_removed"] != 2 or cleaned["receipts_removed"] != 4 or cleaned["logical_bytes_removed"] <= 0 or repeated["releases_removed"] or repeated["receipts_removed"] or inspect()["Id"] != current_id:
            raise ValueError("到期回收、分离权限或重复执行不符合预期")
        final_health = health("health-after-cleanup")
        if final_health["version"] != "v0.1.0-maint.1" or final_health["wal_pending"] != 1:
            raise ValueError("回收中断了运行版本或待传事件")
        rolled = json.loads((root / "state.json").read_text())
        result["maintenance_cleanup"] = {"protected_current_and_previous": True, "interrupted_cleanup_rejected": True, "expired_releases_removed": cleaned["releases_removed"], "expired_receipts_removed": cleaned["receipts_removed"], "logical_bytes_removed": cleaned["logical_bytes_removed"], "running_container_unchanged": True, "repeat_noop": True}
        run("stop-for-wal-inspection", ["docker", "stop", "--timeout", "45", container])
        final_wal = wal_inspect("inspect-retained-wal", "inspect")
        if final_wal != original_wal:
            raise ValueError("事件原字节、来源检查点、WAL 代次或待传计数发生变化")
        result.update(status="passed", final_state=rolled, wal_records_preserved=True, wal_source_epoch_preserved=True, wal_inode_preserved=True, wal_pending_before=first_health["wal_pending"], wal_pending_after=final_health["wal_pending"], identity_config_preserved=True, effective_uid=65532, capability="NET_RAW", no_new_privileges=True, init=True, readonly=True, network="none", program_sha256={str(n): sha(base / f"build/agent-{n}") for n in (1, 2)})
        print(json.dumps({"status": "passed", "directory": str(base), "steps": len(result["results"]), "workspace_sha256": args.source}))
    except BaseException as error:
        result.update(status="failed", error_type=type(error).__name__, error=str(error))
        save()
        print(json.dumps({"status": "failed", "directory": str(base), "error": str(error)}))
        raise
    finally:
        # 只清理本轮精确身份的容器；目录、失败与原始证据留待回传核验。
        probe = subprocess.run(["docker", "container", "ls", "--all", "--filter", "name=^/" + container + "$", "--format", "{{.ID}}"], stdout=subprocess.PIPE, check=True)
        if probe.stdout.strip():
            actual = inspect()
            if actual["Config"]["Labels"].get("io.starbeacon.collector.instance") != identity:
                raise ValueError("拒绝清理身份不符的容器")
            subprocess.run(["docker", "rm", "--force", "--volumes", container], stdout=subprocess.DEVNULL, check=True)
            result["test_container_removed"] = True
        save()


if __name__ == "__main__":
    main()
