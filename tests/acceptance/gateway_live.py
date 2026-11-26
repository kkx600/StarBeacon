#!/usr/bin/env python3
"""只在专属 Docker 路由夹具中验收限时防火墙、正常 HTTP 流量和两侧抓包。"""

import argparse
import datetime
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid


LEFT = "10.203.35.0/24"
RIGHT = "10.203.36.0/24"
GATE_LEFT, GATE_RIGHT = "10.203.35.2", "10.203.36.2"
CLIENT, SERVER = "10.203.35.3", "10.203.36.3"
LABEL = "io.starbeacon.acceptance.gateway-fixture"
NSENTER = "/usr/bin/nsenter"
PYTHON = "/usr/bin/python3"
RUNUSER = "/usr/sbin/runuser"
IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"


def run(*args, timeout=30, **options):
    return subprocess.run(args, check=True, timeout=timeout, **options)


def output(*args, timeout=30):
    return run(*args, stdout=subprocess.PIPE, text=True, timeout=timeout).stdout.strip()


def inspect(kind, name):
    return json.loads(output("docker", kind, "inspect", name))[0]


def ns(pid, *args):
    return [NSENTER, "-t", str(pid), "-n", "--", *args]


class FixtureHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        match = re.fullmatch(r"/acceptance/(\d+)", self.path)
        if match is None:
            self.send_error(404)
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("X-Fixture-Step", match[1])
        self.end_headers()

    def log_message(self, *_):
        pass


def serve_http():
    with http.server.ThreadingHTTPServer((SERVER, 8080), FixtureHTTP) as httpd:
        print("ready", flush=True)
        httpd.serve_forever()


def http_client():
    connections = [socket.create_connection((SERVER, 8080), timeout=2) for _ in range(2)]
    pending = [b"", b""]
    print(json.dumps([conn.getsockname()[1] for conn in connections]), flush=True)
    try:
        for sequence, line in enumerate(sys.stdin, 1):
            if line.strip() == "reconnect":
                fresh = socket.create_connection((SERVER, 8080), timeout=2)
                connections[1].close()
                connections[1], pending[1] = fresh, b""
                print(json.dumps(fresh.getsockname()[1]), flush=True)
                continue
            which = int(line)
            if which not in (0, 1):
                raise ValueError("仅允许选择两个实验连接")
            sock = connections[which]
            author = f"GET /acceptance/{sequence} HTTP/1.1\r\nHost: gateway-fixture\r\n\r\n".encode()
            expected = f"X-Fixture-Step: {sequence}".encode()
            end = time.monotonic() + 0.8
            sock.settimeout(0.8)
            passing = False
            try:
                sock.sendall(author)
                while time.monotonic() < end:
                    if b"\r\n\r\n" in pending[which]:
                        header, pending[which] = pending[which].split(b"\r\n\r\n", 1)
                        if expected in header.split(b"\r\n"):
                            passing = True
                            break
                        continue
                    sock.settimeout(max(0.001, end - time.monotonic()))
                    fragment = sock.recv(4096)
                    if not fragment:
                        raise EOFError("实验服务器提前断开了持久连接")
                    pending[which] += fragment
                    if len(pending[which]) > 16384:
                        raise ValueError("实验响应超过头部长度上限")
            except TimeoutError:
                pass
            print(json.dumps(passing), flush=True)
    finally:
        for sock in connections:
            sock.close()


def private_environment(directory, network):
    names = ("POSTGRES_PASSWORD", "SB_RUNTIME_DB_PASSWORD", "REDIS_PASSWORD", "NATS_TOKEN")
    entries = dict(line.split("=", 1) for line in (directory / "dependencies.env").read_text().splitlines() if "=" in line)
    cred = {name: urllib.parse.quote(entries[name], safe="") for name in names}
    project = directory.name

    def ip(service):
        data = inspect("container", f"{project}-{service}-1")
        if not data["State"]["Running"] or data["Config"]["Labels"].get("com.docker.compose.project") != project:
            raise ValueError("验收依赖的归属不匹配")
        return str(data["NetworkSettings"]["Networks"][network]["IPAddress"])

    postgres, elastic = ip("postgres"), ip("elasticsearch")
    return {
        "SB_MODE": "development", "SB_ES_URL": f"http://{elastic}:9200",
        "SB_MIGRATION_DATABASE_URL": f"postgres://starbeacon_owner:{cred['POSTGRES_PASSWORD']}@{postgres}:5432/starbeacon?sslmode=disable",
        "SB_DATABASE_URL": f"postgres://starbeacon_app:{cred['SB_RUNTIME_DB_PASSWORD']}@{postgres}:5432/starbeacon?sslmode=disable",
        "SB_NATS_URL": f"nats://{cred['NATS_TOKEN']}@{ip('nats')}:4222",
        "SB_REDIS_URL": f"redis://:{cred['REDIS_PASSWORD']}@{ip('redis')}:6379/0",
    }


def qualify(source, project, observation):
    source = source.resolve(strict=True)
    if os.geteuid() != 0 or not re.fullmatch(r"sbacc_[a-f0-9]{16}", project) or not (source / "go.mod").is_file():
        raise ValueError("需使用专属 Docker 验收工程与已同步的 Go 源码")
    directory = pathlib.Path("/var/lib/starbeacon-acceptance") / project
    if json.loads((directory / "owner.json").read_text()) != {"schema_version": 1, "project": project, "storage": "persistent"}:
        raise ValueError("远程验收项目归属不匹配")
    management = project + "_default"
    fixtures = "sb-gateway-" + uuid.uuid4().hex[:10]
    image = "starbeacon/acceptance:" + project
    script = source / "tests/acceptance/gateway_live.py"
    work = pathlib.Path(tempfile.mkdtemp(prefix="gateway-live-", dir=source.parent))
    compose = ["docker", "compose", "-p", project, "--env-file", str(directory / "dependencies.env"), "-f", str(directory / "compose.json")]
    ordered_resources = []
    httpd = None
    status = 1
    journal = work / "resources.jsonl"
    if output(*compose, "ps", "--status", "running", "-q", "runner", "capture-runner", "capture-fixture"):
        raise ValueError("同一个验收工程已有活动测试，稍后运行受控网关验收")
    binary_dir = work / "bin"
    binary_dir.mkdir(mode=0o700)
    os.chown(binary_dir, 65532, 65532)
    cache = directory / "go-build-cache"
    cache.mkdir(mode=0o700, exist_ok=True)
    os.chown(cache, 65532, 65532)
    labels = {LABEL: fixtures}

    def create_network(name, subnet):
        key = output("docker", "network", "create", "--internal", "--label", f"{LABEL}={fixtures}",
                     "--subnet", subnet, fixtures + "-" + name)
        ordered_resources.append(("network", key))
        return key

    def make_peer(name, network, ip, gateway=False):
        options = ["--sysctl", "net.ipv4.ip_forward=1"] if gateway else []
        key = output("docker", "run", "-d", "--name", fixtures + "-" + name, "--network", network,
                     "--ip", ip, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                     "--label", f"{LABEL}={fixtures}", *options, "--entrypoint", "/bin/sleep", image, "240")
        ordered_resources.append(("container", key))
        data = inspect("container", key)
        pid = data["State"]["Pid"]
        if pid < 2 or not data["State"]["Running"] or data["Config"]["Labels"].get(LABEL) != fixtures:
            raise ValueError("Docker 夹具身份无法确认")
        if os.readlink(f"/proc/{pid}/ns/net") == os.readlink("/proc/1/ns/net"):
            raise ValueError("Docker 夹具与宿主机必须分属独立网络命名空间")
        return key, pid

    try:
        run(*compose, "run", "--rm", "-T", "--no-deps", "--env", "CGO_ENABLED=0", "--env", "GOPROXY=off",
            "--volume", str(source) + ":/source:ro", "--volume", str(binary_dir) + ":/output",
            "--volume", str(cache) + ":/tmp/go-cache", "--entrypoint", "go", "runner",
            "test", "-tags=integration,gatewayintegration", "-c", "-o", "/output/gateway.test",
            "./tests/integration", stdin=subprocess.DEVNULL, timeout=600)
        left, right = create_network("left", LEFT), create_network("right", RIGHT)
        gateway, gateway_pid = make_peer("router", left, GATE_LEFT, True)
        run("docker", "network", "connect", "--ip", GATE_RIGHT, right, gateway)
        run("docker", "network", "connect", management, gateway)
        _, client_pid = make_peer("client", left, CLIENT)
        _, server_pid = make_peer("server", right, SERVER)
        run(*ns(client_pid, IP, "route", "replace", RIGHT, "via", GATE_LEFT))
        run(*ns(server_pid, IP, "route", "replace", LEFT, "via", GATE_RIGHT))
        run(*ns(gateway_pid, NFT, "-f", str(source / "deploy/gateway/nftables.conf")))
        httpd = subprocess.Popen(ns(server_pid, RUNUSER, "-u", "nobody", "--", PYTHON, "-I", str(script), "server"),
                                 stdout=subprocess.PIPE, text=True, start_new_session=True)
        if httpd.stdout.readline().strip() != "ready":
            raise ValueError("HTTP 实验服务启动失败")
        interfaces = json.loads(output(*ns(gateway_pid, IP, "-4", "-j", "address", "show")))
        by_address = {addr["local"]: item["ifname"] for item in interfaces for addr in item.get("addr_info", [])}
        env = dict(os.environ, **private_environment(directory, management),
                   SB_GATEWAY_CLIENT_PID=str(client_pid), SB_GATEWAY_FIXTURE=str(script),
                   SB_GATEWAY_LEFT_IFACE=by_address[GATE_LEFT], SB_GATEWAY_RIGHT_IFACE=by_address[GATE_RIGHT])
        log = work / "gateway-live.log"
        test = "TestGatewayBlockLiveDockerObservation" if observation else "TestGatewayBlockLiveDockerForwarding"
        with log.open("w") as target:
            proc = subprocess.run(ns(gateway_pid, str(binary_dir/"gateway.test"), "-test.v",
                                     f"-test.run=^{test}$", "-test.timeout=130s"),
                                  env=env, stdout=target, stderr=subprocess.STDOUT, timeout=150)
        redacted = ("postgres://", "redis://", "nats://")
        for line in log.read_text(errors="replace").splitlines():
            if not any(value in line for value in redacted):
                print(line)
        status = proc.returncode
    finally:
        if httpd is not None:
            if httpd.poll() is None:
                os.killpg(httpd.pid, signal.SIGTERM)
            httpd.wait(timeout=10)
        with journal.open("w") as file:
            before = shutil.disk_usage(work).free
            file.write(json.dumps({"phase": "manifest", "label": labels, "resources": ordered_resources, "disk_free_before": before}) + "\n")
            file.flush()
            os.fsync(file.fileno())
            removed, skipped = [], []
            for kind, key in reversed(ordered_resources):
                data = inspect(kind, key)
                actual = data["Config"]["Labels"] if kind == "container" else data["Labels"]
                if actual.get(LABEL) != fixtures:
                    skipped.append(key)
                    continue
                if kind == "container" and data["State"]["Running"]:
                    run("docker", "container", "stop", "--time", "1", key, stdout=subprocess.DEVNULL)
                run("docker", kind, "rm", key, stdout=subprocess.DEVNULL)
                removed.append(key)
            file.write(json.dumps({"phase": "result", "status": "partial" if skipped else "passed",
                                   "removed": removed, "skipped": skipped, "disk_free_after": shutil.disk_usage(work).free}) + "\n")
            if skipped:
                status = 1
        print(f"网关验收目录 {work}", flush=True)
    return status


def main():
    if sys.argv[1:] == ["server"]:
        serve_http()
        return 0
    if sys.argv[1:] == ["client", SERVER]:
        http_client()
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--observation", action="store_true")
    args = parser.parse_args()
    return qualify(args.source, args.project, args.observation)


if __name__ == "__main__":
    raise SystemExit(main())
