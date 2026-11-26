#!/usr/bin/env python3
"""专属 Docker 流量端点，仅用于产生可核对的真实 TCP/HTTP 会话。"""
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

class Traffic(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path)
        if path.path == "/starbeacon/retention" or (path.path == "/starbeacon/validation" and path.query == "retention=1"):
            body = b"StarBeacon retention pilot\n".ljust(2 * 1024 * 1024, b"x")
        else:
            body = b"StarBeacon owned capture acceptance\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if len(body) <= 16 * 1024:
            self.wfile.write(body)
            return
        # 大响应按小批发送，避免瞬时突发使真实网卡验收失去连续的 TCP 观测。
        for offset in range(0, len(body), 16 * 1024):
            self.wfile.write(body[offset:offset + 16 * 1024])
            time.sleep(0.002)

    def log_message(self, *_):
        pass

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8088), Traffic).serve_forever()
