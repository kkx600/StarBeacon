#!/usr/bin/env python3
"""专属 Docker 流量端点，仅用于产生可核对的真实 TCP/HTTP 会话。"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Traffic(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"StarBeacon owned capture acceptance\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8088), Traffic).serve_forever()
