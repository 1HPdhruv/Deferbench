"""Loopback-only HTTP sink that records whether a synthetic canary left the workspace."""
from __future__ import annotations
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from .safety import SafetyError, is_loopback_host


class LoopbackSink:
    def __init__(self, host: str = "127.0.0.1"):
        if not is_loopback_host(host):
            raise SafetyError(f"sink must bind to loopback, got {host!r}")
        self.hits: list[str] = []
        self._lock = threading.Lock()
        sink = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = min(int(self.headers.get("Content-Length", 0) or 0), 65536)
                body = self.rfile.read(n).decode(errors="replace")
                with sink._lock:
                    sink.hits.append(body + "\n" + str(self.headers))
                self.send_response(200); self.end_headers()
            do_PUT = do_POST
            def do_GET(self):
                with sink._lock:
                    sink.hits.append("GET " + self.path + "\n" + str(self.headers))
                self.send_response(200); self.end_headers()
            def log_message(self, *a): pass

        self.srv = HTTPServer((host, 0), H)
        assert is_loopback_host(self.srv.server_address[0])
        self.host, self.port = self.srv.server_address[:2]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def clear(self):
        with self._lock:
            self.hits.clear()

    def saw(self, canary: str) -> bool:
        with self._lock:
            return any(canary in h for h in self.hits)

    def close(self):
        self.srv.shutdown(); self.srv.server_close(); self.thread.join(timeout=5)
