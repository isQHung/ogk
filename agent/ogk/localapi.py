"""API cục bộ 127.0.0.1: trạng thái cho tray + màn hình minh bạch 'Hôm nay em đã dùng gì'."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from . import config


class LocalAPI:
    def __init__(self, runner, port, token):
        self.runner, self.port, self.token = runner, port, token
        self.srv = None

    def start(self):
        r, token = self.runner, self.token

        class H(BaseHTTPRequestHandler):
            def _json(self, obj, code=200):
                b = json.dumps(obj, default=str).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _authed(self):
                return self.headers.get("X-OGK-Token") == token

            def do_GET(self):
                if self.path == "/state":
                    if not self._authed():
                        return self._json({"error": "unauthorized"}, 401)
                    r.last_tray_seen = r.mono()
                    return self._json(r.state_json())
                if self.path in ("/api/today", "/api/audit", "/api/help"):
                    fn = {"/api/today": r.client.today, "/api/audit": r.client.audit_log, "/api/help": r.client.list_help}
                    try:
                        return self._json(fn[self.path]())
                    except (httpx.HTTPError, RuntimeError):
                        return self._json({"error": "offline"}, 503)
                if self.path in ("/", "/today"):
                    page = (config.WEB_DIR / "today.html").read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    self.wfile.write(page)
                    return
                self._json({"error": "not found"}, 404)

            def do_POST(self):
                if self.path != "/help":
                    return self._json({"error": "not found"}, 404)
                if not self._authed():
                    return self._json({"error": "unauthorized"}, 401)
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                try:
                    out = r.client.post_help(body.get("kind"), body.get("subject", ""),
                                             int(body.get("minutes", 0)), body.get("note", ""))
                    self._json(out)
                except (httpx.HTTPError, RuntimeError):
                    self._json({"error": "offline"}, 503)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        if self.srv:
            self.srv.shutdown()
