"""API cục bộ 127.0.0.1: trạng thái cho tray + màn hình minh bạch 'Hôm nay em đã dùng gì'."""
import json
import base64
import hashlib
import queue
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx

from . import config


class LocalAPI:
    def __init__(self, runner, port, token):
        self.runner, self.port, self.token = runner, port, token
        self.srv = None
        self._listeners = set()
        self._listeners_lock = threading.Lock()

    def broadcast(self, payload):
        with self._listeners_lock:
            listeners = tuple(self._listeners)
        for listener in listeners:
            listener.put(payload)

    def start(self):
        r, token = self.runner, self.token
        api = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _json(self, obj, code=200):
                b = json.dumps(obj, default=str).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _authed(self):
                return self.headers.get("X-OGK-Token") == token

            def _send_ws_text(self, payload):
                data = json.dumps(payload, default=str).encode("utf-8")
                size = len(data)
                if size < 126:
                    frame = bytes([0x81, size]) + data
                elif size < 65536:
                    frame = bytes([0x81, 126]) + size.to_bytes(2, "big") + data
                else:
                    frame = bytes([0x81, 127]) + size.to_bytes(8, "big") + data
                self.connection.sendall(frame)

            def _websocket_events(self, parsed):
                expected_origin = f"http://127.0.0.1:{self.server.server_port}"
                requested_token = parse_qs(parsed.query).get("token", [""])[0]
                key = self.headers.get("Sec-WebSocket-Key", "")
                if (self.headers.get("Origin") != expected_origin or requested_token != token
                        or self.headers.get("Upgrade", "").lower() != "websocket" or not key):
                    return self._json({"error": "unauthorized"}, 401)
                accept = base64.b64encode(hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
                ).digest()).decode("ascii")
                self.send_response(101, "Switching Protocols")
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                listener = queue.Queue()
                with api._listeners_lock:
                    api._listeners.add(listener)
                try:
                    while True:
                        readable, _, _ = select.select([self.connection], [], [], 0)
                        if readable:
                            incoming = self.connection.recv(2, socket.MSG_PEEK)
                            if not incoming or incoming[0] & 0x0F == 0x08:
                                return
                        try:
                            payload = listener.get(timeout=0.5)
                        except queue.Empty:
                            continue
                        self._send_ws_text(payload)
                except (ConnectionError, OSError):
                    return
                finally:
                    with api._listeners_lock:
                        api._listeners.discard(listener)

            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path == "/api/events":
                    return self._websocket_events(parsed)
                if self.path == "/state":
                    if not self._authed():
                        return self._json({"error": "unauthorized"}, 401)
                    r.last_tray_seen = r.mono()
                    return self._json(r.state_json())
                if self.path == "/api/state":
                    if not self._authed():
                        return self._json({"error": "unauthorized"}, 401)
                    r.last_tray_seen = r.mono()
                    state = r.state
                    last_contact = r.cache.get("last_contact")
                    online = bool(last_contact) and r.ts.now() - last_contact < r.interval * 3
                    return self._json({
                        "locked": state.locked,
                        "reason": state.reason,
                        "remaining_sec": state.remaining_sec,
                        "in_grace": state.in_grace,
                        "policy_version": r.policy_version,
                        "online": online,
                        "expired": r.enforcer.expired,
                        "suspended": r.suspended,
                        "revoked": r.revoked,
                    })
                if self.path in ("/api/today", "/api/audit", "/api/help"):
                    fn = {"/api/today": r.client.today, "/api/audit": r.client.audit_log, "/api/help": r.client.list_help}
                    try:
                        return self._json(fn[self.path]())
                    except (httpx.HTTPError, RuntimeError):
                        return self._json({"error": "offline"}, 503)
                if self.path in ("/", "/today"):
                    page = (config.WEB_DIR / "today.html").read_bytes()
                    page = page.replace(b"__OGK_LOCAL_TOKEN__", token.encode("ascii"))
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    self.wfile.write(page)
                    return
                self._json({"error": "not found"}, 404)

            def do_POST(self):
                browser_request = self.path == "/api/help"
                if self.path not in ("/help", "/api/help"):
                    return self._json({"error": "not found"}, 404)
                if browser_request:
                    expected_origin = f"http://127.0.0.1:{self.server.server_port}"
                    if self.headers.get("Origin") != expected_origin:
                        return self._json({"error": "forbidden origin"}, 403)
                    if not self.headers.get("Content-Type", "").startswith("application/json"):
                        return self._json({"error": "JSON required"}, 415)
                elif not self._authed():
                    return self._json({"error": "unauthorized"}, 401)
                try:
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                except (ValueError, json.JSONDecodeError):
                    return self._json({"error": "invalid JSON"}, 400)
                if not isinstance(body, dict):
                    return self._json({"error": "JSON object required"}, 400)
                try:
                    out = r.client.post_help(body.get("kind"), body.get("subject", ""),
                                             int(body.get("minutes", 0)), body.get("note", ""))
                    self._json(out)
                except ValueError:
                    self._json({"error": "invalid request"}, 400)
                except (httpx.HTTPError, RuntimeError):
                    self._json({"error": "offline"}, 503)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        if self.srv:
            self.srv.shutdown()
            self.srv.server_close()
