import socket
from types import SimpleNamespace

import httpx
from websockets.sync.client import connect

from ogk.localapi import LocalAPI


class HelpClient:
    def __init__(self):
        self.requests = []

    def post_help(self, kind, subject="", minutes=0, note=""):
        request = {"kind": kind, "subject": subject, "minutes": minutes, "note": note}
        self.requests.append(request)
        return {"status": "pending", **request}


class Runner:
    def __init__(self):
        self.client = HelpClient()
        self.state = SimpleNamespace(
            locked=False,
            reason="",
            remaining_sec=1800,
            in_grace=False,
        )
        self.cache = SimpleNamespace(get=lambda key, default=None: 1000 if key == "last_contact" else default)
        self.ts = SimpleNamespace(now=lambda: 1010)
        self.interval = 60
        self.policy_version = 3
        self.enforcer = SimpleNamespace(expired=False)
        self.suspended = False
        self.revoked = False
        self.last_tray_seen = 0

    def mono(self):
        return 42

    def state_json(self):
        return {}


def test_local_browser_help_requires_same_origin():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    runner = Runner()
    api = LocalAPI(runner, port, "tray-token")
    api.start()
    try:
        url = f"http://127.0.0.1:{port}/api/help"
        payload = {"kind": "more_time", "minutes": 15, "note": "bài tập"}

        rejected = httpx.post(url, json=payload, headers={"Origin": "http://example.com"})
        assert rejected.status_code == 403
        assert runner.client.requests == []

        accepted = httpx.post(url, json=payload, headers={"Origin": f"http://127.0.0.1:{port}"})
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "pending"
        assert runner.client.requests == [payload | {"subject": ""}]
    finally:
        api.stop()


def test_local_ui_receives_remaining_time_only_with_local_token():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    runner = Runner()
    api = LocalAPI(runner, port, "tray-token")
    api.start()
    try:
        url = f"http://127.0.0.1:{port}"
        page = httpx.get(url + "/")
        assert page.status_code == 200
        assert b'content="tray-token"' in page.content
        assert b"__OGK_LOCAL_TOKEN__" not in page.content

        rejected = httpx.get(url + "/api/state")
        assert rejected.status_code == 401

        accepted = httpx.get(url + "/api/state", headers={"X-OGK-Token": "tray-token"})
        assert accepted.status_code == 200
        assert accepted.json() == {
            "locked": False,
            "reason": "",
            "remaining_sec": 1800,
            "in_grace": False,
            "policy_version": 3,
            "online": True,
            "expired": False,
            "suspended": False,
            "revoked": False,
        }
        assert runner.last_tray_seen == 42
    finally:
        api.stop()


def test_local_ui_receives_websocket_help_updates():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    runner = Runner()
    api = LocalAPI(runner, port, "tray-token")
    api.start()
    try:
        url = f"ws://127.0.0.1:{port}/api/events?token=tray-token"
        with connect(url, origin=f"http://127.0.0.1:{port}") as ws:
            api.broadcast({"type": "help_decided", "id": 12, "status": "approved"})
            assert ws.recv(timeout=2) == '{"type": "help_decided", "id": 12, "status": "approved"}'
    finally:
        api.stop()
