"""Kịch bản tích hợp: server thật (uvicorn) + agent thật (ServerClient/Runner)."""
import json
import threading
import time

import httpx
import pytest
import uvicorn
from websockets.sync.client import connect

import main
from ogk.cache import Cache
from ogk.client import PolicyRejected, ServerClient
from ogk.runner import Runner

PW = "matkhau-dai-123"


@pytest.fixture(scope="module")
def live():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)


class Parent:
    def __init__(self, base, email):
        self.c = httpx.Client(base_url=base)
        self.c.post("/auth/register", json={"email": email, "password": PW})
        self.c.post("/auth/login", json={"email": email, "password": PW})
        self.c.headers["X-CSRF-Token"] = self.c.cookies.get("ogk_csrf")

    def child_and_code(self, name="Bin"):
        cid = self.c.post("/children", json={"name": name, "age": 9}).json()["id"]
        return cid, self.c.post(f"/children/{cid}/enroll-code").json()["code"]


def enroll(base, parent, tmp_path, name="Bin"):
    cid, code = parent.child_and_code(name)
    cache = Cache(tmp_path / "agent.db")
    ServerClient(cache).enroll(base, code, "fp", "PC-test")
    return cid, cache


def wait_for(fn, timeout=5.0):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
        if fn():
            return time.monotonic() - t
        time.sleep(0.05)
    raise AssertionError("hết thời gian chờ")


def new_runner(tmp_path, free_ports, interval=60):
    api = free_ports(1)[0]
    r = Runner(home=tmp_path, start_dns_servers=False, api_port=api, enforce_lock=False, interval=interval)
    r.start()
    return r


def test_i1_policy_push_is_signed_and_applied(live, tmp_path, free_ports):
    p = Parent(live, "i1@x.vn")
    cid, cache = enroll(live, p, tmp_path)
    pol = p.c.get(f"/children/{cid}/policy").json()["policy"]
    pol["quota_min_weekday"] = pol["quota_min_weekend"] = 45
    p.c.put(f"/children/{cid}/policy", json=pol)
    r = new_runner(tmp_path, free_ports)
    try:
        wait_for(lambda: r.policy_version == 2 and r.policy["quota_min_weekday"] == 45)
        assert r.cache.get("policy_signed")["sig"]
    finally:
        r.stop()


def test_i2_tampered_and_downgraded_policy_rejected(live, tmp_path):
    p = Parent(live, "i2@x.vn")
    cid, cache = enroll(live, p, tmp_path)
    c = ServerClient(cache)
    data, payload, sig = c.fetch_policy(0)
    assert data["version"] == 1
    conn = cache.get("conn")
    cache.set("conn", {**conn, "pubkey": "A" * 43 + "="})  # khóa công khai sai (giả mạo máy chủ)
    with pytest.raises(PolicyRejected):
        c.fetch_policy(0)
    cache.set("conn", conn)
    with pytest.raises(PolicyRejected):  # bản cũ hơn bản đang dùng
        c.fetch_policy(5)


def test_i3_offline_queue_then_idempotent_sync(live, tmp_path):
    p = Parent(live, "i3@x.vn")
    cid, cache = enroll(live, p, tmp_path)
    for i in range(3):
        cache.enqueue_event("app_stop", "minecraft", 60, 1, time.time())
    evs = cache.pending_events()
    dead = Cache(tmp_path / "dead.db")
    dead.set("conn", {**cache.get("conn"), "server": "http://127.0.0.1:9"})
    with pytest.raises(httpx.HTTPError):
        ServerClient(dead).post_events(evs)  # mất mạng: sự kiện vẫn nằm trong hàng đợi
    assert len(cache.pending_events()) == 3
    c = ServerClient(cache)
    assert c.post_events(evs)["accepted"] == 3
    assert c.post_events(evs) == {"accepted": 0, "duplicates": 3}  # gửi lại không bị đếm hai lần
    assert p.c.get(f"/reports/{cid}?days=1").json()["top_apps"][0]["minutes"] == 3.0


def test_i4_urgent_command_under_5s_over_websocket(live, tmp_path, free_ports):
    p = Parent(live, "i4@x.vn")
    cid, cache = enroll(live, p, tmp_path)
    r = new_runner(tmp_path, free_ports, interval=60)  # heartbeat 60s: chỉ WebSocket mới kịp
    try:
        time.sleep(1.5)  # chờ WS kết nối
        t0 = time.monotonic()
        p.c.post(f"/children/{cid}/commands", json={"kind": "lock"})
        dt = wait_for(lambda: r.enforcer.forced["on"], 5)
        assert dt < 5
        p.c.post(f"/children/{cid}/commands", json={"kind": "unlock"})
        wait_for(lambda: not r.enforcer.forced["on"], 5)
        p.c.post(f"/children/{cid}/commands", json={"kind": "add_minutes", "minutes": 15})
        wait_for(lambda: r.cache.extra(r.enforcer._local(r.policy).date().isoformat()) == 900, 5)
        # lệnh đã ack -> không còn chờ ở server
        wait_for(lambda: not r.client.request("POST", "/heartbeat", json={"acked": []})["commands"], 5)
    finally:
        r.stop()


def test_help_decision_reaches_child_ui_over_websocket(live, tmp_path, free_ports):
    p = Parent(live, "help-ws@x.vn")
    _, cache = enroll(live, p, tmp_path)
    r = new_runner(tmp_path, free_ports)
    device_id = cache.get("conn")["device_id"]
    try:
        wait_for(lambda: device_id in main.hub.conns, 5)
        url = f"ws://127.0.0.1:{r.api.port}/api/events?token={r.token}"
        with connect(url, origin=f"http://127.0.0.1:{r.api.port}") as child_ui:
            request = r.client.post_help("more_time", minutes=15, note="bài tập")
            response = p.c.post(f"/requests/{request['id']}/decide",
                                json={"approve": True, "minutes": 15, "reply": "Được con"})
            assert response.status_code == 200
            event = json.loads(child_ui.recv(timeout=3))
            assert event == {"type": "help_decided", "id": request["id"], "status": "approved"}
    finally:
        r.stop()


def test_i5_policy_change_reaches_agent_within_seconds(live, tmp_path, free_ports):
    p = Parent(live, "i5@x.vn")
    cid, cache = enroll(live, p, tmp_path)
    r = new_runner(tmp_path, free_ports, interval=60)
    try:
        time.sleep(1.5)
        pol = p.c.get(f"/children/{cid}/policy").json()["policy"]
        pol["blocked_categories"] = ["social", "games", "inappropriate"]
        p.c.put(f"/children/{cid}/policy", json=pol)
        dt = wait_for(lambda: r.policy_version == 2 and "games" in r.policy["blocked_categories"], 10)
        assert dt < 10  # yêu cầu của đề: ≤ 60 giây
    finally:
        r.stop()


def test_i6_runner_events_report_and_revocation(live, tmp_path, free_ports):
    p = Parent(live, "i6@x.vn")
    cid, cache = enroll(live, p, tmp_path)
    r = new_runner(tmp_path, free_ports)
    try:
        r.emit("app_stop", "scratch", 120)
        r.on_query("www.hcmus.edu.vn")
        r.sync_now.set()
        wait_for(lambda: p.c.get(f"/reports/{cid}?days=1").json()["top_apps"], 6)
        rep = p.c.get(f"/reports/{cid}?days=1").json()
        assert rep["top_apps"][0] == {"name": "scratch", "minutes": 2.0}
        assert rep["top_domains"][0]["name"] == "hcmus.edu.vn"  # chỉ lưu tên miền cấp hai
        dev = p.c.get("/devices").json()[0]
        assert dev["last_seen"] and dev["policy_version_seen"] == 1
        # thu hồi thiết bị -> agent tự dừng kiểm soát
        p.c.delete(f"/devices/{dev['id']}")
        r.sync_now.set()
        wait_for(lambda: r.revoked, 6)
        assert r.get_policy() is None
    finally:
        r.stop()
