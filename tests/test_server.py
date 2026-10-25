"""Unit test phía server (dùng TestClient)."""
import json
import sqlite3
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import crypto
import main
import models as m
from db import SessionLocal

PW = "matkhau-dai-123"


@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


def parent(client, email):
    client.post("/auth/register", json={"email": email, "password": PW})
    c = TestClient(main.app)
    assert c.post("/auth/login", json={"email": email, "password": PW}).status_code == 200
    c.headers["X-CSRF-Token"] = c.cookies.get("ogk_csrf")
    return c


def pair(p, name="Bin", age=9):
    cid = p.post("/children", json={"name": name, "age": age}).json()["id"]
    code = p.post(f"/children/{cid}/enroll-code").json()["code"]
    return cid, code


def enroll(client, code):
    return client.post("/enroll", json={"code": code, "fingerprint": "fp", "name": "PC"}).json()


def auth(d):
    return {"Authorization": f"Bearer {d['token']}"}


def ev(uid, typ="app_stop", subject="minecraft", dur=60, ts=None):
    import time
    return {"uid": uid, "ts": ts or time.time(), "type": typ, "subject": subject, "duration_sec": dur}


# ---------- xác thực / phiên ----------
def test_short_password_rejected(client):
    assert client.post("/auth/register", json={"email": "a@x.vn", "password": "ngan"}).status_code == 422


def test_lockout_after_5_failures(client):
    client.post("/auth/register", json={"email": "lock@x.vn", "password": PW})
    for _ in range(5):
        assert client.post("/auth/login", json={"email": "lock@x.vn", "password": "sai-sai-sai-1"}).status_code == 401
    # đúng mật khẩu cũng bị khóa 15 phút
    assert client.post("/auth/login", json={"email": "lock@x.vn", "password": PW}).status_code == 429


def test_rate_limiter_blocks_burst():
    rl = main.RateLimiter(3, 60)
    for _ in range(3):
        rl.check("ip")
    with pytest.raises(Exception):
        rl.check("ip")


def test_csrf_required_for_writes(client):
    p = parent(client, "csrf@x.vn")
    del p.headers["X-CSRF-Token"]
    assert p.post("/children", json={"name": "A"}).status_code == 403
    p.headers["X-CSRF-Token"] = "sai"
    assert p.post("/children", json={"name": "A"}).status_code == 403


def test_logout_destroys_session(client):
    p = parent(client, "out@x.vn")
    stale = p.cookies.get("ogk_session")
    p.post("/auth/logout")
    other = TestClient(main.app)
    other.cookies.set("ogk_session", stale)
    assert other.get("/children").status_code == 401


# ---------- ghép đôi / token ----------
def test_enroll_single_use_and_expiry(client):
    p = parent(client, "enr@x.vn")
    _, code = pair(p)
    assert client.post("/enroll", json={"code": code, "fingerprint": "f", "name": "n"}).status_code == 200
    assert client.post("/enroll", json={"code": code, "fingerprint": "f", "name": "n"}).status_code == 400
    _, code2 = pair(p, "B")
    with SessionLocal() as db:
        c = db.get(m.EnrollCode, code2)
        c.expires = c.created_at - timedelta(seconds=1)
        db.commit()
    assert client.post("/enroll", json={"code": code2, "fingerprint": "f", "name": "n"}).status_code == 400


def test_access_token_expires_and_refresh_works(client):
    p = parent(client, "tok@x.vn")
    d = enroll(client, pair(p)[1])
    assert client.post("/heartbeat", headers=auth(d), json={}).status_code == 200
    with SessionLocal() as db:
        at = db.get(m.AccessToken, main.sha(d["token"]))
        at.expires = main.now() - timedelta(seconds=1)
        db.commit()
    assert client.post("/heartbeat", headers=auth(d), json={}).status_code == 401
    new = client.post("/token/refresh", json={"refresh_token": d["refresh_token"]}).json()
    assert client.post("/heartbeat", headers={"Authorization": f"Bearer {new['token']}"}, json={}).status_code == 200


def test_revoked_device_rejected(client):
    p = parent(client, "rev@x.vn")
    d = enroll(client, pair(p)[1])
    dev_id = p.get("/devices").json()[0]["id"]
    assert p.delete(f"/devices/{dev_id}").status_code == 200
    assert client.post("/heartbeat", headers=auth(d), json={}).status_code == 401
    assert client.post("/token/refresh", json={"refresh_token": d["refresh_token"]}).status_code == 401


def test_idor(client):
    a, b = parent(client, "ia@x.vn"), parent(client, "ib@x.vn")
    cid, _ = pair(a)
    assert b.post(f"/children/{cid}/enroll-code").status_code == 404
    assert b.get(f"/children/{cid}/policy").status_code == 404
    assert b.put(f"/children/{cid}/policy", json={}).status_code == 404
    assert b.get(f"/reports/{cid}").status_code == 404
    assert b.get(f"/audit?child_id={cid}").status_code == 404
    assert b.delete(f"/children/{cid}/data").status_code == 404
    assert b.post(f"/children/{cid}/commands", json={"kind": "lock"}).status_code == 404
    assert b.get("/children").json() == []


# ---------- chính sách có ký + nhật ký kiểm toán ----------
def test_policy_signed_versioned_and_audited(client):
    p = parent(client, "pol@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    pol = p.get(f"/children/{cid}/policy").json()["policy"]
    pol["quota_min_weekday"] = 45
    assert p.put(f"/children/{cid}/policy", json=pol).json()["version"] == 2
    got = client.get("/policy", headers=auth(d)).json()
    assert got["version"] == 2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import base64
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(d["server_pubkey"]))
    pub.verify(base64.b64decode(got["sig"]), got["payload"].encode())  # không ném lỗi = hợp lệ
    with pytest.raises(Exception):
        pub.verify(base64.b64decode(got["sig"]), got["payload"].replace("45", "450").encode())
    log = p.get(f"/audit?child_id={cid}").json()
    upd = [x for x in log if x["action"] == "policy_update"][0]
    assert upd["old"]["quota_min_weekday"] == 90 and upd["new"]["quota_min_weekday"] == 45
    assert upd["who"] == "pol@x.vn" and upd["ip"]
    # trẻ xem được nhật ký (NT5), không có IP
    ta = client.get("/transparency/audit", headers=auth(d)).json()
    assert "ip" not in ta[0] and "quota_min_weekday" in [k for x in ta for k in x["changed"]]
    assert ta[0]["details"] == {}


def test_invalid_policy_rejected(client):
    p = parent(client, "bad@x.vn")
    cid, _ = pair(p)
    pol = p.get(f"/children/{cid}/policy").json()["policy"]
    pol["schedule"] = ["1" * 47] * 7
    assert p.put(f"/children/{cid}/policy", json=pol).status_code == 422


def test_age_default_policy(client):
    p = parent(client, "age@x.vn")
    young = p.post("/children", json={"name": "Nho", "age": 8}).json()["id"]
    teen = p.post("/children", json={"name": "Lon", "age": 14}).json()["id"]
    assert "social" in p.get(f"/children/{young}/policy").json()["policy"]["blocked_categories"]
    assert "social" not in p.get(f"/children/{teen}/policy").json()["policy"]["blocked_categories"]


# ---------- sự kiện / quyền riêng tư ----------
def test_events_idempotent_and_encrypted_at_rest(client):
    p = parent(client, "evt@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    batch = {"events": [ev("uid-aaaaaaaa"), ev("uid-bbbbbbbb", "domain_query", "vnexpress.net", 0)]}
    assert client.post("/events", headers=auth(d), json=batch).json()["accepted"] == 2
    again = client.post("/events", headers=auth(d), json=batch).json()
    assert again["accepted"] == 0 and again["duplicates"] == 2
    rep = p.get(f"/reports/{cid}?days=1").json()
    assert rep["top_apps"][0] == {"name": "minecraft", "minutes": 1.0}
    assert rep["top_domains"][0]["name"] == "vnexpress.net"
    with SessionLocal() as db:
        raw = [e.subject_enc for e in db.query(m.Event).filter_by(child_id=cid)]
    assert raw and all("minecraft" not in r and "vnexpress" not in r for r in raw)
    assert crypto.dec(raw[0]) in ("minecraft", "vnexpress.net")


def test_events_reject_urls_and_unknown_types(client):
    p = parent(client, "url@x.vn")
    d = enroll(client, pair(p)[1])
    assert client.post("/events", headers=auth(d),
                       json={"events": [ev("uid-cccccccc", "domain_query", "site.com/path?q=1")]}).status_code == 422
    assert client.post("/events", headers=auth(d),
                       json={"events": [ev("uid-dddddddd", "keystroke", "abc")]}).status_code == 422


def test_retention_purge_90_days(client):
    p = parent(client, "ret@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    import time
    old = time.time() - 91 * 86400
    client.post("/events", headers=auth(d), json={"events": [ev("uid-old00001", ts=old), ev("uid-new00001")]})
    with SessionLocal() as db:
        assert main.purge_old(db) == 1
        assert db.query(m.Event).filter_by(child_id=cid).count() == 1


def test_delete_child_data_queues_wipe(client):
    p = parent(client, "del@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    client.post("/events", headers=auth(d), json={"events": [ev("uid-del00001")]})
    assert p.delete(f"/children/{cid}/data").json()["deleted_events"] == 1
    hb = client.post("/heartbeat", headers=auth(d), json={}).json()
    assert [c["kind"] for c in hb["commands"]] == ["wipe_cache"]
    assert p.get(f"/reports/{cid}?days=1").json()["top_apps"] == []


# ---------- yêu cầu của trẻ, lệnh ----------
def test_child_request_flow_more_time(client):
    p = parent(client, "req@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    r = client.post("/help", headers=auth(d), json={"kind": "more_time", "minutes": 20, "note": "bài tập"}).json()
    assert p.get("/requests").json()[0]["id"] == r["id"]
    p.post(f"/requests/{r['id']}/decide", json={"approve": True, "minutes": 20, "reply": "OK con"})
    mine = client.get("/help", headers=auth(d)).json()[0]
    assert mine["status"] == "approved" and mine["reply"] == "OK con"
    child_audit = client.get("/transparency/audit", headers=auth(d)).json()
    decision = next(entry for entry in child_audit if entry["action"] == "request_decided")
    assert decision["details"] == {"status": "approved", "reply": "OK con", "kind": "more_time"}
    hb = client.post("/heartbeat", headers=auth(d), json={}).json()
    assert hb["commands"][0]["kind"] == "add_minutes" and hb["commands"][0]["minutes"] == 20
    # ack -> không gửi lại
    hb2 = client.post("/heartbeat", headers=auth(d), json={"acked": [hb["commands"][0]["id"]]}).json()
    assert hb2["commands"] == []


@pytest.mark.parametrize("approve,status", [(True, "approved"), (False, "denied")])
def test_deciding_child_request_pushes_status_over_websocket(client, approve, status):
    p = parent(client, f"push-{status}@x.vn")
    _, code = pair(p)
    d = enroll(client, code)
    request = client.post("/help", headers=auth(d), json={
        "kind": "more_time", "minutes": 15, "note": "bài tập"
    }).json()

    class ConnectedDevice:
        def __init__(self):
            self.messages = []

        async def send_json(self, payload):
            self.messages.append(payload)

    connection = ConnectedDevice()
    main.hub.conns[d["device_id"]] = connection
    try:
        response = p.post(f"/requests/{request['id']}/decide", json={"approve": approve})
        assert response.status_code == 200
        assert connection.messages[0] == {
            "type": "help_decided", "id": request["id"], "status": status
        }
    finally:
        main.hub.conns.pop(d["device_id"], None)


def test_wrong_block_request_adds_allow_rule(client):
    p = parent(client, "wb@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    r = client.post("/help", headers=auth(d), json={"kind": "wrong_block", "subject": "scratch.mit.edu"}).json()
    p.post(f"/requests/{r['id']}/decide", json={"approve": True})
    pol = p.get(f"/children/{cid}/policy").json()
    assert pol["version"] == 2
    assert {"domain": "scratch.mit.edu", "action": "allow", "set_by": "wb@x.vn"} in pol["policy"]["domain_rules"]


def test_uninstall_needs_parent_password_and_is_logged(client):
    p = parent(client, "un@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    assert client.post("/devices/uninstall", headers=auth(d), json={"email": "un@x.vn", "password": "sai-sai-sai"}).status_code == 401
    assert client.post("/devices/uninstall", headers=auth(d), json={"email": "un@x.vn", "password": PW}).status_code == 200
    assert client.post("/heartbeat", headers=auth(d), json={}).status_code == 401
    assert "device_uninstalled" in [x["action"] for x in p.get(f"/audit?child_id={cid}").json()]


def test_csv_export(client):
    p = parent(client, "csv@x.vn")
    cid, code = pair(p)
    d = enroll(client, code)
    client.post("/events", headers=auth(d), json={"events": [ev("uid-csv00001")]})
    r = p.get(f"/reports/{cid}/export.csv?days=1")
    assert r.headers["content-type"].startswith("text/csv") and "app_minutes,minecraft,1.0" in r.text
