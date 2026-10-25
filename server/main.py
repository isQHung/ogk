import asyncio
import csv
import hashlib
import io
import json
import os
import secrets
import time
from collections import Counter, defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import (Depends, FastAPI, Header, HTTPException, Request, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

import crypto
import models as m
from db import Base, SessionLocal, engine, get_db
from policy_schema import DomainRule, Policy, default_policy

COOKIE, CSRF_COOKIE = "ogk_session", "ogk_csrf"
COOKIE_SECURE = os.getenv("OGK_COOKIE_SECURE", "0") == "1"  # =1 khi chạy sau TLS
SESSION_HOURS, CODE_MINUTES, ACCESS_MINUTES = 12, 10, 15
LOGIN_MAX_FAILS, LOCK_MINUTES = 5, 15
RETENTION_DAYS = int(os.getenv("OGK_RETENTION_DAYS", "90"))
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
EVENT_TYPES = Literal["app_start", "app_stop", "domain_query", "blocked_app", "blocked_domain",
                      "quota_warning", "locked", "unlock_request", "override_granted"]

ph = PasswordHasher()  # Argon2id


class RateLimiter:
    def __init__(self, max_calls: int, window_s: float):
        self.max, self.window, self.hits = max_calls, window_s, defaultdict(deque)

    def check(self, key: str):
        t, q = time.monotonic(), self.hits[key]
        while q and t - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max:
            raise HTTPException(429, "Quá nhiều yêu cầu, hãy thử lại sau")
        q.append(t)


limiter = RateLimiter(int(os.getenv("OGK_RATE_MAX", "60")), 60)


class Hub:
    """Các WebSocket thiết bị đang kết nối (lệnh khẩn)."""
    def __init__(self):
        self.conns: dict[int, WebSocket] = {}

    async def push(self, device_id: int, payload: dict):
        ws = self.conns.get(device_id)
        if ws:
            try:
                await ws.send_json(payload)
            except Exception:
                self.conns.pop(device_id, None)


hub = Hub()


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def ip_of(request: Request) -> str:
    return request.client.host if request.client else "?"


def purge_old(db: Session, days: int = RETENTION_DAYS) -> int:
    """Xóa dữ liệu quá hạn lưu trữ (90 ngày) – Nghị định 13/2023: hạn chế lưu trữ."""
    cut = now() - timedelta(days=days)
    n = db.execute(delete(m.Event).where(m.Event.ts < cut)).rowcount
    db.execute(delete(m.HelpRequest).where(m.HelpRequest.created_at < cut))
    db.execute(delete(m.Command).where(m.Command.created_at < cut, m.Command.delivered == True))  # noqa: E712
    db.execute(delete(m.Session).where(m.Session.expires < now()))
    db.execute(delete(m.AccessToken).where(m.AccessToken.expires < now()))
    db.commit()
    return n


async def _purge_loop():
    while True:
        with SessionLocal() as db:
            purge_old(db)
        await asyncio.sleep(86400)


@asynccontextmanager
async def lifespan(_):
    Base.metadata.create_all(engine)
    task = asyncio.create_task(_purge_loop())
    yield
    task.cancel()


app = FastAPI(title="OGK-Server", lifespan=lifespan)


# ================= phụ thuộc / xác thực =================
def parent_required(request: Request, db: Session = Depends(get_db)) -> m.Parent:
    tok = request.cookies.get(COOKIE)
    if tok:
        s = db.get(m.Session, sha(tok))
        if s and s.expires > now():
            return db.get(m.Parent, s.parent_id)
    raise HTTPException(401, "Chưa đăng nhập")


def parent_w(request: Request, p: m.Parent = Depends(parent_required)) -> m.Parent:
    """Thao tác ghi: bắt buộc CSRF double-submit."""
    c, h = request.cookies.get(CSRF_COOKIE), request.headers.get("x-csrf-token")
    if not c or not h or not secrets.compare_digest(c, h):
        raise HTTPException(403, "CSRF token không hợp lệ")
    return p


def device_from_token(db: Session, token: str) -> m.Device | None:
    at = db.get(m.AccessToken, sha(token))
    if at and at.expires > now():
        d = db.get(m.Device, at.device_id)
        if d and not d.revoked:
            return d
    return None


def device_required(authorization: str = Header(default=""), db: Session = Depends(get_db)) -> m.Device:
    if authorization.startswith("Bearer "):
        d = device_from_token(db, authorization[7:])
        if d:
            return d
    raise HTTPException(401, "Token thiết bị không hợp lệ hoặc đã hết hạn")


def own_child(db: Session, parent: m.Parent, child_id: int) -> m.Child:
    """Kiểm tra quyền sở hữu ở tầng truy vấn (chống IDOR)."""
    c = db.scalar(select(m.Child).where(m.Child.id == child_id, m.Child.parent_id == parent.id))
    if not c:
        raise HTTPException(404, "Không tìm thấy")
    return c


def audit(db: Session, request: Request | None, parent_id, child_id, action, old=None, new=None):
    db.add(m.Audit(ts=now(), parent_id=parent_id, child_id=child_id, ip=ip_of(request) if request else "",
                   action=action, old=json.dumps(old, ensure_ascii=False, default=str),
                   new=json.dumps(new, ensure_ascii=False, default=str)))


# ================= chính sách (có ký) =================
def _payload(child_id: int, version: int, policy: dict) -> str:
    return json.dumps({"child_id": child_id, "version": version, "policy": policy},
                      sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def set_policy(db: Session, child: m.Child, policy: Policy, request, actor: m.Parent | None, action: str):
    old = json.loads(child.policy_payload)["policy"] if child.policy_payload else None
    if actor:
        policy.set_by = actor.email
    new = policy.model_dump()
    child.policy_version = (child.policy_version or 0) + (1 if child.policy_payload else 0)
    child.policy_payload = _payload(child.id, child.policy_version, new)
    child.policy_sig = crypto.sign(child.policy_payload)
    audit(db, request, actor.id if actor else None, child.id, action, old, new)


async def notify_policy(db: Session, child: m.Child):
    for d in db.scalars(select(m.Device).where(m.Device.child_id == child.id, m.Device.revoked == False)):  # noqa: E712
        await hub.push(d.id, {"type": "policy_changed", "version": child.policy_version})


# ================= schemas =================
class Credentials(BaseModel):
    email: str
    password: str


class ChildIn(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    age: int = Field(10, ge=3, le=17)


class EnrollIn(BaseModel):
    code: str
    fingerprint: str
    name: str


class RefreshIn(BaseModel):
    refresh_token: str


class HeartbeatIn(BaseModel):
    policy_version: int = 0
    quota_used_sec: int = 0
    clock_skew_sec: float = 0.0
    acked: list[int] = []


class EventIn(BaseModel):
    uid: str = Field(min_length=8, max_length=64)
    ts: float
    type: EVENT_TYPES
    subject: str = Field("", max_length=100)
    duration_sec: int = Field(0, ge=0, le=86400)
    policy_id: int = 0


class EventsIn(BaseModel):
    events: list[EventIn] = Field(max_length=500)


class HelpIn(BaseModel):
    kind: Literal["more_time", "wrong_block"]
    subject: str = Field("", max_length=100)
    minutes: int = Field(0, ge=0, le=120)
    note: str = Field("", max_length=200)


class DecideIn(BaseModel):
    approve: bool
    minutes: int = Field(15, ge=1, le=120)
    reply: str = Field("", max_length=200)


class CommandIn(BaseModel):
    kind: Literal["lock", "unlock", "add_minutes"]
    minutes: int = Field(15, ge=1, le=120)


class UninstallIn(BaseModel):
    email: str
    password: str


# ================= auth phụ huynh =================
@app.post("/auth/register", status_code=201)
def register(body: Credentials, request: Request, db: Session = Depends(get_db)):
    limiter.check(f"reg:{ip_of(request)}")
    if len(body.password) < 10:  # NIST SP 800-63B: độ dài quan trọng hơn quy tắc thành phần
        raise HTTPException(422, "Mật khẩu tối thiểu 10 ký tự")
    email = body.email.strip().lower()
    if db.scalar(select(m.Parent).where(m.Parent.email == email)):
        raise HTTPException(409, "Email đã tồn tại")
    db.add(m.Parent(email=email, pw_hash=ph.hash(body.password)))
    db.commit()
    return {"ok": True}


@app.post("/auth/login")
def login(body: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    limiter.check(f"login:{ip_of(request)}")
    p = db.scalar(select(m.Parent).where(m.Parent.email == body.email.strip().lower()))
    if p and p.locked_until and p.locked_until > now():
        raise HTTPException(429, f"Tài khoản tạm khóa {LOCK_MINUTES} phút do nhập sai nhiều lần")
    try:
        if not p:
            raise VerifyMismatchError
        ph.verify(p.pw_hash, body.password)
    except VerifyMismatchError:
        if p:
            p.failed += 1
            if p.failed >= LOGIN_MAX_FAILS:
                p.failed, p.locked_until = 0, now() + timedelta(minutes=LOCK_MINUTES)
            db.commit()
        raise HTTPException(401, "Sai email hoặc mật khẩu")
    p.failed = 0
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    db.add(m.Session(token_hash=sha(tok), parent_id=p.id, expires=now() + timedelta(hours=SESSION_HOURS)))
    db.commit()
    age = SESSION_HOURS * 3600
    response.set_cookie(COOKIE, tok, httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=age)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=COOKIE_SECURE, samesite="lax", max_age=age)
    return {"ok": True}


@app.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    tok = request.cookies.get(COOKIE)
    if tok and (s := db.get(m.Session, sha(tok))):
        db.delete(s)  # hủy phiên phía máy chủ
        db.commit()
    response.delete_cookie(COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    return {"ok": True}


# ================= trẻ / thiết bị / chính sách (phụ huynh) =================
@app.post("/children", status_code=201)
def add_child(body: ChildIn, request: Request, p: m.Parent = Depends(parent_w), db: Session = Depends(get_db)):
    c = m.Child(parent_id=p.id, name=body.name.strip(), age=body.age, policy_version=1)
    db.add(c)
    db.flush()
    set_policy(db, c, default_policy(body.age), request, p, "child_created")
    db.commit()
    return {"id": c.id, "name": c.name}


@app.get("/children")
def list_children(p: m.Parent = Depends(parent_required), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.Child).where(m.Child.parent_id == p.id)).all()
    return [{"id": c.id, "name": c.name, "age": c.age, "policy_version": c.policy_version} for c in rows]


@app.get("/children/{child_id}/policy")
def get_child_policy(child_id: int, p: m.Parent = Depends(parent_required), db: Session = Depends(get_db)):
    c = own_child(db, p, child_id)
    return {"version": c.policy_version, "policy": json.loads(c.policy_payload)["policy"]}


@app.put("/children/{child_id}/policy")
async def put_child_policy(child_id: int, body: Policy, request: Request,
                           p: m.Parent = Depends(parent_w), db: Session = Depends(get_db)):
    c = own_child(db, p, child_id)
    set_policy(db, c, body, request, p, "policy_update")
    db.commit()
    await notify_policy(db, c)
    return {"version": c.policy_version}


@app.post("/children/{child_id}/enroll-code")
def enroll_code(child_id: int, p: m.Parent = Depends(parent_w), db: Session = Depends(get_db)):
    c = own_child(db, p, child_id)
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    t = now()
    db.add(m.EnrollCode(code=code, parent_id=p.id, child_id=c.id, created_at=t,
                        expires=t + timedelta(minutes=CODE_MINUTES)))
    db.commit()
    return {"code": code, "expires_in_sec": CODE_MINUTES * 60}


@app.get("/devices")
def list_devices(p: m.Parent = Depends(parent_required), db: Session = Depends(get_db)):
    rows = db.execute(select(m.Device, m.Child.name).join(m.Child, m.Device.child_id == m.Child.id)
                      .where(m.Child.parent_id == p.id, m.Device.revoked == False)).all()  # noqa: E712
    return [{"id": d.id, "name": d.name, "child": cn, "child_id": d.child_id, "last_seen": d.last_seen,
             "policy_version_seen": d.policy_version_seen, "quota_used_sec": d.quota_used_sec,
             "clock_skew": d.clock_skew} for d, cn in rows]


@app.delete("/devices/{device_id}")
def revoke_device(device_id: int, request: Request, p: m.Parent = Depends(parent_w), db: Session = Depends(get_db)):
    d = db.scalar(select(m.Device).join(m.Child, m.Device.child_id == m.Child.id)
                  .where(m.Device.id == device_id, m.Child.parent_id == p.id))
    if not d:
        raise HTTPException(404, "Không tìm thấy")
    d.revoked = True
    db.execute(delete(m.AccessToken).where(m.AccessToken.device_id == d.id))
    audit(db, request, p.id, d.child_id, "device_revoked", {"device": d.name}, None)
    db.commit()
    return {"ok": True}


@app.post("/children/{child_id}/commands")
async def send_command(child_id: int, body: CommandIn, request: Request,
                       p: m.Parent = Depends(parent_w), db: Session = Depends(get_db)):
    c = own_child(db, p, child_id)
    devs = db.scalars(select(m.Device).where(m.Device.child_id == c.id, m.Device.revoked == False)).all()  # noqa: E712
    cmds = []
    for d in devs:
        cmd = m.Command(device_id=d.id, kind=body.kind, minutes=body.minutes if body.kind == "add_minutes" else 0,
                        created_at=now())
        db.add(cmd)
        cmds.append((d.id, cmd))
    audit(db, request, p.id, c.id, f"command_{body.kind}", None, {"minutes": body.minutes})
    db.commit()
    for did, cmd in cmds:  # đẩy tức thời qua WebSocket; nếu offline thì heartbeat sẽ mang tới
        await hub.push(did, {"type": "command", "id": cmd.id, "kind": cmd.kind, "minutes": cmd.minutes})
    return {"sent": len(cmds)}


# ================= yêu cầu của trẻ =================
def _req_json(r: m.HelpRequest):
    return {"id": r.id, "kind": r.kind, "subject": r.subject, "minutes": r.minutes, "note": r.note,
            "status": r.status, "reply": r.reply, "created_at": r.created_at}


@app.get("/requests")
def parent_requests(status: str = "pending", p: m.Parent = Depends(parent_required), db: Session = Depends(get_db)):
    q = (select(m.HelpRequest, m.Child.name).join(m.Child, m.HelpRequest.child_id == m.Child.id)
         .where(m.Child.parent_id == p.id).order_by(m.HelpRequest.id.desc()).limit(100))
    if status != "all":
        q = q.where(m.HelpRequest.status == status)
    return [{**_req_json(r), "child": cn} for r, cn in db.execute(q)]


@app.post("/requests/{req_id}/decide")
async def decide(req_id: int, body: DecideIn, request: Request,
                 p: m.Parent = Depends(parent_w), db: Session = Depends(get_db)):
    r = db.scalar(select(m.HelpRequest).join(m.Child, m.HelpRequest.child_id == m.Child.id)
                  .where(m.HelpRequest.id == req_id, m.Child.parent_id == p.id))
    if not r or r.status != "pending":
        raise HTTPException(404, "Không tìm thấy yêu cầu đang chờ")
    r.status, r.reply, r.decided_at = ("approved" if body.approve else "denied"), body.reply, now()
    child = db.get(m.Child, r.child_id)
    pushes = []
    help_update_devices = list(db.scalars(select(m.Device.id).where(
        m.Device.child_id == child.id, m.Device.revoked == False  # noqa: E712
    )))
    if body.approve and r.kind == "more_time":
        minutes = body.minutes or r.minutes or 15
        for d in db.scalars(select(m.Device).where(m.Device.child_id == child.id, m.Device.revoked == False)):  # noqa: E712
            cmd = m.Command(device_id=d.id, kind="add_minutes", minutes=minutes, created_at=now())
            db.add(cmd)
            pushes.append((d.id, cmd))
    elif body.approve and r.kind == "wrong_block" and r.subject:
        pol = Policy(**json.loads(child.policy_payload)["policy"])
        pol.domain_rules = [x for x in pol.domain_rules if x.domain != r.subject]
        pol.domain_rules.append(DomainRule(domain=r.subject, action="allow", set_by=p.email))
        set_policy(db, child, pol, request, p, "policy_update_from_request")
    audit(db, request, p.id, child.id, "request_decided", {"id": r.id, "kind": r.kind},
          {"status": r.status, "reply": r.reply})
    db.commit()
    for did in help_update_devices:
        await hub.push(did, {"type": "help_decided", "id": r.id, "status": r.status})
    for did, cmd in pushes:
        await hub.push(did, {"type": "command", "id": cmd.id, "kind": cmd.kind, "minutes": cmd.minutes})
    if body.approve and r.kind == "wrong_block":
        await notify_policy(db, child)
    return _req_json(r)


# ================= báo cáo =================
def aggregate(db: Session, child: m.Child, days: int) -> dict:
    tz = json.loads(child.policy_payload)["policy"]["tz_offset_min"]
    since = now() - timedelta(days=days)
    daily, apps, doms, blocked = defaultdict(int), Counter(), Counter(), 0
    for e in db.scalars(select(m.Event).where(m.Event.child_id == child.id, m.Event.ts >= since)):
        if e.type == "app_stop":
            daily[(e.ts + timedelta(minutes=tz)).date().isoformat()] += e.duration_sec
            apps[crypto.dec(e.subject_enc)] += e.duration_sec
        elif e.type == "domain_query":
            doms[crypto.dec(e.subject_enc)] += 1
        elif e.type in ("blocked_app", "blocked_domain"):
            blocked += 1
    today = (now() + timedelta(minutes=tz)).date()
    series = [((today - timedelta(days=i)).isoformat()) for i in range(days - 1, -1, -1)]
    return {"daily": [{"date": d, "minutes": round(daily.get(d, 0) / 60, 1)} for d in series],
            "top_apps": [{"name": k, "minutes": round(v / 60, 1)} for k, v in apps.most_common(10)],
            "top_domains": [{"name": k, "count": v} for k, v in doms.most_common(10)],
            "blocked": blocked}


@app.get("/reports/{child_id}")
def report(child_id: int, days: int = 7, p: m.Parent = Depends(parent_required), db: Session = Depends(get_db)):
    c = own_child(db, p, child_id)
    return aggregate(db, c, max(1, min(days, 90)))


@app.get("/reports/{child_id}/export.csv")
def report_csv(child_id: int, days: int = 7, p: m.Parent = Depends(parent_required), db: Session = Depends(get_db)):
    c = own_child(db, p, child_id)
    a = aggregate(db, c, max(1, min(days, 90)))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["section", "name", "value"])
    for d in a["daily"]:
        w.writerow(["daily_minutes", d["date"], d["minutes"]])
    for x in a["top_apps"]:
        w.writerow(["app_minutes", x["name"], x["minutes"]])
    for x in a["top_domains"]:
        w.writerow(["domain_queries", x["name"], x["count"]])
    w.writerow(["blocked_total", "", a["blocked"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=report_{child_id}.csv"})


@app.get("/audit")
def parent_audit(child_id: int, p: m.Parent = Depends(parent_required), db: Session = Depends(get_db)):
    own_child(db, p, child_id)
    q = (select(m.Audit, m.Parent.email).join(m.Parent, m.Audit.parent_id == m.Parent.id, isouter=True)
         .where(m.Audit.child_id == child_id).order_by(m.Audit.id.desc()).limit(200))
    return [{"ts": a.ts, "who": em, "ip": a.ip, "action": a.action,
             "old": json.loads(a.old), "new": json.loads(a.new)} for a, em in db.execute(q)]


@app.delete("/children/{child_id}/data")
async def delete_child_data(child_id: int, request: Request, p: m.Parent = Depends(parent_w),
                            db: Session = Depends(get_db)):
    """'Xóa toàn bộ dữ liệu của con tôi': server + yêu cầu agent xóa bộ đệm."""
    c = own_child(db, p, child_id)
    n = db.execute(delete(m.Event).where(m.Event.child_id == c.id)).rowcount
    db.execute(delete(m.HelpRequest).where(m.HelpRequest.child_id == c.id))
    pushes = []
    for d in db.scalars(select(m.Device).where(m.Device.child_id == c.id, m.Device.revoked == False)):  # noqa: E712
        db.execute(delete(m.Command).where(m.Command.device_id == d.id))
        cmd = m.Command(device_id=d.id, kind="wipe_cache", created_at=now())
        db.add(cmd)
        pushes.append((d.id, cmd))
    audit(db, request, p.id, c.id, "data_deleted", {"events": n}, None)
    db.commit()
    for did, cmd in pushes:
        await hub.push(did, {"type": "command", "id": cmd.id, "kind": "wipe_cache", "minutes": 0})
    return {"deleted_events": n}


# ================= agent =================
def _issue_access(db: Session, d: m.Device) -> str:
    tok = secrets.token_urlsafe(32)
    db.add(m.AccessToken(token_hash=sha(tok), device_id=d.id, expires=now() + timedelta(minutes=ACCESS_MINUTES)))
    return tok


@app.post("/enroll")
def enroll(body: EnrollIn, request: Request, db: Session = Depends(get_db)):
    limiter.check(f"enroll:{ip_of(request)}")
    c = db.get(m.EnrollCode, body.code.strip().upper())
    if not c or c.used or c.expires < now():
        raise HTTPException(400, "Mã không hợp lệ hoặc đã hết hạn")
    c.used = True  # dùng một lần; đây là điểm ghi nhận sự đồng ý của cha mẹ (NĐ 13/2023)
    refresh = secrets.token_urlsafe(40)
    d = m.Device(child_id=c.child_id, name=body.name[:64], fingerprint=body.fingerprint[:128],
                 refresh_hash=sha(refresh), consent_parent_id=c.parent_id, enrolled_at=now())
    db.add(d)
    db.flush()
    access = _issue_access(db, d)
    audit(db, request, c.parent_id, c.child_id, "device_enrolled", None, {"device": d.name, "consent": True})
    child = db.get(m.Child, c.child_id)
    db.commit()
    return {"device_id": d.id, "token": access, "refresh_token": refresh, "expires_in": ACCESS_MINUTES * 60,
            "policy_version": child.policy_version, "server_pubkey": crypto.public_key_b64()}


@app.post("/token/refresh")
def refresh_token(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    limiter.check(f"refresh:{ip_of(request)}")
    d = db.scalar(select(m.Device).where(m.Device.refresh_hash == sha(body.refresh_token),
                                         m.Device.revoked == False))  # noqa: E712
    if not d:
        raise HTTPException(401, "Refresh token không hợp lệ hoặc thiết bị đã bị thu hồi")
    tok = _issue_access(db, d)
    db.commit()
    return {"token": tok, "expires_in": ACCESS_MINUTES * 60}


@app.post("/heartbeat")
def heartbeat(body: HeartbeatIn, d: m.Device = Depends(device_required), db: Session = Depends(get_db)):
    d.last_seen, d.policy_version_seen = now(), body.policy_version
    d.quota_used_sec, d.clock_skew = max(0, body.quota_used_sec), body.clock_skew_sec
    if body.acked:
        for c in db.scalars(select(m.Command).where(m.Command.device_id == d.id, m.Command.id.in_(body.acked))):
            c.delivered = True
    pending = db.scalars(select(m.Command).where(m.Command.device_id == d.id, m.Command.delivered == False)  # noqa: E712
                         .order_by(m.Command.id)).all()
    child = db.get(m.Child, d.child_id)
    db.commit()
    return {"policy_version": child.policy_version, "server_time": time.time(),
            "commands": [{"id": c.id, "kind": c.kind, "minutes": c.minutes} for c in pending]}


@app.get("/policy")
def device_policy(d: m.Device = Depends(device_required), db: Session = Depends(get_db)):
    c = db.get(m.Child, d.child_id)
    return {"version": c.policy_version, "payload": c.policy_payload, "sig": c.policy_sig}


@app.post("/events")
def post_events(body: EventsIn, d: m.Device = Depends(device_required), db: Session = Depends(get_db)):
    uids = [e.uid for e in body.events]
    seen = set(db.scalars(select(m.Event.uid).where(m.Event.uid.in_(uids))))
    accepted = 0
    for e in body.events:
        if e.uid in seen:
            continue  # idempotency: gửi lại lô không bị đếm hai lần
        if any(ch in e.subject for ch in "/?#& "):
            raise HTTPException(422, "subject chỉ là tên ứng dụng hoặc tên miền cấp hai, không phải URL")
        seen.add(e.uid)
        db.add(m.Event(uid=e.uid, device_id=d.id, child_id=d.child_id,
                       ts=datetime.fromtimestamp(e.ts, timezone.utc).replace(tzinfo=None), type=e.type,
                       subject_enc=crypto.enc(e.subject), duration_sec=e.duration_sec, policy_id=e.policy_id))
        accepted += 1
    db.commit()
    return {"accepted": accepted, "duplicates": len(body.events) - accepted}


@app.post("/help")
def child_help(body: HelpIn, d: m.Device = Depends(device_required), db: Session = Depends(get_db)):
    r = m.HelpRequest(child_id=d.child_id, device_id=d.id, kind=body.kind, subject=body.subject,
                      minutes=body.minutes, note=body.note, created_at=now())
    db.add(r)
    db.add(m.Event(uid=secrets.token_hex(16), device_id=d.id, child_id=d.child_id, ts=now(),
                   type="unlock_request", subject_enc=crypto.enc(body.subject or body.kind),
                   duration_sec=0, policy_id=0))
    db.commit()
    return _req_json(r)


@app.get("/help")
def child_help_list(d: m.Device = Depends(device_required), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.HelpRequest).where(m.HelpRequest.child_id == d.child_id)
                      .order_by(m.HelpRequest.id.desc()).limit(30))
    return [_req_json(r) for r in rows]


@app.get("/transparency/today")
def transparency_today(d: m.Device = Depends(device_required), db: Session = Depends(get_db)):
    """Trẻ xem cùng bộ dữ liệu mà phụ huynh xem (NT5)."""
    c = db.get(m.Child, d.child_id)
    a = aggregate(db, c, 1)
    return {"minutes_today": a["daily"][-1]["minutes"], "top_apps": a["top_apps"],
            "top_domains": a["top_domains"], "blocked": a["blocked"]}


@app.get("/transparency/audit")
def transparency_audit(d: m.Device = Depends(device_required), db: Session = Depends(get_db)):
    """Nhật ký thay đổi luật – trẻ được xem (không kèm IP)."""
    q = (select(m.Audit, m.Parent.email).join(m.Parent, m.Audit.parent_id == m.Parent.id, isouter=True)
         .where(m.Audit.child_id == d.child_id).order_by(m.Audit.id.desc()).limit(50))
    out = []
    for a, em in db.execute(q):
        old, new = json.loads(a.old), json.loads(a.new)
        old = old if isinstance(old, dict) else {}
        new = new if isinstance(new, dict) else {}
        changed = [k for k in dict.fromkeys([*old, *new]) if old.get(k) != new.get(k)]
        details = {key: new[key] for key in ("status", "reply", "minutes", "device", "events", "consent")
                   if key in new}
        if "kind" in old:
            details["kind"] = old["kind"]
        out.append({"ts": a.ts, "who": em, "action": a.action, "changed": changed, "details": details})
    return out


@app.post("/devices/uninstall")
def uninstall(body: UninstallIn, request: Request, d: m.Device = Depends(device_required),
              db: Session = Depends(get_db)):
    """Gỡ cài đặt hợp pháp: nhập mật khẩu phụ huynh trên chính máy trẻ, có ghi nhật ký."""
    limiter.check(f"uninstall:{ip_of(request)}")
    p = db.get(m.Parent, d.consent_parent_id)
    try:
        ph.verify(p.pw_hash, body.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Sai mật khẩu")
    if body.email.strip().lower() != p.email:
        raise HTTPException(401, "Sai mật khẩu")
    d.revoked = True
    db.execute(delete(m.AccessToken).where(m.AccessToken.device_id == d.id))
    audit(db, request, p.id, d.child_id, "device_uninstalled", {"device": d.name}, None)
    db.commit()
    return {"ok": True}


@app.websocket("/ws/device")
async def ws_device(ws: WebSocket):
    auth = ws.headers.get("authorization", "")
    with SessionLocal() as db:
        d = device_from_token(db, auth[7:]) if auth.startswith("Bearer ") else None
        if not d:
            await ws.close(code=4401)
            return
        did = d.id
        pending = [{"type": "command", "id": c.id, "kind": c.kind, "minutes": c.minutes}
                   for c in db.scalars(select(m.Command).where(m.Command.device_id == did,
                                                              m.Command.delivered == False))]  # noqa: E712
    await ws.accept()
    hub.conns[did] = ws
    try:
        for msg in pending:
            await ws.send_json(msg)
        while True:
            data = await ws.receive_json()
            if data.get("ack"):
                with SessionLocal() as db:
                    for c in db.scalars(select(m.Command).where(m.Command.device_id == did,
                                                               m.Command.id.in_(data["ack"]))):
                        c.delivered = True
                    db.commit()
    except WebSocketDisconnect:
        pass
    finally:
        if hub.conns.get(did) is ws:
            hub.conns.pop(did, None)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(DASHBOARD)
