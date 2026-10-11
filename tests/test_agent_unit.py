"""Unit test phía agent (không cần Windows)."""
import csv
import hashlib
from datetime import datetime, timezone

import pytest
from dnslib import A, QTYPE, RCODE, RR, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from ogk import config
from ogk.appctl import AppController
from ogk.cache import Cache
from ogk.dnsproxy import (FilterResolver, decide_domain, load_categories, load_list, start_dns)
from ogk.domains import sld
from ogk.enforcer import TAMPER_SKEW, Enforcer, TimeSource
from ogk.verify import verify_sig

START = datetime(2026, 9, 30, 5, 0, tzinfo=timezone.utc).timestamp()  # thứ Tư 12:00 giờ VN
ALL = ["1" * 48] * 7


def policy(**kw):
    p = {"tz_offset_min": 420, "quota_min_weekday": 90, "quota_min_weekend": 120, "schedule": ALL,
         "app_mode": "blocklist", "app_rules": [], "domain_rules": [], "blocked_categories": ["social", "inappropriate"],
         "block_uncategorized": False, "safesearch": True, "set_by": "ba@x.vn"}
    p.update(kw)
    return p


class Clock:
    def __init__(self):
        self.m, self.w = 1000.0, START

    def mono(self): return self.m
    def wall(self): return self.w

    def adv(self, s):
        self.m += s
        self.w += s


@pytest.fixture()
def env(tmp_path):
    clk, cache = Clock(), Cache(tmp_path / "c.db")
    ts = TimeSource(cache, clk.mono, clk.wall)
    ts.sync(clk.w)
    box = {"pol": policy(), "idle": 0, "events": [], "notes": []}
    enf = Enforcer(cache, ts, lambda: box["pol"], lambda *a: box["events"].append(a),
                   lambda kind, title, text, who="": box["notes"].append((title, text)),
                   idle_fn=lambda: box["idle"], mono=clk.mono)
    return clk, cache, ts, enf, box


def run(clk, enf, n):
    st = None
    for _ in range(n):
        clk.adv(1)
        st = enf.tick()
    return st


# ---------- F1 ----------
def test_quota_3min_locks_after_grace(env):
    clk, cache, ts, enf, box = env
    box["pol"] = policy(quota_min_weekday=3)
    assert not run(clk, enf, 179).locked
    st = run(clk, enf, 2)
    assert st.in_grace and not st.locked  # hết giờ -> ân hạn 60s để lưu bài
    assert not run(clk, enf, 58).locked
    st = run(clk, enf, 2)
    assert st.locked and "hạn mức" in st.reason and ("locked", "quota", 0) in box["events"]


def test_schedule_locks_outside_window(env):
    clk, cache, ts, enf, box = env
    sched = ["1" * 48] * 7
    sched[2] = "1" * 24 + "0" * 24  # thứ Tư: khóa từ 12:00
    box["pol"] = policy(schedule=sched)
    st = run(clk, enf, 1)
    assert st.locked and "khung giờ" in st.reason and st.who == "ba@x.vn"


def test_weekend_quota_used_on_saturday(env):
    clk, cache, ts, enf, box = env
    clk.w += 3 * 86400  # thứ Bảy
    ts.sync(clk.w)
    box["pol"] = policy(quota_min_weekday=1, quota_min_weekend=100)
    assert run(clk, enf, 120).remaining_sec == 100 * 60 - 120


def test_idle_time_not_counted(env):
    clk, cache, ts, enf, box = env
    box["idle"] = 400
    run(clk, enf, 30)
    assert cache.used("2026-09-30") == 0


def test_clock_rewind_does_not_add_quota_and_is_detected(env):
    clk, cache, ts, enf, box = env
    box["pol"] = policy(quota_min_weekday=10)
    run(clk, enf, 100)
    before = enf.tick().remaining_sec
    clk.w -= 3 * 3600  # lùi đồng hồ hệ thống 3 giờ
    st = run(clk, enf, 1)
    assert st.remaining_sec <= before  # quota KHÔNG tăng
    assert abs(ts.skew()) > TAMPER_SKEW  # runner sẽ ghi sự kiện clock_tamper


def test_time_floor_survives_restart(env, tmp_path):
    clk, cache, ts, enf, box = env
    ts.persist()
    clk2 = Clock()
    clk2.w = START - 3 * 3600  # khởi động lại sau khi lùi giờ
    assert TimeSource(cache, clk2.mono, clk2.wall).now() >= START


def test_warnings_10_5_1_once_each(env):
    clk, cache, ts, enf, box = env
    box["pol"] = policy(quota_min_weekday=12)
    run(clk, enf, 12 * 60)
    warns = [e[1] for e in box["events"] if e[0] == "quota_warning"]
    assert warns == ["10min", "5min", "1min"]
    assert sum(1 for t, _ in box["notes"] if t == "Sắp hết giờ") == 3


def test_add_minutes_ends_grace_and_forced_lock(env):
    clk, cache, ts, enf, box = env
    box["pol"] = policy(quota_min_weekday=1)
    assert run(clk, enf, 70).in_grace
    enf.add_minutes(15)
    assert run(clk, enf, 1).remaining_sec > 0
    enf.set_forced(True)
    assert run(clk, enf, 1).locked
    enf.set_forced(False)
    assert not run(clk, enf, 1).locked


def test_policy_expiry_modes(env):
    clk, cache, ts, enf, box = env
    box["pol"] = policy(schedule=["0" * 48] * 7)
    enf.expired, enf.on_expiry = True, "open"
    assert not run(clk, enf, 1).locked
    enf.on_expiry = "closed"
    assert run(clk, enf, 1).locked


# ---------- F2: DNS ----------
def test_sld():
    assert sld("a.b.example.com") == "example.com" and sld("x.hcmus.edu.vn") == "hcmus.edu.vn"
    assert sld("localhost") == "localhost"


def test_decide_domain_rules():
    cats, exempt, doh = load_categories(), load_list(config.DATA_DIR / "exempt.txt"), load_list(config.DATA_DIR / "doh_endpoints.txt")
    pol = policy(domain_rules=[{"domain": "m.facebook.com", "action": "allow", "set_by": "ba"},
                               {"domain": "vnexpress.net", "action": "block", "set_by": "ba"}])
    d = lambda h: decide_domain(pol, cats, exempt, doh, h)
    assert d("www.facebook.com").action == "block"           # tên miền con của nhóm bị chặn
    assert d("m.facebook.com").action == "allow"             # luật cụ thể thắng nhóm
    assert d("vnexpress.net").action == "block" and "Phụ huynh" in d("vnexpress.net").reason
    assert d("hcmus.edu.vn").action == "allow"
    assert d("use-application-dns.net").action == "nx" and d("dns.google").action == "nx"
    assert d("tongdai111.vn").action == "allow"              # danh sách miễn chặn (NT6)
    pol["block_uncategorized"] = True
    assert d("some-random-site.vn").action == "block"
    assert d("tongdai111.vn").action == "allow"


def test_block_and_false_positive_rates_on_test_set():
    """Bộ kiểm thử: ≥95% chặn đúng, 0 dương tính giả trên 20 miền giáo dục."""
    cats = load_categories()
    doh = load_list(config.DATA_DIR / "doh_endpoints.txt")
    by = lambda c: [d for d, k in cats.items() if k == c]
    edu, social, games, sim = by("education")[:20], by("social")[:8], by("games")[:7], by("inappropriate")
    pol = policy(blocked_categories=["social", "games", "inappropriate"])
    blocked = lambda h: decide_domain(pol, cats, [], doh, h).action in ("block", "nx")
    assert len(cats) >= 200
    must_block = social + games + doh[:5] + sim
    assert len(must_block) == 30
    rate = sum(blocked(h) for h in must_block) / len(must_block)
    assert rate >= 0.95
    assert [h for h in edu if blocked(h)] == []  # 0 dương tính giả
    assert not any(blocked("www." + h) for h in edu)


class FakeUpstream(BaseResolver):
    def resolve(self, request, handler):
        r, n = request.reply(), str(request.q.qname).rstrip(".")
        ip = {"forcesafesearch.google.com": "1.2.3.4"}.get(n, "93.184.216.34")
        if QTYPE[request.q.qtype] == "A":
            r.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=60))
        return r


@pytest.fixture()
def dns(free_ports):
    up_port, px_port = free_ports(2)
    up = DNSServer(FakeUpstream(), port=up_port, address="127.0.0.1", logger=DNSLogger(log="", prefix=False))
    up.start_thread()
    seen = {"q": [], "b": []}
    res = FilterResolver(lambda: policy(), load_categories(), [], load_list(config.DATA_DIR / "doh_endpoints.txt"),
                         ("127.0.0.1", up_port), on_query=seen["q"].append, on_block=lambda n, d: seen["b"].append((n, d.action)))
    servers = start_dns(res, "127.0.0.1", px_port)
    yield px_port, seen
    for s in servers + [up]:
        s.stop()


def ask(port, name, qtype="A"):
    return DNSRecord.parse(DNSRecord.question(name, qtype).send("127.0.0.1", port, timeout=3))


def test_dns_proxy_block_allow_safesearch_doh(dns):
    port, seen = dns
    r = ask(port, "www.facebook.com")
    assert str(r.rr[0].rdata) == "127.0.0.1"                      # trỏ về trang giải thích cục bộ
    assert ask(port, "www.facebook.com", "AAAA").rr == []          # không để lọt qua IPv6
    r = ask(port, "hcmus.edu.vn")
    assert str(r.rr[0].rdata) == "93.184.216.34" and "hcmus.edu.vn" in seen["q"]
    r = ask(port, "www.google.com")                                # SafeSearch: CNAME + A của forcesafesearch
    assert [QTYPE[x.rtype] for x in r.rr] == ["CNAME", "A"] and str(r.rr[0].rdata).rstrip(".") == "forcesafesearch.google.com"
    assert str(r.rr[1].rdata) == "1.2.3.4"
    assert ask(port, "use-application-dns.net").header.rcode == RCODE.NXDOMAIN
    assert ask(port, "dns.google").header.rcode == RCODE.NXDOMAIN
    assert ("www.facebook.com", "block") in seen["b"]


# ---------- F2: ứng dụng ----------
def make_app(tmp_path, name, content):
    p = tmp_path / name
    p.write_bytes(content)
    return str(p), hashlib.sha256(content).hexdigest()


def controller(pol, procs, killed, events, notes, visible=None, protected=()):
    return AppController(lambda: pol, lambda *a: events.append(a), lambda *a: notes.append(a),
                         procs=lambda: procs, visible=lambda: visible, kill=killed.append, protected=protected)


def test_renamed_executable_still_blocked_by_hash(tmp_path):
    exe, sha = make_app(tmp_path, "game.exe", b"NOTEPAD-BINARY")  # notepad.exe đã đổi tên thành game.exe
    other, _ = make_app(tmp_path, "notepad.exe", b"ANOTHER-BINARY")
    pol = policy(app_rules=[{"name": "notepad.exe", "sha256": sha, "action": "block", "set_by": "Ba"}])
    killed, events, notes = [], [], []
    procs = [{"pid": 10, "name": "game.exe", "exe": exe}, {"pid": 11, "name": "notepad.exe", "exe": other}]
    controller(pol, procs, killed, events, notes).scan()
    assert killed == [10]                                   # nhận đúng theo băm, không theo tên
    assert ("blocked_app", "game.exe", 0) in events
    assert notes[0][0] == "app" and "Ba" == notes[0][3]     # giải thích + ai đặt luật


def test_block_by_name_when_no_hash_and_allow_override(tmp_path):
    exe, _ = make_app(tmp_path, "x.exe", b"1")
    pol = policy(app_rules=[{"name": "x.exe", "action": "block"}])
    killed = []
    controller(pol, [{"pid": 5, "name": "X.EXE", "exe": exe}], killed, [], []).scan()
    assert killed == [5]


def test_allowlist_mode_spares_protected_and_allowed(tmp_path):
    ok, ok_sha = make_app(tmp_path, "ok.exe", b"OK")
    bad, _ = make_app(tmp_path, "bad.exe", b"BAD")
    pol = policy(app_mode="allowlist", app_rules=[{"name": "ok.exe", "sha256": ok_sha, "action": "allow"}])
    killed = []
    procs = [{"pid": 1, "name": "ok.exe", "exe": ok}, {"pid": 2, "name": "bad.exe", "exe": bad},
             {"pid": 3, "name": "svc", "exe": "/usr/bin/svc"}]
    controller(pol, procs, killed, [], [], protected=("/usr/",)).scan()
    assert killed == [2]


def test_app_usage_events_start_stop(tmp_path):
    exe, _ = make_app(tmp_path, "mc.exe", b"MC")
    procs, events, clk = [{"pid": 7, "name": "mc.exe", "exe": exe}], [], Clock()
    c = AppController(lambda: policy(), lambda *a: events.append(a), lambda *a: None, procs=lambda: procs,
                      visible=lambda: {7}, kill=lambda p: None, protected=(), mono=clk.mono)
    c.scan()
    clk.adv(90)
    procs.clear()
    c.scan()
    assert events == [("app_start", "mc.exe", 0), ("app_stop", "mc.exe", 90.0)]


# ---------- cache / chữ ký ----------
def test_event_queue_roundtrip(tmp_path):
    c = Cache(tmp_path / "q.db")
    u = [c.enqueue_event("app_stop", "a", 5, 1, 1.0), c.enqueue_event("domain_query", "b.com", 0, 1, 2.0)]
    assert len(set(u)) == 2 and len(c.pending_events()) == 2
    c.drop_events(u[:1])
    assert [e["uid"] for e in c.pending_events()] == u[1:]
    c.wipe_events()
    assert c.pending_events() == []


def test_verify_sig_rejects_tampering():
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    pub = base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    sig = base64.b64encode(k.sign(b"payload")).decode()
    assert verify_sig(pub, "payload", sig) and not verify_sig(pub, "payload!", sig) and not verify_sig(pub, "payload", "AAAA")
