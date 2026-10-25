"""Ghép các thành phần agent: enforcer + DNS proxy + app controller + đồng bộ + lệnh khẩn."""
import asyncio
import json
import secrets
import ssl
import threading
import time
from collections import deque

import httpx

from . import config, winadapter
from .appctl import AppController
from .cache import Cache
from .client import DeviceRevoked, PolicyRejected, ServerClient
from .dnsproxy import FilterResolver, load_categories, load_list, start_block_page, start_dns
from .domains import sld
from .enforcer import TAMPER_SKEW, Enforcer, State, TimeSource
from .localapi import LocalAPI
from .verify import verify_sig


def _ws_connect(url, headers, **kw):
    try:
        from websockets.asyncio.client import connect
        return connect(url, additional_headers=headers, **kw)
    except ImportError:  # websockets < 14
        from websockets import connect
        return connect(url, extra_headers=headers, **kw)


class Runner:
    def __init__(self, home=None, dns_port=53, dns_bind="127.0.0.1", block_port=80, api_port=47800,
                 upstream=("1.1.1.1", 53), interval=60.0, scan_interval=2.0, expiry_days=7, on_expiry="open",
                 enforce_lock=True, system_dns=False, require_tray=False, tray_timeout=180.0,
                 adapter=winadapter, start_dns_servers=True):
        self.home = home or config.home()
        self.dns_port, self.dns_bind, self.block_port, self.api_port = dns_port, dns_bind, block_port, api_port
        self.upstream, self.interval, self.scan_interval = upstream, interval, scan_interval
        self.expiry_days, self.on_expiry, self.enforce_lock = expiry_days, on_expiry, enforce_lock
        self.system_dns, self.require_tray, self.tray_timeout = system_dns, require_tray, tray_timeout
        self.adapter, self.start_dns_servers = adapter, start_dns_servers
        self.stop_evt, self.sync_now = threading.Event(), threading.Event()
        self.notes, self.notes_lock = deque(maxlen=50), threading.Lock()
        self.acks: set = set()
        self.policy, self.policy_version = None, 0
        self.state, self.revoked, self.suspended = State(), False, False
        self.rejected_policies = 0
        self._dq, self._db, self._last_tamper = {}, {}, -1e9
        self.last_tray_seen = time.monotonic()
        self.servers, self.threads = [], []

    # ---------- khởi tạo ----------
    def mono(self):
        return time.monotonic()

    def get_policy(self):
        return None if (self.suspended or self.revoked) else self.policy

    def start(self):
        self.adapter.protect_home(self.home)
        self.cache = Cache(self.home / "agent.db")
        self.client = ServerClient(self.cache)
        if not self.cache.get("conn"):
            raise SystemExit("Chưa ghép đôi. Chạy: agent.py enroll --server URL --code MÃ")
        self._load_policy()
        self.ts = TimeSource(self.cache)
        self.enforcer = Enforcer(self.cache, self.ts, self.get_policy, self.emit, self.notify,
                                 idle_fn=self.adapter.idle_seconds)
        self.enforcer.on_expiry = self.on_expiry
        self.apps = AppController(self.get_policy, self.emit, self.notify, visible=self.adapter.visible_pids)
        cats = load_categories()
        exempt = load_list(config.DATA_DIR / "exempt.txt")
        doh = load_list(config.DATA_DIR / "doh_endpoints.txt")
        self.resolver = FilterResolver(self.get_policy, cats, exempt, doh, self.upstream,
                                       on_query=self.on_query, on_block=self.on_block)
        self.token = secrets.token_urlsafe(24)
        (self.home / "local_token").write_text(self.token)
        self.api = LocalAPI(self, self.api_port, self.token)
        self.api.start()
        if self.start_dns_servers:
            self.servers += start_dns(self.resolver, self.dns_bind, self.dns_port)
            try:
                self.servers.append(start_block_page(self.resolver.decide, self.block_port))
            except OSError as e:
                print("Không mở được cổng trang giải thích:", e)
            if self.system_dns:
                self.adapter.set_system_dns_to_local()
                self.adapter.block_external_dns(self.upstream[0])
        # NT1: trẻ luôn biết mình đang được hỗ trợ
        self.notify("startup", "OpenGuard Kids đang hỗ trợ máy này",
                    "Phụ huynh cài công cụ này để đồng hành cùng con. Biểu tượng trên khay hệ thống luôn hiển thị.", "")
        for fn in (self._tick_loop, self._sync_loop, self._scan_loop, lambda: asyncio.run(self._ws_main())):
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.stop_evt.set()
        for s in self.servers:
            try:
                (s.stop if hasattr(s, "stop") else s.shutdown)()
            except Exception:
                pass
        if getattr(self, "api", None):
            self.api.stop()
        if self.system_dns:  # để không làm mất Internet của trẻ khi agent dừng
            self.adapter.restore_system_dns()
            self.adapter.unblock_external_dns()

    def _load_policy(self):
        conn, pp = self.cache.get("conn"), self.cache.get("policy_signed")
        if conn and pp and verify_sig(conn["pubkey"], pp["payload"], pp["sig"]):  # xác minh lại mỗi lần nạp
            d = json.loads(pp["payload"])
            self.policy, self.policy_version = d["policy"], d["version"]

    # ---------- sự kiện / thông báo ----------
    def emit(self, type_, subject, duration=0):
        self.cache.enqueue_event(type_, subject, duration, self.policy_version, self.ts.now())

    def notify(self, kind, title, text, who=""):
        with self.notes_lock:
            self.notes.append({"kind": kind, "title": title, "text": text, "who": who})

    def drain_notes(self):
        with self.notes_lock:
            out = list(self.notes)
            self.notes.clear()
        return out

    def on_query(self, name):
        s, t = sld(name), self.mono()
        if t - self._dq.get(s, -1e9) > 60:
            self._dq[s] = t
            self.emit("domain_query", s)

    def on_block(self, name, d):
        s, t = sld(name), self.mono()
        if t - self._db.get(s, -1e9) > 30:
            self._db[s] = t
            self.emit("blocked_domain", s)
            if d.action == "block":
                self.notify("domain", "Trang web bị chặn", f"{s}: {d.reason}", d.who)

    # ---------- đồng bộ ----------
    def apply_command(self, c):
        cid = c["id"]
        if not self.cache.applied(cid):
            k = c["kind"]
            if k == "lock":
                self.enforcer.set_forced(True, "Phụ huynh")
                self.emit("locked", "parent", 0)
            elif k == "unlock":
                self.enforcer.set_forced(False)
            elif k == "add_minutes":
                self.enforcer.add_minutes(c["minutes"])
                self.emit("override_granted", "parent", c["minutes"] * 60)
                self.notify("time", "Được cộng thêm giờ", f"Phụ huynh cộng thêm {c['minutes']} phút.", "")
            elif k == "wipe_cache":
                self.cache.wipe_events()
            self.cache.mark_applied(cid)
        self.acks.add(cid)

    def fetch_policy(self):
        try:
            data, payload, sig = self.client.fetch_policy(self.policy_version)
        except PolicyRejected as e:
            self.rejected_policies += 1
            print("Từ chối chính sách:", e)
            return False
        self.cache.set("policy_signed", {"payload": payload, "sig": sig})
        self.policy, self.policy_version = data["policy"], data["version"]
        self.adapter.flush_dns() # flush dns after update new policy (clear window dns cache )
        self.notify("policy", "Luật đã được cập nhật", f"Phiên bản {self.policy_version}.", self.policy.get("set_by", ""))
        return True

    def flush_events(self):
        evs = self.cache.pending_events(200)
        if not evs:
            return
        try:
            self.client.post_events(evs)
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 422:
                raise
        self.cache.drop_events([e["uid"] for e in evs])  # 422 = lô hỏng, bỏ để không kẹt hàng đợi

    def sync_once(self):
        skew = self.ts.skew()
        if abs(skew) > TAMPER_SKEW and self.mono() - self._last_tamper > 600:
            self._last_tamper = self.mono()
            self.emit("quota_warning", "clock_tamper", 0)
        date_used = self.enforcer.cache.used(self.enforcer._local(self.policy or {}).date().isoformat())
        sent = set(self.acks)
        try:
            hb = self.client.heartbeat(self.policy_version, date_used, skew, sent)
        except DeviceRevoked:
            self.revoked = True
            self.notify("revoked", "Máy này đã được gỡ khỏi OpenGuard Kids", "Các hạn chế đã dừng.", "")
            self.stop_evt.set()
            raise
        self.acks -= sent
        self.ts.sync(hb["server_time"])
        self.cache.set("last_contact", self.ts.now())
        for c in hb["commands"]:
            self.apply_command(c)
        if hb["policy_version"] != self.policy_version:
            self.fetch_policy()
        self.flush_events()

    # ---------- vòng lặp ----------
    def _tick_loop(self):
        last_lock = last_persist = -1e9
        while not self.stop_evt.wait(1.0):
            try:
                m = self.mono()
                self.suspended = self.require_tray and m - self.last_tray_seen > self.tray_timeout
                lc = self.cache.get("last_contact")
                self.enforcer.expired = bool(lc) and self.ts.now() - lc > self.expiry_days * 86400
                self.state = self.enforcer.tick()
                if self.state.locked and self.enforce_lock and m - last_lock >= 5:
                    last_lock = m
                    self.adapter.lock_session()
                if m - last_persist > 60:
                    last_persist = m
                    self.ts.persist()
            except Exception as e:
                print("tick lỗi:", e)

    def _sync_loop(self):
        while not self.stop_evt.is_set():
            try:
                self.sync_once()
            except DeviceRevoked:
                return
            except Exception as e:  # mất mạng/server: tiếp tục dùng chính sách đệm, sự kiện xếp hàng
                print("Không đồng bộ được:", e)
            self.sync_now.wait(self.interval)
            self.sync_now.clear()

    def _scan_loop(self):
        while not self.stop_evt.wait(self.scan_interval):
            try:
                self.apps.scan()
            except Exception as e:
                print("scan lỗi:", e)

    async def _ws_main(self):
        while not self.stop_evt.is_set():
            conn = self.cache.get("conn")
            url = conn["server"].replace("http", "ws", 1) + "/ws/device"
            kw = {}
            if url.startswith("wss") and conn.get("ca"):
                kw["ssl"] = ssl.create_default_context(cafile=conn["ca"])
            try:
                async with _ws_connect(url, {"Authorization": f"Bearer {conn['token']}"}, **kw) as ws:
                    self.api.broadcast({"type": "refresh_help"})
                    while not self.stop_evt.is_set():
                        try:
                            raw = await asyncio.wait_for(ws.recv(), 1.0)
                        except asyncio.TimeoutError:
                            continue
                        msg = json.loads(raw)
                        if msg.get("type") == "command":
                            self.apply_command(msg)
                            await ws.send(json.dumps({"ack": [msg["id"]]}))
                        elif msg.get("type") == "policy_changed":
                            self.sync_now.set()
                        elif msg.get("type") == "help_decided":
                            self.api.broadcast(msg)
            except Exception:
                try:
                    await asyncio.to_thread(self.client.refresh_access)
                except Exception:
                    pass
                await asyncio.sleep(3)

    # ---------- cho tray / local API ----------
    def state_json(self):
        st, lc = self.state, self.cache.get("last_contact")
        return {"locked": st.locked, "reason": st.reason, "who": st.who, "remaining_sec": st.remaining_sec,
                "in_grace": st.in_grace, "policy_version": self.policy_version,
                "online": bool(lc) and self.ts.now() - lc < self.interval * 3, "expired": self.enforcer.expired,
                "suspended": self.suspended, "revoked": self.revoked, "notes": self.drain_notes()}
