import json

import httpx

from .verify import verify_sig


class PolicyRejected(Exception):
    pass


class DeviceRevoked(Exception):
    pass


class ServerClient:
    def __init__(self, cache):
        self.cache = cache

    @property
    def conn(self):
        return self.cache.get("conn")

    def enroll(self, server, code, fingerprint, name, ca_cert=None):
        r = httpx.post(f"{server}/enroll", timeout=10, verify=ca_cert or True,
                       json={"code": code, "fingerprint": fingerprint, "name": name})
        r.raise_for_status()
        j = r.json()
        self.cache.set("conn", {"server": server, "ca": ca_cert, "device_id": j["device_id"],
                                "token": j["token"], "refresh": j["refresh_token"], "pubkey": j["server_pubkey"]})
        return j

    def refresh_access(self):
        conn = self.conn
        with httpx.Client(base_url=conn["server"], verify=conn.get("ca") or True, timeout=10) as c:
            r = c.post("/token/refresh", json={"refresh_token": conn["refresh"]})
        if r.status_code == 401:
            raise DeviceRevoked()
        r.raise_for_status()
        conn["token"] = r.json()["token"]
        self.cache.set("conn", conn)
        return conn["token"]

    def request(self, method, path, **kw):
        conn = self.conn
        if not conn:
            raise RuntimeError("Chưa ghép đôi")
        for attempt in (0, 1):
            with httpx.Client(base_url=conn["server"], verify=conn.get("ca") or True, timeout=10) as c:
                r = c.request(method, path, headers={"Authorization": f"Bearer {conn['token']}"}, **kw)
            if r.status_code == 401 and attempt == 0:
                conn["token"] = self.refresh_access()  # có thể ném DeviceRevoked
                continue
            r.raise_for_status()
            return r.json()

    # --- API ---
    def heartbeat(self, policy_version, used_sec, skew, acked):
        return self.request("POST", "/heartbeat", json={
            "policy_version": policy_version, "quota_used_sec": int(used_sec),
            "clock_skew_sec": skew, "acked": list(acked)})

    def fetch_policy(self, current_version):
        """Tải + xác minh chữ ký + từ chối bản cũ hơn (chống replay/downgrade)."""
        j = self.request("GET", "/policy")
        if not verify_sig(self.conn["pubkey"], j["payload"], j["sig"]):
            raise PolicyRejected("chữ ký chính sách không hợp lệ")
        data = json.loads(j["payload"])
        if data["version"] < current_version:
            raise PolicyRejected("phiên bản chính sách cũ hơn bản đang dùng")
        return data, j["payload"], j["sig"]

    def post_events(self, events):
        return self.request("POST", "/events", json={"events": events})

    def post_help(self, kind, subject="", minutes=0, note=""):
        return self.request("POST", "/help", json={"kind": kind, "subject": subject, "minutes": minutes, "note": note})

    def list_help(self):
        return self.request("GET", "/help")

    def today(self):
        return self.request("GET", "/transparency/today")

    def audit_log(self):
        return self.request("GET", "/transparency/audit")

    def uninstall(self, email, password):
        return self.request("POST", "/devices/uninstall", json={"email": email, "password": password})
