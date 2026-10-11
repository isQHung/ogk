"""Kho dữ liệu cục bộ: chính sách gần nhất, hàng đợi sự kiện, bộ đếm sử dụng."""
import json
import sqlite3
import threading
import uuid


class Cache:
    def __init__(self, path):
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS events(uid TEXT PRIMARY KEY, body TEXT);
            CREATE TABLE IF NOT EXISTS usage(date TEXT PRIMARY KEY, used REAL DEFAULT 0, extra INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS applied(id INTEGER PRIMARY KEY);
            """)

    def get(self, k, default=None):
        with self.lock:
            r = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else default

    def set(self, k, v):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO kv VALUES(?,?)", (k, json.dumps(v)))

    # --- sự kiện (hàng đợi ngoại tuyến, có khóa chống trùng) ---
    def enqueue_event(self, type_, subject, duration, policy_id, ts) -> str:
        uid = uuid.uuid4().hex
        body = {"uid": uid, "ts": ts, "type": type_, "subject": subject,
                "duration_sec": int(duration), "policy_id": policy_id}
        with self.lock:
            self.db.execute("INSERT INTO events VALUES(?,?)", (uid, json.dumps(body)))
        return uid

    def pending_events(self, limit=200):
        with self.lock:
            rows = self.db.execute("SELECT body FROM events LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def drop_events(self, uids):
        with self.lock:
            self.db.executemany("DELETE FROM events WHERE uid=?", [(u,) for u in uids])

    def wipe_events(self):
        with self.lock:
            self.db.execute("DELETE FROM events")

    # --- bộ đếm sử dụng theo ngày ---
    def add_used(self, date, sec):
        with self.lock:
            self.db.execute("INSERT INTO usage(date,used) VALUES(?,?) ON CONFLICT(date) DO UPDATE SET used=used+?",
                            (date, sec, sec))

    def used(self, date) -> float:
        with self.lock:
            r = self.db.execute("SELECT used FROM usage WHERE date=?", (date,)).fetchone()
        return r[0] if r else 0.0

    def add_extra(self, date, sec):
        with self.lock:
            self.db.execute("INSERT INTO usage(date,extra) VALUES(?,?) ON CONFLICT(date) DO UPDATE SET extra=extra+?",
                            (date, sec, sec))

    def extra(self, date) -> int:
        with self.lock:
            r = self.db.execute("SELECT extra FROM usage WHERE date=?", (date,)).fetchone()
        return r[0] if r else 0

    # --- lệnh đã áp dụng (chống áp hai lần) ---
    def applied(self, cid) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1 FROM applied WHERE id=?", (cid,)).fetchone() is not None

    def mark_applied(self, cid):
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO applied VALUES(?)", (cid,))
