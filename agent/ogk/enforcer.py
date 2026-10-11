"""F1: đếm giờ, lịch tuần, cảnh báo 10/5/1 phút, ân hạn 60s, chống chỉnh đồng hồ."""
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

WARN_LEVELS = (600, 300, 60)
GRACE_SEC = 60
IDLE_LIMIT = 300
TAMPER_SKEW = 120


class TimeSource:
    """Thời gian đáng tin: neo vào giờ máy chủ + đồng hồ đơn điệu; không bao giờ lùi (sàn 'floor')."""

    def __init__(self, cache=None, mono=time.monotonic, wall=time.time):
        self.mono, self.wall, self.cache = mono, wall, cache
        self.anchor = None  # (server_epoch, mono_at_sync)
        self.floor = cache.get("floor", 0) if cache else 0

    def sync(self, server_epoch: float):
        self.anchor = (server_epoch, self.mono())
        self.floor = server_epoch

    def now(self) -> float:
        est = self.anchor[0] + (self.mono() - self.anchor[1]) if self.anchor else self.wall()
        return max(est, self.floor)

    def skew(self) -> float:
        """Đồng hồ hệ thống lệch bao nhiêu so với thời gian đáng tin (dương = nhanh hơn)."""
        return self.wall() - self.now() if self.anchor else 0.0

    def persist(self):
        if self.cache:
            self.cache.set("floor", self.now())


@dataclass
class State:
    locked: bool = False
    reason: str = ""
    who: str = ""
    remaining_sec: int | None = None
    in_grace: bool = False


class Enforcer:
    def __init__(self, cache, ts: TimeSource, get_policy, emit, notify, idle_fn=lambda: 0, mono=time.monotonic):
        self.cache, self.ts, self.get_policy = cache, ts, get_policy
        self.emit, self.notify, self.idle_fn, self.mono = emit, notify, idle_fn, mono
        self._last = mono()
        self.grace_started = None
        self._warned: set = set()
        self._lock_emitted: set = set()
        self.expired = False          # chính sách hết hạn (mất kết nối quá N ngày)
        self.on_expiry = "open"       # open: nới giới hạn thời gian | closed: giữ chính sách cũ
        self.forced = cache.get("forced", {"on": False, "who": ""})

    # ---- lệnh từ phụ huynh ----
    def set_forced(self, on: bool, who: str = "Phụ huynh"):
        self.forced = {"on": on, "who": who}
        self.cache.set("forced", self.forced)

    def add_minutes(self, minutes: int):
        date = self._local(self.get_policy() or {}).date().isoformat()
        self.cache.add_extra(date, minutes * 60)
        self.grace_started = None

    # ---- nội bộ ----
    def _local(self, pol) -> datetime:
        off = pol.get("tz_offset_min", 420)
        return datetime.fromtimestamp(self.ts.now(), timezone.utc) + timedelta(minutes=off)

    def tick(self) -> State:
        mono = self.mono()
        dt = min(max(mono - self._last, 0.0), 5.0)  # đồng hồ đơn điệu; giới hạn khi máy ngủ
        self._last = mono
        pol = self.get_policy()
        if not pol:
            return State()
        ldt = self._local(pol)
        date, wd = ldt.date().isoformat(), ldt.weekday()
        slot = ldt.hour * 2 + ldt.minute // 30
        limit = (pol["quota_min_weekend"] if wd >= 5 else pol["quota_min_weekday"]) * 60 + self.cache.extra(date)

        if self.expired and self.on_expiry == "open":
            return State()
        if self.forced["on"]:
            return State(True, "Phụ huynh đã khóa máy", self.forced["who"], None)
        if pol["schedule"][wd][slot] == "0":
            return State(True, "Ngoài khung giờ được phép sử dụng", pol.get("set_by", ""), None)

        quota_locked = self.cache.used(date) >= limit and self.grace_started is not None \
            and mono - self.grace_started >= GRACE_SEC
        if not quota_locked and self.idle_fn() < IDLE_LIMIT:
            self.cache.add_used(date, dt)  # chỉ đếm khi không khóa và có thao tác gần đây
        remaining = int(limit - self.cache.used(date))

        if remaining <= 0:
            if self.grace_started is None:
                self.grace_started = mono
                self.notify("time", "Hết giờ", "Con còn 60 giây để lưu bài.", pol.get("set_by", ""))
            if mono - self.grace_started >= GRACE_SEC:
                if date not in self._lock_emitted:
                    self._lock_emitted.add(date)
                    self.emit("locked", "quota", 0)
                return State(True, "Đã hết hạn mức thời gian trong ngày", pol.get("set_by", ""), 0)
            return State(False, "", "", 0, in_grace=True)

        self.grace_started = None
        hit = [lv for lv in WARN_LEVELS if remaining <= lv]
        if hit and (date, min(hit)) not in self._warned:
            lv = min(hit)
            self._warned.update((date, x) for x in hit)
            self.notify("time", "Sắp hết giờ", f"Còn khoảng {lv // 60} phút.", pol.get("set_by", ""))
            self.emit("quota_warning", f"{lv // 60}min", 0)
        return State(False, "", "", remaining)
