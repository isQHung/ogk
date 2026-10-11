from typing import Literal

from pydantic import BaseModel, Field, field_validator

CATEGORIES = ("education", "entertainment", "social", "games", "inappropriate")
DEFAULT_SCHEDULE = "0" * 12 + "1" * 31 + "0" * 5  # 06:00–21:30, bước 30 phút


class AppRule(BaseModel):
    name: str = ""
    sha256: str = ""
    action: Literal["block", "allow"] = "block"
    set_by: str = ""


class DomainRule(BaseModel):
    domain: str
    action: Literal["block", "allow"]
    set_by: str = ""


class Policy(BaseModel):
    tz_offset_min: int = Field(420, ge=-720, le=840)
    quota_min_weekday: int = Field(90, ge=0, le=1440)
    quota_min_weekend: int = Field(120, ge=0, le=1440)
    schedule: list[str] = [DEFAULT_SCHEDULE] * 7  # T2..CN, mỗi ngày 48 ký tự '0'/'1'
    app_mode: Literal["blocklist", "allowlist"] = "blocklist"
    app_rules: list[AppRule] = []
    domain_rules: list[DomainRule] = []
    blocked_categories: list[str] = ["social", "inappropriate"]
    block_uncategorized: bool = False
    safesearch: bool = True
    set_by: str = ""

    @field_validator("schedule")
    @classmethod
    def _sched(cls, v):
        if len(v) != 7 or any(len(d) != 48 or set(d) - {"0", "1"} for d in v):
            raise ValueError("schedule phải là 7 chuỗi, mỗi chuỗi 48 ký tự 0/1")
        return v

    @field_validator("blocked_categories")
    @classmethod
    def _cats(cls, v):
        bad = set(v) - set(CATEGORIES)
        if bad:
            raise ValueError(f"nhóm không hợp lệ: {sorted(bad)}")
        return v


def default_policy(age: int) -> Policy:
    """Chính sách mặc định: trẻ 6–11 chặn mạng xã hội + nội dung không phù hợp."""
    cats = ["social", "inappropriate"] if age <= 11 else ["inappropriate"]
    return Policy(blocked_categories=cats)
