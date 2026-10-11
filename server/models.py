from datetime import datetime
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from db import Base


class Parent(Base):
    __tablename__ = "parents"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True)
    pw_hash: Mapped[str]
    role: Mapped[str] = mapped_column(default="parent")  # parent | admin (child-view = thiết bị)
    failed: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(default=None)


class Session(Base):  # khóa = sha256(cookie)
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(primary_key=True)
    parent_id: Mapped[int] = mapped_column(ForeignKey("parents.id"))
    expires: Mapped[datetime]


class Child(Base):
    __tablename__ = "children"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_id: Mapped[int] = mapped_column(ForeignKey("parents.id"))
    name: Mapped[str]
    age: Mapped[int] = mapped_column(default=10)
    policy_version: Mapped[int] = mapped_column(default=1)
    policy_payload: Mapped[str] = mapped_column(Text, default="")  # chuỗi JSON chuẩn hóa đã ký
    policy_sig: Mapped[str] = mapped_column(Text, default="")


class EnrollCode(Base):
    __tablename__ = "enroll_codes"
    code: Mapped[str] = mapped_column(primary_key=True)
    parent_id: Mapped[int] = mapped_column(ForeignKey("parents.id"))
    child_id: Mapped[int] = mapped_column(ForeignKey("children.id"))
    created_at: Mapped[datetime]
    expires: Mapped[datetime]
    used: Mapped[bool] = mapped_column(default=False)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    child_id: Mapped[int] = mapped_column(ForeignKey("children.id"))
    name: Mapped[str]
    fingerprint: Mapped[str]
    refresh_hash: Mapped[str] = mapped_column(index=True)
    revoked: Mapped[bool] = mapped_column(default=False)
    consent_parent_id: Mapped[int] = mapped_column(ForeignKey("parents.id"))  # NĐ 13/2023
    enrolled_at: Mapped[datetime]
    last_seen: Mapped[datetime | None] = mapped_column(default=None)
    policy_version_seen: Mapped[int] = mapped_column(default=0)
    quota_used_sec: Mapped[int] = mapped_column(default=0)
    clock_skew: Mapped[float] = mapped_column(default=0.0)


class AccessToken(Base):
    __tablename__ = "access_tokens"
    token_hash: Mapped[str] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    expires: Mapped[datetime]


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String, unique=True)  # idempotency key
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    child_id: Mapped[int] = mapped_column(ForeignKey("children.id"), index=True)
    ts: Mapped[datetime] = mapped_column(index=True)
    type: Mapped[str]
    subject_enc: Mapped[str] = mapped_column(Text, default="")  # AES-GCM
    duration_sec: Mapped[int] = mapped_column(default=0)
    policy_id: Mapped[int] = mapped_column(default=0)


class HelpRequest(Base):
    __tablename__ = "help_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    child_id: Mapped[int] = mapped_column(ForeignKey("children.id"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    kind: Mapped[str]  # more_time | wrong_block
    subject: Mapped[str] = mapped_column(default="")
    minutes: Mapped[int] = mapped_column(default=0)
    note: Mapped[str] = mapped_column(default="")
    status: Mapped[str] = mapped_column(default="pending")  # pending|approved|denied
    reply: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime]
    decided_at: Mapped[datetime | None] = mapped_column(default=None)


class Command(Base):
    __tablename__ = "commands"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    kind: Mapped[str]  # lock | unlock | add_minutes | wipe_cache
    minutes: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime]
    delivered: Mapped[bool] = mapped_column(default=False)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime]
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("parents.id"), default=None)
    child_id: Mapped[int | None] = mapped_column(ForeignKey("children.id"), default=None, index=True)
    ip: Mapped[str] = mapped_column(default="")
    action: Mapped[str]
    old: Mapped[str] = mapped_column(Text, default="null")
    new: Mapped[str] = mapped_column(Text, default="null")
