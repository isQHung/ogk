"""Mã hóa trường nhạy cảm (AES-GCM) và ký chính sách (Ed25519). Khóa KHÔNG hardcode."""
import base64
import os
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _key_dir() -> Path:
    d = Path(os.getenv("OGK_KEY_DIR", "./keys"))
    d.mkdir(parents=True, exist_ok=True)
    return d


@lru_cache
def _aes() -> AESGCM:
    env = os.getenv("OGK_DATA_KEY")  # base64 của 32 byte; ưu tiên biến môi trường
    if env:
        return AESGCM(base64.b64decode(env))
    p = _key_dir() / "data.key"
    if not p.exists():
        p.write_bytes(os.urandom(32))
        os.chmod(p, 0o600)
    return AESGCM(p.read_bytes())


def enc(text: str) -> str:
    nonce = os.urandom(12)
    return base64.b64encode(nonce + _aes().encrypt(nonce, text.encode(), None)).decode()


def dec(blob: str) -> str:
    raw = base64.b64decode(blob)
    return _aes().decrypt(raw[:12], raw[12:], None).decode()


@lru_cache
def _signer() -> Ed25519PrivateKey:
    p = _key_dir() / "signing.pem"
    if not p.exists():
        k = Ed25519PrivateKey.generate()
        p.write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        os.chmod(p, 0o600)
        return k
    return serialization.load_pem_private_key(p.read_bytes(), None)


def public_key_b64() -> str:
    raw = _signer().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(payload: str) -> str:
    return base64.b64encode(_signer().sign(payload.encode())).decode()
