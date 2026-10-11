import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_sig(pub_b64: str, payload: str, sig_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), payload.encode())
        return True
    except Exception:
        return False
