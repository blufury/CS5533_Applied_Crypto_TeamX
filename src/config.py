import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def get_master_secret() -> bytes:
    env_value = os.getenv("QDELEGATE_MASTER_KEY_B64")
    if env_value:
        return base64.b64decode(env_value)
    return os.urandom(32)


def derive_session_key(master_secret: bytes, context: bytes = b"qdelegate-session") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    )
    return hkdf.derive(master_secret)


def get_session_key() -> bytes:
    master_secret = get_master_secret()
    return derive_session_key(master_secret)
