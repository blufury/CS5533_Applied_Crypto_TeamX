import base64
import hashlib
import json
import os
from typing import Any, Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_nonce() -> str:
    return os.urandom(12).hex()


def encrypt_payload(plaintext: str, key: bytes, nonce_hex: str, aad: Dict[str, Any]) -> Tuple[str, str]:
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), canonical_json(aad))
    ciphertext = ct[:-16]
    tag = ct[-16:]
    return base64.b64encode(ciphertext).decode("utf-8"), base64.b64encode(tag).decode("utf-8")


def decrypt_payload(payload_b64: str, auth_tag_b64: str, key: bytes, nonce_hex: str, aad: Dict[str, Any]) -> str:
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = base64.b64decode(payload_b64)
    tag = base64.b64decode(auth_tag_b64)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, canonical_json(aad))
    return plaintext.decode("utf-8")


def sign_result(result_payload: str) -> str:
    return hashlib.sha256(result_payload.encode("utf-8")).hexdigest()
