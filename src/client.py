import time
from typing import Dict
from .crypto_utils import encrypt_payload, generate_nonce


def build_request(session_key: bytes, job_id: str, plaintext_payload: str, circuit_type: str = "clifford") -> Dict[str, str | int]:
    nonce = generate_nonce()
    request = {
        "spec_version": "v0.5",
        "job_id": job_id,
        "client_id": "client-001",
        "nonce": nonce,
        "timestamp": int(time.time()),
        "circuit_type": circuit_type,
    }
    aad = {
        "spec_version": request["spec_version"],
        "job_id": request["job_id"],
        "client_id": request["client_id"],
        "nonce": request["nonce"],
        "timestamp": request["timestamp"],
        "circuit_type": request["circuit_type"],
    }
    payload_b64, auth_tag_b64 = encrypt_payload(plaintext_payload, session_key, nonce, aad)
    request["payload"] = payload_b64
    request["auth_tag"] = auth_tag_b64
    return request
