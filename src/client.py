import time
from typing import Any, Dict

from .crypto_utils import encrypt_payload, generate_nonce


def build_request(
    session_key: bytes,
    job_id: str,
    payload: str,
    circuit_type: str = "clifford",
    nonce: str | None = None,
    timestamp: int | None = None,
    client_id: str = "client-001",
) -> Dict[str, Any]:
    nonce = nonce or generate_nonce()
    timestamp = timestamp if timestamp is not None else int(time.time())

    request: Dict[str, Any] = {
        "spec_version": "v0.5",
        "job_id": job_id,
        "client_id": client_id,
        "nonce": nonce,
        "timestamp": timestamp,
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

    payload_b64, auth_tag_b64 = encrypt_payload(payload, session_key, nonce, aad)
    request["payload"] = payload_b64
    request["auth_tag"] = auth_tag_b64
    return request
