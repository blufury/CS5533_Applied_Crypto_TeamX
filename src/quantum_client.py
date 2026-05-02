import time
from typing import Any, Dict

from src.crypto_utils import generate_nonce
from src.quantum_encryption_simulator import QuantumEncryptionSimulator


def build_quantum_request(
    simulator: QuantumEncryptionSimulator,
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
        "encryption_mode": "simulated-qotp",
    }

    encrypted_fields = simulator.encrypt_payload(
        job_id=job_id,
        plaintext=payload,
        aad=aad,
    )

    request.update(encrypted_fields)
    return request
