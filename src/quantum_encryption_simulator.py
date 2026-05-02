import base64
import hmac
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict


def _canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass
class QuantumPad:
    x_mask: bytes
    z_mask: bytes
    mac_key: bytes


class QuantumEncryptionSimulator:
    """
    Simulates a quantum one-time-pad style encryption layer.

    Important:
    - This is a simulator, not real quantum hardware.
    - The payload is treated as classical data encoded into simulated qubits.
    - The X mask changes the encoded bit values.
    - The Z mask is tracked to model the full quantum one-time pad, even though
      phase does not affect recovery of classical payload bits in this simulator.
    - HMAC-SHA256 is used for authentication because quantum one-time pad style
      encryption alone does not authenticate messages.
    """

    def __init__(self):
        self._pads_by_job_id: Dict[str, QuantumPad] = {}

    def create_pad_for_job(self, job_id: str, payload_length: int) -> str:
        if job_id in self._pads_by_job_id:
            raise ValueError("pad already exists for job_id")

        pad = QuantumPad(
            x_mask=os.urandom(payload_length),
            z_mask=os.urandom(payload_length),
            mac_key=os.urandom(32),
        )
        self._pads_by_job_id[job_id] = pad
        return f"qotp-pad-{job_id}"

    def encrypt_payload(self, job_id: str, plaintext: str, aad: Dict[str, Any]) -> Dict[str, str]:
        plaintext_bytes = plaintext.encode("utf-8")
        key_context_id = self.create_pad_for_job(job_id, len(plaintext_bytes))
        pad = self._pads_by_job_id[job_id]

        ciphertext = _xor_bytes(plaintext_bytes, pad.x_mask)
        ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")

        tag_input = _canonical_json(aad) + ciphertext
        auth_tag = hmac.new(pad.mac_key, tag_input, hashlib.sha256).digest()

        return {
            "quantum_ciphertext": ciphertext_b64,
            "quantum_auth_tag": base64.b64encode(auth_tag).decode("utf-8"),
            "key_context_id": key_context_id,
            "encryption_mode": "simulated-qotp",
        }

    def decrypt_payload(
        self,
        job_id: str,
        quantum_ciphertext: str,
        quantum_auth_tag: str,
        aad: Dict[str, Any],
    ) -> str:
        if job_id not in self._pads_by_job_id:
            raise ValueError("missing quantum pad for job_id")

        pad = self._pads_by_job_id[job_id]
        ciphertext = base64.b64decode(quantum_ciphertext)
        received_tag = base64.b64decode(quantum_auth_tag)

        tag_input = _canonical_json(aad) + ciphertext
        expected_tag = hmac.new(pad.mac_key, tag_input, hashlib.sha256).digest()

        if not hmac.compare_digest(received_tag, expected_tag):
            raise ValueError("quantum payload authentication failed")

        plaintext_bytes = _xor_bytes(ciphertext, pad.x_mask)
        return plaintext_bytes.decode("utf-8")
