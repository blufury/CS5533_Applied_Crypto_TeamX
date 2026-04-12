from typing import Any, Dict, Set
from cryptography.exceptions import InvalidTag
from .crypto_utils import decrypt_payload, sign_result


class QDelegateServer:
    def __init__(self, session_key: bytes):
        self.session_key = session_key
        self.used_nonces: Set[str] = set()
        self.used_job_ids: Set[str] = set()
        self.supported_version = "v0.5"
        self.supported_circuit_types = {"clifford"}
        self.max_payload_chars = 4096

    def _validate_required_fields(self, request: Dict[str, Any]) -> bool:
        required = {
            "spec_version",
            "job_id",
            "client_id",
            "nonce",
            "timestamp",
            "circuit_type",
            "payload",
            "auth_tag",
        }
        return required.issubset(request.keys())

    def submit_job(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if not self._validate_required_fields(request):
            return {"status": "error", "code": 400, "message": "Invalid request format"}

        if request["spec_version"] != self.supported_version:
            return {"status": "error", "code": 400, "message": "Unsupported protocol version"}

        if request["circuit_type"] not in self.supported_circuit_types:
            return {"status": "error", "code": 422, "message": "Unsupported circuit type"}

        job_id = request["job_id"]
        nonce = request["nonce"]

        if len(request["payload"]) > self.max_payload_chars:
            return {"status": "error", "code": 400, "message": "Payload too large"}

        if nonce in self.used_nonces or job_id in self.used_job_ids:
            return {"status": "error", "code": 409, "message": "Replay detected"}

        aad = {
            "spec_version": request["spec_version"],
            "job_id": request["job_id"],
            "client_id": request["client_id"],
            "nonce": request["nonce"],
            "timestamp": request["timestamp"],
            "circuit_type": request["circuit_type"],
        }

        try:
            plaintext_payload = decrypt_payload(
                request["payload"],
                request["auth_tag"],
                self.session_key,
                nonce,
                aad,
            )
        except (InvalidTag, ValueError):
            return {"status": "error", "code": 401, "message": "Authentication failed"}

        self.used_nonces.add(nonce)
        self.used_job_ids.add(job_id)

        result_payload = f"processed:{plaintext_payload}"
        signature = sign_result(result_payload)

        return {
            "status": "complete",
            "code": 200,
            "job_id": job_id,
            "result_payload": result_payload,
            "signature": signature,
            "spec_version": self.supported_version,
        }
