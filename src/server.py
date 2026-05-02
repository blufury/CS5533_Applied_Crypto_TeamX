import logging
import time
from typing import Any, Dict, Set

from src.crypto_utils import decrypt_payload, sign_result


logger = logging.getLogger("qdelegate.audit")

if not logger.handlers:
    logger.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler("audit.log")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    logger.addHandler(file_handler)


class QDelegateServer:
    MAX_PAYLOAD_B64_LENGTH = 4096
    TIMESTAMP_WINDOW_SECONDS = 60

    def __init__(self, session_key: bytes):
        self.session_key = session_key
        self.used_nonces: Set[str] = set()
        self.used_job_ids: Set[str] = set()
        self.supported_version = "v0.5"
        self.supported_circuit_types = {"clifford"}

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

    def _is_nonce_valid(self, nonce: Any) -> bool:
        if not isinstance(nonce, str):
            return False
        if len(nonce) != 24:
            return False
        try:
            bytes.fromhex(nonce)
        except ValueError:
            return False
        return True

    def _is_timestamp_valid(self, timestamp: Any) -> bool:
        if not isinstance(timestamp, int):
            return False
        now = int(time.time())
        return abs(now - timestamp) <= self.TIMESTAMP_WINDOW_SECONDS

    def _is_payload_size_valid(self, payload: Any) -> bool:
        return isinstance(payload, str) and len(payload) <= self.MAX_PAYLOAD_B64_LENGTH

    def _audit(self, event: str, request: Dict[str, Any], status: str, reason: str = "") -> None:
        logger.info(
            "event=%s job_id=%s spec_version=%s nonce=%s status=%s reason=%s",
            event,
            request.get("job_id", "unknown"),
            request.get("spec_version", "unknown"),
            request.get("nonce", "unknown"),
            status,
            reason,
        )

    def submit_job(self, request: Dict[str, Any]) -> Dict[str, Any]:
        self._audit("request_received", request, "started")

        if not self._validate_required_fields(request):
            self._audit("request_rejected", request, "error", "invalid_format")
            return {"status": "error", "code": 400, "message": "Invalid request format"}

        if request["spec_version"] != self.supported_version:
            self._audit("request_rejected", request, "error", "unsupported_version")
            return {"status": "error", "code": 400, "message": "Unsupported protocol version"}

        if not self._is_nonce_valid(request["nonce"]):
            self._audit("request_rejected", request, "error", "invalid_nonce")
            return {"status": "error", "code": 400, "message": "Invalid nonce"}

        if not self._is_timestamp_valid(request["timestamp"]):
            self._audit("request_rejected", request, "error", "stale_or_future_timestamp")
            return {"status": "error", "code": 400, "message": "Invalid timestamp"}

        if not self._is_payload_size_valid(request["payload"]):
            self._audit("request_rejected", request, "error", "payload_too_large")
            return {"status": "error", "code": 400, "message": "Payload too large"}

        if request["circuit_type"] not in self.supported_circuit_types:
            self._audit("request_rejected", request, "error", "unsupported_circuit")
            return {"status": "error", "code": 422, "message": "Unsupported circuit type"}

        job_id = request["job_id"]
        nonce = request["nonce"]

        if nonce in self.used_nonces or job_id in self.used_job_ids:
            self._audit("replay_detected", request, "error", "duplicate_nonce_or_job_id")
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
            plaintext = decrypt_payload(
                payload_b64=request["payload"],
                auth_tag_b64=request["auth_tag"],
                key=self.session_key,
                nonce_hex=request["nonce"],
                aad=aad,
            )
        except Exception:
            self._audit("request_rejected", request, "error", "auth_failed_or_tampered")
            return {"status": "error", "code": 401, "message": "Authentication failed"}

        self.used_nonces.add(nonce)
        self.used_job_ids.add(job_id)

        result_payload = f"processed:{plaintext}"
        signature = sign_result(result_payload)

        response = {
            "status": "complete",
            "code": 200,
            "job_id": job_id,
            "result_payload": result_payload,
            "signature": signature,
            "spec_version": self.supported_version,
        }

        self._audit("request_accepted", request, "success", "result_returned")
        return response
