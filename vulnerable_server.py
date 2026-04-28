from src.server import QDelegateServer


class VulnerableQDelegateServer(QDelegateServer):
    def submit_job(self, request):
        self._audit("request_received", request, "started")

        if not self._validate_required_fields(request):
            return {"status": "error", "code": 400, "message": "Invalid request format"}

        if request["spec_version"] != self.supported_version:
            return {"status": "error", "code": 400, "message": "Unsupported protocol version"}

        if request["circuit_type"] not in self.supported_circuit_types:
            return {"status": "error", "code": 422, "message": "Unsupported circuit type"}

        # Replay protection intentionally removed

        response = {
            "status": "complete",
            "code": 200,
            "job_id": request["job_id"],
            "result_payload": "processed_replayed_request",
            "signature": "vulnerable_signature",
            "spec_version": self.supported_version,
        }

        self._audit("request_accepted", request, "success", "replay_allowed")
        return response
