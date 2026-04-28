import time

from src.client import build_request
from src.config import get_session_key
from src.server import QDelegateServer


def test_replay_attack_fixed():
    key = get_session_key()
    server = QDelegateServer(key)

    request = build_request(
        session_key=key,
        job_id="regression-job-001",
        nonce="abcdefabcdefabcdefabcdef",
        payload="H q0",
        timestamp=int(time.time()),
    )

    first = server.submit_job(request)
    second = server.submit_job(request)

    assert first["code"] == 200
    assert second["code"] == 409
    assert second["message"] == "Replay detected"
