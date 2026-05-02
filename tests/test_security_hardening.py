import time

from src.client import build_request
from src.config import get_session_key
from src.server import QDelegateServer


def test_old_timestamp_rejected():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="old-job",
        nonce="1234567890abcdef12345678",
        payload="H q0",
        timestamp=int(time.time()) - 1000,
    )

    res = server.submit_job(req)

    assert res["code"] == 400
    assert "timestamp" in res["message"].lower()


def test_future_timestamp_rejected():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="future-job",
        nonce="abcdefabcdefabcdefabcdef",
        payload="H q0",
        timestamp=int(time.time()) + 1000,
    )

    res = server.submit_job(req)

    assert res["code"] == 400
    assert "timestamp" in res["message"].lower()


def test_invalid_nonce_rejected():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="bad-nonce-job",
        nonce="1234567890abcdef12345678",
        payload="H q0",
        timestamp=int(time.time()),
    )

    req["nonce"] = "not-a-valid-nonce"

    res = server.submit_job(req)

    assert res["code"] == 400
    assert "nonce" in res["message"].lower()


def test_oversized_payload_rejected():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="large-payload-job",
        nonce="555555555555555555555555",
        payload="H q0",
        timestamp=int(time.time()),
    )
    req["payload"] = "A" * (server.MAX_PAYLOAD_B64_LENGTH + 1)

    res = server.submit_job(req)

    assert res["code"] == 400
    assert "payload" in res["message"].lower()


def test_replay_attack_still_rejected():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="regression-replay-job",
        nonce="666666666666666666666666",
        payload="H q0",
        timestamp=int(time.time()),
    )

    first = server.submit_job(req)
    second = server.submit_job(req)

    assert first["code"] == 200
    assert second["code"] == 409
    assert second["message"] == "Replay detected"
