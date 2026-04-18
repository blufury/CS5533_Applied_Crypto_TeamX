import time

from src.client import build_request
from src.config import get_session_key
from src.server import QDelegateServer


def test_happy_path_end_to_end():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="int-job-001",
        nonce="00112233445566778899aabb",
        payload="H q0",
        timestamp=int(time.time()),
    )

    res = server.submit_job(req)

    assert res["status"] == "complete"
    assert res["code"] == 200
    assert res["job_id"] == "int-job-001"
    assert res["spec_version"] == "v0.5"
    assert "result_payload" in res
    assert "signature" in res


def test_replay_rejected_end_to_end():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="int-job-002",
        nonce="111122223333444455556666",
        payload="X q0",
        timestamp=int(time.time()),
    )

    first = server.submit_job(req)
    second = server.submit_job(req)

    assert first["code"] == 200
    assert second["status"] == "error"
    assert second["code"] == 409
    assert "Replay" in second["message"]


def test_tampered_request_rejected_end_to_end():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="int-job-003",
        nonce="abcdefabcdefabcdefabcdef",
        payload="Z q0",
        timestamp=int(time.time()),
    )

    req["ciphertext"] = "tampered" + req["ciphertext"]

    res = server.submit_job(req)

    assert res["status"] == "error"
    assert res["code"] == 401


def test_wrong_version_rejected_end_to_end():
    key = get_session_key()
    server = QDelegateServer(key)

    req = build_request(
        session_key=key,
        job_id="int-job-004",
        nonce="999988887777666655554444",
        payload="H q0; X q1",
        timestamp=int(time.time()),
    )
    req["spec_version"] = "v0.4"

    res = server.submit_job(req)

    assert res["status"] == "error"
    assert res["code"] == 400
    assert "version" in res["message"].lower()


def test_reused_nonce_with_new_job_rejected_end_to_end():
    key = get_session_key()
    server = QDelegateServer(key)

    nonce = "1234567890abcdef12345678"

    req1 = build_request(
        session_key=key,
        job_id="int-job-005",
        nonce=nonce,
        payload="H q0",
        timestamp=int(time.time()),
    )
    req2 = build_request(
        session_key=key,
        job_id="int-job-006",
        nonce=nonce,
        payload="X q0",
        timestamp=int(time.time()),
    )

    first = server.submit_job(req1)
    second = server.submit_job(req2)

    assert first["code"] == 200
    assert second["status"] == "error"
    assert second["code"] == 409
