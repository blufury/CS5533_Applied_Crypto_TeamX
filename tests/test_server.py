from src.client import build_request
from src.config import derive_session_key
from src.server import QDelegateServer


def make_server_and_key() -> tuple[QDelegateServer, bytes]:
    master_secret = b"a" * 32
    session_key = derive_session_key(master_secret)
    return QDelegateServer(session_key), session_key


def test_valid_request() -> None:
    server, key = make_server_and_key()
    req = build_request(key, "job-1", "H q0")
    res = server.submit_job(req)
    assert res["code"] == 200
    assert res["status"] == "complete"


def test_replay_rejected() -> None:
    server, key = make_server_and_key()
    req = build_request(key, "job-1", "H q0")
    first = server.submit_job(req)
    second = server.submit_job(req)
    assert first["code"] == 200
    assert second["code"] == 409


def test_tampered_payload_rejected() -> None:
    server, key = make_server_and_key()
    req = build_request(key, "job-1", "H q0")
    req["payload"] = req["payload"][:-4] + "AAAA"
    res = server.submit_job(req)
    assert res["code"] == 401


def test_unsupported_circuit_rejected() -> None:
    server, key = make_server_and_key()
    req = build_request(key, "job-1", "T q0", circuit_type="non_clifford")
    res = server.submit_job(req)
    assert res["code"] == 422


def test_missing_field_rejected() -> None:
    server, key = make_server_and_key()
    req = build_request(key, "job-1", "H q0")
    del req["client_id"]
    res = server.submit_job(req)
    assert res["code"] == 400
