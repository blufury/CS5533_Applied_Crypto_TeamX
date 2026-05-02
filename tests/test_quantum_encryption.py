import time

from src.quantum_client import build_quantum_request
from src.quantum_encryption_simulator import QuantumEncryptionSimulator
from src.quantum_server import QuantumQDelegateServer


def test_quantum_encrypted_happy_path():
    simulator = QuantumEncryptionSimulator()
    server = QuantumQDelegateServer(simulator)

    req = build_quantum_request(
        simulator=simulator,
        job_id="quantum-test-001",
        nonce="00112233445566778899aabb",
        payload="H q0",
        timestamp=int(time.time()),
    )

    res = server.submit_job(req)

    assert res["code"] == 200
    assert res["status"] == "complete"
    assert res["result_payload"] == "processed:H q0"
    assert res["encryption_mode"] == "simulated-qotp"


def test_quantum_encrypted_replay_rejected():
    simulator = QuantumEncryptionSimulator()
    server = QuantumQDelegateServer(simulator)

    req = build_quantum_request(
        simulator=simulator,
        job_id="quantum-test-002",
        nonce="111122223333444455556666",
        payload="X q0",
        timestamp=int(time.time()),
    )

    first = server.submit_job(req)
    second = server.submit_job(req)

    assert first["code"] == 200
    assert second["code"] == 409


def test_quantum_ciphertext_tamper_rejected():
    simulator = QuantumEncryptionSimulator()
    server = QuantumQDelegateServer(simulator)

    req = build_quantum_request(
        simulator=simulator,
        job_id="quantum-test-003",
        nonce="abcdefabcdefabcdefabcdef",
        payload="Z q0",
        timestamp=int(time.time()),
    )
    req["quantum_ciphertext"] = "tampered" + req["quantum_ciphertext"]

    res = server.submit_job(req)

    assert res["code"] == 401


def test_wrong_encryption_mode_rejected():
    simulator = QuantumEncryptionSimulator()
    server = QuantumQDelegateServer(simulator)

    req = build_quantum_request(
        simulator=simulator,
        job_id="quantum-test-004",
        nonce="999988887777666655554444",
        payload="H q0",
        timestamp=int(time.time()),
    )
    req["encryption_mode"] = "aes-gcm"

    res = server.submit_job(req)

    assert res["code"] == 400
    assert "encryption" in res["message"].lower()
