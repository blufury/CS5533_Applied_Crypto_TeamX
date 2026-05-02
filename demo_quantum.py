import json
import time

from src.quantum_client import build_quantum_request
from src.quantum_encryption_simulator import QuantumEncryptionSimulator
from src.quantum_server import QuantumQDelegateServer


def pretty_print(title: str, response: dict) -> None:
    print(f"\n=== {title} ===")
    print(json.dumps(response, indent=2))


def main() -> None:
    simulator = QuantumEncryptionSimulator()
    server = QuantumQDelegateServer(simulator)

    req1 = build_quantum_request(
        simulator=simulator,
        job_id="quantum-demo-job-001",
        nonce="00112233445566778899aabb",
        payload="H q0",
        timestamp=int(time.time()),
    )
    pretty_print("VALID SIMULATED-QUANTUM ENCRYPTED REQUEST", server.submit_job(req1))

    pretty_print("REPLAYED REQUEST", server.submit_job(req1))

    req2 = build_quantum_request(
        simulator=simulator,
        job_id="quantum-demo-job-002",
        nonce="abcdefabcdefabcdefabcdef",
        payload="X q0",
        timestamp=int(time.time()),
    )
    req2["quantum_ciphertext"] = "tampered" + req2["quantum_ciphertext"]
    pretty_print("TAMPERED QUANTUM CIPHERTEXT", server.submit_job(req2))

    req3 = build_quantum_request(
        simulator=simulator,
        job_id="quantum-demo-job-003",
        nonce="999988887777666655554444",
        payload="Z q0",
        timestamp=int(time.time()),
    )
    req3["encryption_mode"] = "aes-gcm"
    pretty_print("WRONG ENCRYPTION MODE", server.submit_job(req3))

    print("\nQuantum audit log written to quantum_audit.log")


if __name__ == "__main__":
    main()
