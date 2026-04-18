import json
import time

from src.client import build_request
from src.config import get_session_key
from src.server import QDelegateServer


def pretty_print(title: str, response: dict) -> None:
    print(f"\n=== {title} ===")
    print(json.dumps(response, indent=2))


def main() -> None:
    key = get_session_key()
    server = QDelegateServer(key)

    req1 = build_request(
        session_key=key,
        job_id="demo-job-001",
        nonce="00112233445566778899aabb",
        payload="H q0",
        timestamp=int(time.time()),
    )
    res1 = server.submit_job(req1)
    pretty_print("VALID REQUEST", res1)

    res2 = server.submit_job(req1)
    pretty_print("REPLAYED REQUEST", res2)

    req3 = build_request(
        session_key=key,
        job_id="demo-job-002",
        nonce="abcdefabcdefabcdefabcdef",
        payload="X q0",
        timestamp=int(time.time()),
    )
    req3["payload"] = "tampered" + req3["payload"]
    res3 = server.submit_job(req3)
    pretty_print("TAMPERED REQUEST", res3)

    req4 = build_request(
        session_key=key,
        job_id="demo-job-003",
        nonce="999988887777666655554444",
        payload="Z q0",
        timestamp=int(time.time()),
    )
    req4["spec_version"] = "v0.4"
    res4 = server.submit_job(req4)
    pretty_print("WRONG VERSION", res4)

    print("\nAudit log written to audit.log")


if __name__ == "__main__":
    main()
