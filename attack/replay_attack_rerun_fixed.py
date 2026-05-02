import time

from src.client import build_request
from src.config import get_session_key
from src.server import QDelegateServer


def main() -> None:
    key = get_session_key()
    server = QDelegateServer(key)

    request = build_request(
        session_key=key,
        job_id="rerun-replay-job-001",
        nonce="00112233445566778899aabb",
        payload="H q0",
        timestamp=int(time.time()),
    )

    print("=== FIRST REQUEST ===")
    print(server.submit_job(request))

    print("\n=== REPLAY #1: SHOULD FAIL ===")
    print(server.submit_job(request))

    print("\n=== REPLAY #2: SHOULD FAIL ===")
    print(server.submit_job(request))


if __name__ == "__main__":
    main()
