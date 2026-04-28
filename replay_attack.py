import time

from attack.vulnerable_server import VulnerableQDelegateServer
from src.client import build_request
from src.config import get_session_key


def main():
    key = get_session_key()
    server = VulnerableQDelegateServer(key)

    request = build_request(
        session_key=key,
        job_id="replay-job-001",
        nonce="00112233445566778899aabb",
        payload="H q0",
        timestamp=int(time.time()),
    )

    print("=== FIRST REQUEST ===")
    print(server.submit_job(request))

    print("\n=== REPLAY #1 ===")
    print(server.submit_job(request))

    print("\n=== REPLAY #2 ===")
    print(server.submit_job(request))

    print("\n=== REPLAY #3 ===")
    print(server.submit_job(request))


if __name__ == "__main__":
    main()
