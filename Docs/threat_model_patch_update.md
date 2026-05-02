# Threat Model Update — Replay Patch and Hardening

## Added Threat: Delayed Replay Attack

An attacker may capture a valid authenticated request and resend it later. Even if the message has not been modified, it should not be accepted outside a short freshness window.

## Updated Mitigations

The server now enforces:

- nonce uniqueness
- job_id uniqueness
- timestamp freshness
- valid nonce format
- payload size limits
- protocol version validation
- AEAD authentication before processing

## Updated Security Requirements

1. The system shall reject duplicate nonces.
2. The system shall reject duplicate job IDs.
3. The system shall reject requests outside the accepted timestamp window.
4. The system shall reject malformed nonce values.
5. The system shall reject oversized payloads before decryption.
6. The system shall log replay, validation, and authentication failures.

## Traceability

| Threat | Mitigation |
|---|---|
| Immediate replay | nonce + job_id tracking |
| Delayed replay | timestamp freshness window |
| Nonce misuse | 96-bit nonce format validation |
| Oversized payload input | maximum payload size check |
| Protocol downgrade | spec_version validation |
| Payload tampering | AES-GCM authentication |
