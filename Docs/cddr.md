# Crypto Design Decision Record (CDDR) — Q-Delegate

## 1. Overview

This document defines the cryptographic primitives used in the Q-Delegate protocol, along with the rationale for their selection and the rules for safe usage. The goal is to ensure confidentiality, integrity, authentication, and resistance to misuse.

---

## 2. Security Goals

The system must provide:

- Message integrity (no tampering)
- Message authenticity (verify sender)
- Replay protection
- Secure key separation
- Misuse resistance (prevent common crypto mistakes)

---

## 3. Chosen Cryptographic Primitives

### 3.1 Authenticated Encryption

- **Algorithm:** AES-256-GCM
- **Type:** AEAD (Authenticated Encryption with Associated Data)

#### Rationale

- Provides both confidentiality and integrity in a single operation
- Widely used and standardized
- Efficient and supported by major libraries

#### Parameters

- Key size: 256 bits
- Nonce size: 96 bits
- Tag: 128 bits

---

### 3.2 Digital Signatures

- **Algorithm:** Ed25519

#### Rationale

- Modern, secure default for digital signatures
- Fast and simple API
- Resistant to common misuse compared to older schemes

---

### 3.3 Key Derivation

- **Algorithm:** HKDF with SHA-256

#### Rationale

- Allows safe derivation of multiple keys from a master secret
- Prevents key reuse across different purposes
- Standard and well-analyzed

---

### 3.4 Hash Function

- **Algorithm:** SHA-256

#### Use Cases

- Generating job identifiers
- Audit logging
- Integrity metadata

---

## 4. Key Usage Design

| Key Type | Purpose |
|----------|--------|
| Master Key | Root secret (not used directly for encryption) |
| Session Key | Used for AEAD encryption per session |
| Server Signing Key | Used to sign server responses |

---

## 5. Nonce Strategy

### Requirements

- Nonces must be:
  - Unique per key
  - Never reused
  - Randomly generated (96 bits)

### Enforcement

- Server maintains a record of used nonces
- Any reused nonce results in request rejection

---

## 6. Replay Protection

Replay attacks are prevented using:

- Unique `job_id` per request
- Unique `nonce` per message
- Server-side tracking of:
  - processed job_ids
  - used nonces

### Behavior

- Duplicate job_id → rejected
- Reused nonce → rejected

---

## 7. Authentication Design

### Client → Server

- All messages are protected using AES-GCM
- Includes:
  - payload
  - job_id
  - nonce
  - version

### Server → Client

- Responses are signed using Ed25519
- Client verifies:
  - signature validity
  - message integrity

---

## 8. Versioning Strategy

Each message includes:

```text

# Replay Mitigation

The final design enforces replay protection using both nonce uniqueness and job_id uniqueness. The server stores previously seen values and rejects duplicates with code `409`.

## Timestamp Freshness

Requests include a timestamp. The server accepts only timestamps within a 60-second freshness window. Requests that are too old or too far in the future are rejected with code `400`.

## Nonce Discipline

The server validates that nonces are 96-bit values encoded as 24 hex characters. Invalid nonce values are rejected before decryption.

## Validation Order

The server validates requests in this order:

1. required fields
2. protocol version
3. nonce format
4. timestamp freshness
5. payload size
6. supported circuit type
7. replay state
8. AES-GCM decryption/authentication

This prevents unnecessary cryptographic processing of malformed requests and ensures failures are logged with clear reasons.

## Security Logging

The server logs:

- request received
- request accepted
- replay detected
- invalid nonce
- invalid timestamp
- unsupported version
- authentication failure
- payload size failure
spec_version = "v0.5"
