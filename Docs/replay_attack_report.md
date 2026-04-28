# Replay Attack Report

## Overview

This report documents a replay attack vulnerability against the Q-Delegate protocol.

The vulnerable implementation failed to enforce replay protection by not tracking previously used nonces and job identifiers.

As a result, previously valid authenticated requests could be resent multiple times and still be accepted by the server.

## Root Cause

Replay protection checks were intentionally removed from the vulnerable server.

Without nonce and job tracking:
- duplicate requests were accepted
- attackers could replay captured traffic
- authenticated messages were treated as fresh indefinitely

## Attack Steps

1. Build a valid authenticated request
2. Send the request to the vulnerable server
3. Resend the exact same request multiple times
4. Observe the server continues accepting it

## Impact

A successful replay attack could allow:
- repeated execution of the same quantum job
- denial-of-service amplification
- repeated billing or resource consumption
- duplicate processing of sensitive requests

## Evidence

The vulnerable server accepts the same request multiple times successfully.

## Fix

Replay protection was restored by:
- tracking used nonces
- tracking processed job_ids
- rejecting duplicate requests with HTTP 409

## Regression Test

A regression test was added to ensure replay attacks are rejected in future versions.
