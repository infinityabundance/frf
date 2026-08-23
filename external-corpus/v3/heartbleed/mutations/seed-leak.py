#!/usr/bin/env python3
"""The Heartbleed seeded-leak mutation provider — operator id `seed-leak`,
mutation family {relation: seed-sensitive-leak, relation_version: v1},
target axis `memory.leak.sensitive`.

The court challenge is the sensitivity proof: a comparator that never sees a
leak cannot be trusted to certify "no leak". This provider proposes a
MUTANT candidate that dumps a known sensitive payload — a PEM private-key
header plus a SECRET_KEY assignment — to stdout and exits 1, exactly the
observable shape of a real Heartbleed leak. The court then runs the mutant
as an ordinary content-addressed run and derives the verdicts itself: the
leak comparator MUST flag the divergence on `memory.leak.sensitive` (marker
signal) and nothing else (specificity). A court that fails to see the
seeded leak, or conflates it with another axis, is refused — the challenge
record stays as evidence.

The mutant is deterministic: a fixed payload, byte-stable across runs.

Protocol (spec/mutation.md): reads canonical JSON frf-mutation-request-v1,
writes canonical JSON frf-mutation-response-v1, echoing `request_id` (the
SHA-256 of the exact request bytes).
"""
import base64
import hashlib
import json
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-mutation-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()

# The seeded leak: a fixed, deterministic sensitive payload. The court's own
# comparison decides whether this is a leak on the target axis.
MUTANT = (
    b"#!/bin/sh\n"
    b"printf '%s\\n' \\\n"
    b"  '-----BEGIN RSA PRIVATE KEY-----' \\\n"
    b"  'MIIBogIBAAKCAQEAseededleakmaterialAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \\\n"
    b"  'SECRET_KEY=12345' \\\n"
    b"  '-----END RSA PRIVATE KEY-----'\n"
    b"exit 1\n"
)

response = {
    "schema_version": "frf-mutation-response-v1",
    "request_id": request_id,
    "mutant_base64": base64.b64encode(MUTANT).decode(),
    "expected_affected_surfaces": ["memory.leak.sensitive"],
    "failure": None,
}
json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
