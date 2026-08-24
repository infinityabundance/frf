#!/usr/bin/env python3
"""The Goto Fail signature-skip mutation provider — operator id
`signature-skip`, mutation family {relation: seed-signature-skip,
relation_version: v1}, target axis `tls.verdict`.

The court challenge is the sensitivity proof: a comparator that never sees a
skipped signature check cannot be trusted to certify "no acceptance of
tampered records". The challenge runs ONE operator per target axis, and the
operator's mutant must move EXACTLY that dimension (specificity: nothing
else may diverge). This provider therefore proposes the axis's OWN
deterministic, synthetic defect shape: a verifier that ACCEPTS every record
— the CVE-2014-1266 observable (the duplicated `goto fail` accepts
everything), expressed as a wrapper that prints the acceptance line and
exits 0 unconditionally.

The mutant is deterministic and deliberately synthetic: it reproduces the
defect's OBSERVABLE shape (acceptance of any record) without executing any
historical code. A court that fails to see the seeded signal is refused —
the challenge records stay as evidence.

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

target = req["target_axis"]
assert target == "tls.verdict", req

# The mutant: accepts EVERY record — the CVE-2014-1266 observable shape.
MUTANT = (
    "#!/bin/sh\n"
    "printf '%s\\n' 'tls: handshake accepted'\n"
    "exit 0\n"
).encode()

response = {
    "schema_version": "frf-mutation-response-v1",
    "request_id": request_id,
    "mutant_base64": base64.b64encode(MUTANT).decode(),
    "expected_affected_surfaces": ["tls.verdict"],
    "failure": None,
}

json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
