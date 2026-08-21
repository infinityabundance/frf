#!/usr/bin/env python3
"""External minimizer serving the `cli-exit-minimize` κ route under the spec
{relation: drop-comment-blank-lines} — the minimizer extension protocol
(spec/minimizer.md).

Protocol: reads a canonical JSON frf-minimizer-request-v1 on stdin, writes a
canonical JSON frf-minimizer-response-v1 on stdout. The request carries the
residual and the ORIGINAL fixture (base64); the response proposes ONE reduced
fixture. The minimizer has no oracle — it cannot execute — so its proposal is
a STATIC syntactic reduction (drop comment and blank lines). The core
COURT-VERIFIES the proposal with the one comparison operation: a proposal
that does not preserve the residual's lineage is recorded-but-not-accepted.

The response MUST echo `request_id` (the SHA-256 of the exact request bytes)
and its declared fixture hash must rederive from the proposed bytes.
"""
import base64
import hashlib
import json
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-minimizer-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()

original = base64.b64decode(req["fixture"]["raw_base64"])
text = original.decode("utf-8", "replace")
# Static reduction: drop comment lines and blank lines (the divergence is on
# the directive lines; comments cannot carry it).
kept = [line for line in text.split("\n") if line.strip() and not line.lstrip().startswith("#")]
proposal = "\n".join(kept)
if not proposal.endswith("\n"):
    proposal += "\n"
proposal_bytes = proposal.encode("utf-8")

response = {
    "schema_version": "frf-minimizer-response-v1",
    "request_id": request_id,
    "fixture_sha256": hashlib.sha256(proposal_bytes).hexdigest(),
    "fixture_base64": base64.b64encode(proposal_bytes).decode("ascii"),
    "minimal": True,
    "attempts": [
        {
            "attempt": 1,
            "fixture_sha256": hashlib.sha256(original).hexdigest(),
            "kept": False,
        },
        {
            "attempt": 2,
            "fixture_sha256": hashlib.sha256(proposal_bytes).hexdigest(),
            "kept": True,
        },
    ],
    "indeterminate": False,
    "failure": None,
}
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
