#!/usr/bin/env python3
"""The Goto Fail record-length minimizer — serves the kappa route
`ssl-handshake-minimize` under the spec {relation: reduce-record-length,
relation_version: v1}.

CVE-2014-1266 is triggered by ANY handshake record whose signature does not
match its data: the buggy verifier accepts it (the comparison is skipped),
the fixed one refuses it. The fixture IS the trigger knob — the record's
DECLARED PAYLOAD LENGTH (`len=`, the TLS record header's length field) —
so reducing it reduces the trigger while the divergence (buggy accepts,
fixed refuses) survives as long as the record parses.

The minimizer has no oracle — it cannot execute, it proposes — so it cannot
binary-search. It proposes the empirically minimal DECLARED PAYLOAD LENGTH
that still produces the verdict divergence on both verifiers: 1. The
boundary is real and deterministic: at length 1 the record parses and the
tampered-signature divergence survives; at length 0 the record is malformed
(a length mismatch is refused by BOTH sides with exit 2), so no divergence.

The CORE decides, never this program: the proposal is court-verified with
the one comparison operation — both sides re-execute on the proposed
fixture and the residual's lineage must survive — and the adjacent-boundary
is established by the core itself: it executes the adjacent fixture (the
len=0 control, which must LOSE the lineage) and the proposal (the final
verification, which must preserve it), derives both coordinates through the
declared domain projection (embedded-integer over the `len=` token), and
requires predecessor + 1 == value before `proven` can be true. A proposal
that does not survive is recorded-but-not-accepted.

Protocol (spec/minimizer.md): reads canonical JSON frf-minimizer-request-v1,
writes canonical JSON frf-minimizer-response-v2, echoing `request_id` (the
SHA-256 of the exact request bytes).
"""
import base64
import hashlib
import json
import re
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-minimizer-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()

fixture = base64.b64decode(req["fixture"]["raw_base64"])
original = fixture.decode("utf-8", "replace")

RESPONSE_V2 = "frf-minimizer-response-v2"


def parse_len(text):
    m = re.search(r"^len=(\d+)$", text, re.M)
    return int(m.group(1)) if m else None


def with_len_data(text, length, data):
    out = re.sub(r"^(len=)\d+$", r"\g<1>" + str(length), text, flags=re.M)
    out = re.sub(r"^(data=).*$", r"\g<1>" + data, out, flags=re.M)
    return out


length = parse_len(original)
if length is None:
    sys.exit(1)

# The minimal declared payload length: 1, with a deliberately WRONG
# signature (the tampered-record shape). One is the empirical floor — at 0
# the record does not parse (length mismatch, both sides exit 2, no
# divergence).
MINIMAL = 1
DATA = "X"
WRONG_SIG = "00"

proposal = with_len_data(original, MINIMAL, DATA)
proposal = re.sub(r"^(sig=).*$", "sig=" + WRONG_SIG, proposal, flags=re.M)

# The adjacent point one step below: len=0 — malformed (the length mismatch
# is refused by BOTH sides, so the divergence is lost).
adjacent_claim = MINIMAL - 1
adjacent_fixture = with_len_data(original, adjacent_claim, DATA)
adjacent_fixture = re.sub(r"^(sig=).*$", "sig=" + WRONG_SIG, adjacent_fixture, flags=re.M)

response = {
    "schema_version": RESPONSE_V2,
    "request_id": request_id,
    "fixture_sha256": hashlib.sha256(proposal.encode()).hexdigest(),
    "fixture_base64": base64.b64encode(proposal.encode()).decode(),
    "minimal": True,
    "minimality": {
        "kind": "adjacent-boundary",
        "reduction_domain": {
            "kind": "ordered-integer",
            "semantic": "tls.handshake.record_data_length",
            # The DOMAIN PROJECTION: the coordinate is the declared payload
            # length — the integer token that follows the first `len=`.
            "extractor": {
                "kind": "embedded-integer",
                "radix": "10",
                "prefix": "len=",
            },
        },
        "boundary": {
            "predecessor": str(adjacent_claim),
            "predecessor_preserves": False,  # claimed: len=0 is refused by both sides
            "value": str(MINIMAL),
            "value_preserves": True,  # claimed: len=1 preserves the divergence
        },
        "adjacent_fixture_sha256": hashlib.sha256(adjacent_fixture.encode()).hexdigest(),
        "adjacent_fixture_base64": base64.b64encode(adjacent_fixture.encode()).decode(),
    },
    "attempts": [
        {
            "attempt": "1",
            "fixture_sha256": hashlib.sha256(proposal.encode()).hexdigest(),
            "kept": True,  # the minimizer's proposal; the core court-verifies it
        }
    ],
    "indeterminate": False,
    "failure": None,
}

json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
