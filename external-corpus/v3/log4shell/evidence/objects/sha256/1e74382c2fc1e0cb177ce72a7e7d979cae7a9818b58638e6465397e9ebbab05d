#!/usr/bin/env python3
"""The Log4Shell message-suffix minimizer — serves the kappa route
`jndi-message-minimize` under the spec {relation: reduce-message-suffix,
relation_version: v1}.

CVE-2021-44228 is triggered by ANY log message containing a complete JNDI
lookup expression: the vulnerable stack resolves "${jndi:ldap://...}" at
log time (the lookup error path fires against any unreachable endpoint);
the fixed stack logs the expression literally. The fixture IS the trigger
knob — the message line, with its DECLARED message-suffix length
(`len=N `, the ordered-integer domain projection the probe honors: the
message is the LAST N characters of the line) — so reducing N reduces the
message toward the trigger's floor.

The floor is the BARE LOOKUP TOKEN: N=28 isolates "${jndi:ldap://127.0.0.1:1/a}"
(the "connectivity check " prefix is inert), and the divergence (vulnerable
performs the lookup, fixed does not) survives. At N=27 the token loses its
opening "${" — the message is left literal by the substitutor and NEITHER
side performs a lookup — so the divergence is lost. Measured on both stacks
before this proposal was written; the CORE re-establishes both observations
itself (the adjacent control must lose the lineage, the proposal must
preserve it).

The minimizer has no oracle — it cannot execute, it proposes — so it cannot
binary-search; it proposes the empirically minimal suffix length. The CORE
decides: the proposal is court-verified with the one comparison operation —
both sides re-execute on the proposed fixture and the residual's lineage
must survive — and the adjacent-boundary is established by the core itself:
it executes the adjacent fixture (N=27, which must LOSE the lineage) and
the proposal (the final verification, which must preserve it), derives both
coordinates through the declared domain projection (embedded-integer over
the `len=` token), and requires predecessor + 1 == value before `proven`
can be true. A proposal that does not survive is recorded-but-not-accepted.

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
    m = re.search(r"^len=(\d+) ", text)
    return int(m.group(1)) if m else None


def with_len(text, n):
    out = re.sub(r"^(len=)\d+ ", r"\g<1>" + str(n) + " ", text)
    return out


length = parse_len(original)
if length is None:
    sys.exit(1)

# The minimal message-suffix length: 28 — the bare lookup token
# "${jndi:ldap://127.0.0.1:1/a}" (28 characters; the "connectivity check "
# prefix is inert — the vulnerable stack resolves the token wherever it
# appears, the fixed stack logs it literally). 28 is the empirical floor:
# at 27 the token loses its opening "${" and the message is left literal by
# the substitutor — no lookup on EITHER side, so no divergence.
MINIMAL = 28

proposal = with_len(original, MINIMAL)

# The adjacent point one step below: N=27 — the token without its opening
# "${" (the message is literal; the divergence is lost).
adjacent_claim = MINIMAL - 1
adjacent_fixture = with_len(original, adjacent_claim)

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
            "semantic": "jndi.lookup.message_suffix_length",
            # The DOMAIN PROJECTION: the coordinate is the declared
            # message-suffix length — the integer token that follows the
            # first `len=`.
            "extractor": {
                "kind": "embedded-integer",
                "radix": "10",
                "prefix": "len=",
            },
        },
        "boundary": {
            "predecessor": str(adjacent_claim),
            "predecessor_preserves": False,  # claimed: N=27 is literal, no lookup on either side
            "value": str(MINIMAL),
            "value_preserves": True,  # claimed: N=28 preserves the divergence
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
