#!/usr/bin/env python3
"""External comparator serving the `stderr` axis under the spec
{relation: eq, extractor: stderr-first-line, residual_classifier: text} — the
SAME specification the in-binary comparator implements, so this program asks
the SAME question while being a completely different implementation (a Python
comparator, not the frf executable).

Protocol (spec/comparator.md): reads a canonical JSON
frf-comparator-request-v2 on stdin, writes a canonical JSON
frf-comparator-response-v2 on stdout. The raw side streams arrive base64.

The response MUST echo `request_id` — the SHA-256 of the exact request bytes
received — so the response cryptographically names the request it answers; a
court refuses a response that does not.
"""
import base64
import hashlib
import json
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-comparator-request-v2", req
assert req["axis"] == "stderr", req
request_id = hashlib.sha256(raw).hexdigest()

ref = base64.b64decode(req["reference"]["stderr_base64"]).decode("utf-8", "replace")
cand = base64.b64decode(req["candidate"]["stderr_base64"]).decode("utf-8", "replace")
ref_first = ref.split("\n", 1)[0]
cand_first = cand.split("\n", 1)[0]

base = {
    "schema_version": "frf-comparator-response-v2",
    "request_id": request_id,
    "indeterminate": False,
    "failure": None,
}

if ref_first == cand_first:
    response = {
        **base,
        "equivalent": True,
        "residuals": [],
    }
else:
    response = {
        **base,
        "equivalent": False,
        "residuals": [
            {
                "surface": "first-diagnostic-line",
                "raw_reference": ref_first,
                "raw_candidate": cand_first,
            }
        ],
    }

json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
