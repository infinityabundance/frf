#!/usr/bin/env python3
"""External comparator serving the `stderr` axis under the spec
{relation: eq, extractor: stderr-first-line} — the SAME specification the
in-binary comparator implements, so this program asks the SAME question while
being a completely different implementation (a Python comparator, not the frf
executable).

Protocol (spec/comparator.md): reads a canonical JSON
frf-comparator-request-v1 on stdin, writes a canonical JSON
frf-comparator-response-v1 on stdout. The raw side streams arrive base64.
"""
import base64
import json
import sys

req = json.load(sys.stdin)
assert req["schema_version"] == "frf-comparator-request-v1", req
assert req["axis"] == "stderr", req

ref = base64.b64decode(req["reference"]["stderr_base64"]).decode("utf-8", "replace")
cand = base64.b64decode(req["candidate"]["stderr_base64"]).decode("utf-8", "replace")
ref_first = ref.split("\n", 1)[0]
cand_first = cand.split("\n", 1)[0]

if ref_first == cand_first:
    response = {
        "schema_version": "frf-comparator-response-v1",
        "equivalent": True,
        "residuals": [],
        "indeterminate": False,
        "failure": None,
    }
else:
    response = {
        "schema_version": "frf-comparator-response-v1",
        "equivalent": False,
        "residuals": [
            {
                "surface": "first-diagnostic-line",
                "raw_reference": ref_first,
                "raw_candidate": cand_first,
            }
        ],
        "indeterminate": False,
        "failure": None,
    }

json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
