#!/usr/bin/env python3
"""The Heartbleed SEEDED-CANARY comparator — serves the
`memory.leak.seeded_canary` axis under the spec
{relation: eq, extractor: canary-scan, residual_classifier: text,
relation_version: v1}.

The proposition is narrow and deterministic: the probe PLANTED a known,
deliberately synthetic canary byte-string in its own heap before the
handshake (the canary is published in the probe source — it is NOT secret).
Did those EXACT bytes escape the library in the malformed-heartbeat
response?

The probe answers on its projection line, written to stdout ONLY on the
leak path:

    hb-leak-projection len=N sha256=<hex> canary=present|absent fraction=F

where len is the echoed window's size, sha256 is the SHA-256 commitment of
the EXACT echoed bytes, and canary=present means the full planted seed
appeared in that window. The comparator asks one question: is there a
well-formed projection whose canary is present? A projection with
canary=absent, or no projection at all, is not this proposition (an illegal
response that echoed non-canary memory is the `tls.heartbeat.illegal_response`
axis — a separate observable; and the SHA-256 commitment still records the
echoed window's identity either way). No entropy heuristic, no
private-key-looking markers, no interpretation: the seeded canary either
escaped or it did not.

The projection (raw_reference / raw_candidate) is the side's first stdout
line — the residual names the canary observation, never any leaked content.

Protocol (spec/comparator.md): reads canonical JSON frf-comparator-request-v4
on stdin, writes canonical JSON frf-comparator-response-v2 on stdout.
`request_id` MUST be the SHA-256 of the exact request bytes received.
"""
import base64
import hashlib
import json
import re
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-comparator-request-v4", req
assert req["axis"] == "memory.leak.seeded_canary", req
request_id = hashlib.sha256(raw).hexdigest()

PROJECTION_RE = re.compile(
    rb"hb-leak-projection\s+len=(\d+)\s+sha256=([0-9a-f]{64})"
    rb"\s+canary=(present|absent)"
)


def classify(exit_code, stdout_bytes, stderr_text):
    """Return (canary_escaped: bool, projection: str)."""
    m = PROJECTION_RE.search(stdout_bytes)
    if m and int(m.group(1)) > 0 and m.group(3) == b"present":
        # The full seeded canary appeared in the echoed window.
        return True, stdout_bytes.decode("utf-8", "replace").split("\n", 1)[0]
    first = stderr_text.split("\n", 1)[0] if stderr_text else ""
    if not first:
        first = stdout_bytes.decode("utf-8", "replace").split("\n", 1)[0]
    return False, first


ref = req["reference"]
cand = req["candidate"]
ref_out = base64.b64decode(ref["stdout_base64"])
ref_err = base64.b64decode(ref["stderr_base64"]).decode("utf-8", "replace")
cand_out = base64.b64decode(cand["stdout_base64"])
cand_err = base64.b64decode(cand["stderr_base64"]).decode("utf-8", "replace")

ref_leak, ref_proj = classify(ref["exit"], ref_out, ref_err)
cand_leak, cand_proj = classify(cand["exit"], cand_out, cand_err)

base = {
    "schema_version": "frf-comparator-response-v2",
    "request_id": request_id,
    "indeterminate": False,
    "failure": None,
}

if ref_leak == cand_leak:
    response = {**base, "equivalent": True, "residuals": []}
else:
    response = {
        **base,
        "equivalent": False,
        "residuals": [
            {
                "surface": "canary-scan",
                "raw_reference": ref_proj,
                "raw_candidate": cand_proj,
            }
        ],
    }

json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
