#!/usr/bin/env python3
"""The Heartbleed ILLEGAL-RESPONSE comparator — serves the
`tls.heartbeat.illegal_response` axis under the spec
{relation: eq, extractor: verdict-scan, residual_classifier: text,
relation_version: v1}.

The proposition is narrow and deterministic: RFC 6520 §4 requires a peer to
DISCARD a malformed heartbeat — answering one is the vulnerability
(CVE-2014-0160). Did the side under test ANSWER the malformed heartbeat?

The probe (external-corpus/v3/heartbleed/src/hb.c) is the oracle: on the
vulnerable path it exits 1 and writes ONE verdict line to stderr
("HEARTBLEED: the linked libssl echoed N bytes in the heartbeat response");
on the fixed path it exits 0 with a "hb: no leak (...)" line on stdout and
nothing on stderr. The comparator therefore reads exit + stderr and asks
exactly that question. No content interpretation, no entropy heuristic, no
marker scanning: a malformed heartbeat that got a response is a violation,
whatever bytes came back. (The CANARY proposition — whether the exact
planted synthetic canary bytes escaped — is the `memory.leak.seeded_canary`
axis, a separate observable.)

The projection (raw_reference / raw_candidate) is the side's verdict line
(first stderr line, else the first stdout line) — the residual names the
observed answer, never any leaked content.

Protocol (spec/comparator.md): reads canonical JSON frf-comparator-request-v4
on stdin, writes canonical JSON frf-comparator-response-v2 on stdout.
`request_id` MUST be the SHA-256 of the exact request bytes received.
"""
import base64
import hashlib
import json
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-comparator-request-v4", req
assert req["axis"] == "tls.heartbeat.illegal_response", req
request_id = hashlib.sha256(raw).hexdigest()


def classify(exit_code, stdout_bytes, stderr_text):
    """Return (illegal_response: bool, projection: str)."""
    illegal = exit_code == "1" and "HEARTBLEED" in stderr_text
    first = stderr_text.split("\n", 1)[0] if stderr_text else ""
    if not first:
        first = stdout_bytes.decode("utf-8", "replace").split("\n", 1)[0]
    return illegal, first


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
                "surface": "verdict-scan",
                "raw_reference": ref_proj,
                "raw_candidate": cand_proj,
            }
        ],
    }

json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
