#!/usr/bin/env python3
"""The Goto Fail VERDICT comparator — serves the `tls.verdict` axis under
the spec {relation: eq, extractor: verdict-scan, residual_classifier: text,
relation_version: v1}.

The proposition is narrow and deterministic: does the candidate's verifier
accept EXACTLY the handshake records the reference accepts (CVE-2014-1266)?
A record whose signature does not match the data's checksum must be REFUSED;
the historical defect skipped the comparison, accepting everything.

The programs (external-corpus/v3/goto-fail/src/sslcheck.c) are the oracle:
the clean build refuses a mismatched record (exit 1 + a "tls: signature
mismatch" diagnostic on stderr) and accepts a valid one (exit 0 + "tls:
handshake accepted" on stdout); the buggy build accepts EVERYTHING. The
comparator therefore reads exit + the verdict line and asks exactly that
question — a verdict is a semantic observable, never a byte diff.

The projection (raw_reference / raw_candidate) is the side's verdict line
(first stdout line, else the first stderr line) — the residual names the
observed verdict, not the record bytes.

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
assert req["axis"] == "tls.verdict", req
request_id = hashlib.sha256(raw).hexdigest()


def classify(exit_code, stdout_bytes, stderr_text):
    """Return (accepted: bool, projection: str). A verdict is accepted iff
    the side reported the acceptance line (exit 0 alone is not enough — the
    line is the observable; a silent exit 0 is indeterminate, not accepted)."""
    out = stdout_bytes.decode("utf-8", "replace")
    first_out = out.split("\n", 1)[0] if out else ""
    first_err = stderr_text.split("\n", 1)[0] if stderr_text else ""
    accepted = exit_code == "0" and "handshake accepted" in first_out
    projection = first_out if first_out else first_err
    return accepted, projection


ref = req["reference"]
cand = req["candidate"]
ref_out = base64.b64decode(ref["stdout_base64"])
ref_err = base64.b64decode(ref["stderr_base64"]).decode("utf-8", "replace")
cand_out = base64.b64decode(cand["stdout_base64"])
cand_err = base64.b64decode(cand["stderr_base64"]).decode("utf-8", "replace")

ref_acc, ref_proj = classify(ref["exit"], ref_out, ref_err)
cand_acc, cand_proj = classify(cand["exit"], cand_out, cand_err)

base = {
    "schema_version": "frf-comparator-response-v2",
    "request_id": request_id,
    "indeterminate": False,
    "failure": None,
}

if ref_acc == cand_acc:
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
