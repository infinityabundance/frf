#!/usr/bin/env python3
"""The Log4Shell LOOKUP comparator — serves the `jndi.lookup` axis under
the spec {relation: eq, extractor: jndi-scan, residual_classifier: text,
relation_version: v1}.

The proposition is narrow and deterministic: does the candidate's logging
stack perform the JNDI lookup exactly when the fixed reference performs it
(CVE-2021-44228)? A message containing a JNDI lookup expression
("${jndi:ldap://...}") must be logged LITERALLY; the historical defect
resolved it at log time, contacting an attacker-controlled endpoint.

The probe (external-corpus/v3/log4shell/src/Log4ShellProbe.java) is the
oracle: it registers a StatusListener, logs the fixture message through
Log4j 2, and emits a deterministic first stdout line —
`JNDI_LOOKUP_ATTEMPTED` (the "Error looking up JNDI resource" diagnostic
fired) or `JNDI_LOOKUP_NOT_ATTEMPTED` (no lookup) — followed, in the
attempted case, by the captured diagnostic line itself. The comparator
therefore reads the verdict line and asks exactly that question — a lookup
is a semantic observable, never a byte diff.

The projection (raw_reference / raw_candidate) is the side's verdict line
(first stdout line, else the first stderr line) — the residual names the
observed lookup verdict, not the log bytes.

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
assert req["axis"] == "jndi.lookup", req
request_id = hashlib.sha256(raw).hexdigest()


def classify(exit_code, stdout_bytes, stderr_text):
    """Return (attempted: bool, projection: str). A lookup is ATTEMPTED iff
    the side reported the verdict line; any other first line is
    indeterminate (the probe's contract is deterministic, so an unexpected
    first line is a broken side, never a verdict)."""
    out = stdout_bytes.decode("utf-8", "replace")
    first_out = out.split("\n", 1)[0] if out else ""
    first_err = stderr_text.split("\n", 1)[0] if stderr_text else ""
    if first_out == "JNDI_LOOKUP_ATTEMPTED":
        attempted = True
    elif first_out == "JNDI_LOOKUP_NOT_ATTEMPTED":
        attempted = False
    else:
        return None, (first_out if first_out else first_err)
    projection = first_out if first_out else first_err
    return attempted, projection


ref = req["reference"]
cand = req["candidate"]
ref_out = base64.b64decode(ref["stdout_base64"])
ref_err = base64.b64decode(ref["stderr_base64"]).decode("utf-8", "replace")
cand_out = base64.b64decode(cand["stdout_base64"])
cand_err = base64.b64decode(cand["stderr_base64"]).decode("utf-8", "replace")

ref_att, ref_proj = classify(ref["exit"], ref_out, ref_err)
cand_att, cand_proj = classify(cand["exit"], cand_out, cand_err)

base = {
    "schema_version": "frf-comparator-response-v2",
    "request_id": request_id,
    "indeterminate": False,
    "failure": None,
}

if ref_att is None or cand_att is None:
    response = {
        **base,
        "indeterminate": True,
        "failure": "a side's first stdout line was not a deterministic probe verdict",
        "residuals": [],
    }
elif ref_att == cand_att:
    response = {**base, "equivalent": True, "residuals": []}
else:
    response = {
        **base,
        "equivalent": False,
        "residuals": [
            {
                "surface": "jndi-scan",
                "raw_reference": ref_proj,
                "raw_candidate": cand_proj,
            }
        ],
    }

json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
