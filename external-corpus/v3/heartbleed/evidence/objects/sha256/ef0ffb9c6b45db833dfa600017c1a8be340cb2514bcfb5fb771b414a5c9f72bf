#!/usr/bin/env python3
"""The Heartbleed information-leak comparator — serves the `memory.leak.sensitive`
axis under the spec {relation: eq, extractor: leak-scan,
residual_classifier: text, relation_version: v1}.

This is the semantic judgement the user asked for: the axis does NOT ask "did
the two sides print different bytes" (a byte diff cannot tell a leak from a
harmless difference). It asks "did the candidate's observable surface report a
leak of process memory in response to the malformed heartbeat" — the actual
vulnerability, CVE-2014-0160.

The sides are the hb probe (external-corpus/v3/heartbleed/src/hb.c) linked
against the OpenSSL under test. RAW-MEMORY PUBLICATION BOUNDARY: the probe
never writes the echoed process memory to any observed stream. On the leak
path it:

  * exits 1,
  * writes ONE projection line to stdout:
      hb-leak-projection len=N sha256=<hex> canary=<present|absent> fraction=F
    (the response length, the SHA-256 commitment of the exact echoed window,
    and whether the planted synthetic canary appeared in it),
  * writes the verdict to stderr:
    "HEARTBLEED: the linked libssl echoed N bytes in the heartbeat response".

On the fixed path it exits 0 with a "hb: no leak (...)" line on stdout and
nothing on stderr. A leak is therefore a SEMANTIC signal, and this comparator
recognizes three independent signals (any one suffices, fail-open only toward
the leak — a miss is the dangerous direction):

  1. the probe's own verdict  — exit 1 + "HEARTBLEED" on stderr;
  2. a well-formed leak projection — len > 0 and a 64-hex sha256 (the
     commitment is present, so the content was observed even though the raw
     bytes are deliberately not published);
  3. a known sensitive marker in the echoed content — PEM private-key /
     certificate headers, SECRET_KEY= assignments (the seeded-leak challenge
     mutant prints exactly these).

The Shannon-entropy heuristic is GONE: the projection is the semantic
signal, and the planted canary — not an entropy guess — is the
memory-disclosure proof.

The projection (raw_reference / raw_candidate) follows the extractor: the
first line of the side's diagnostic surface — the reference's no-leak line
vs the candidate's "HEARTBLEED" verdict line. For the seeded-leak mutant
(no stderr verdict) the candidate projection is the first matched marker
line, so the residual still names what leaked.

Protocol (spec/comparator.md): reads canonical JSON
frf-comparator-request-v4 on stdin, writes canonical JSON
frf-comparator-response-v2 on stdout. `request_id` MUST be the SHA-256 of the
exact request bytes received.
"""
import base64
import hashlib
import json
import re
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-comparator-request-v4", req
assert req["axis"] == "memory.leak.sensitive", req
request_id = hashlib.sha256(raw).hexdigest()

SENSITIVE_MARKERS = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN CERTIFICATE-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"SECRET_KEY=",
    b"BEGIN OPENSSH PRIVATE KEY",
]

PROJECTION_RE = re.compile(
    rb"hb-leak-projection\s+len=(\d+)\s+sha256=([0-9a-f]{64})"
    rb"\s+canary=(present|absent)"
)


def classify(exit_code, stdout_bytes, stderr_text):
    """Return (leak: bool, projection: str)."""
    signals = []
    projection = ""
    verdict = exit_code == "1" and "HEARTBLEED" in stderr_text
    if verdict:
        signals.append("probe-verdict")
    m = PROJECTION_RE.search(stdout_bytes)
    if m:
        length = int(m.group(1))
        if length > 0:
            signals.append("leak-projection")
            if not projection:
                projection = stdout_bytes.decode("utf-8", "replace").split("\n", 1)[0]
    for marker in SENSITIVE_MARKERS:
        if marker in stdout_bytes:
            signals.append("marker")
            if not projection:
                # the first line containing a sensitive marker
                for line in stdout_bytes.split(b"\n"):
                    if marker in line:
                        projection = line.decode("utf-8", "replace")
                        break
    if not projection:
        # the diagnostic surface: the candidate's first stderr line, else its
        # first stdout line (the no-leak verdicts live on stdout)
        first = stderr_text.split("\n", 1)[0] if stderr_text else ""
        if not first:
            first = stdout_bytes.decode("utf-8", "replace").split("\n", 1)[0]
        projection = first
    return bool(signals), projection


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
                "surface": "leak-scan",
                "raw_reference": ref_proj,
                "raw_candidate": cand_proj,
            }
        ],
    }

json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
