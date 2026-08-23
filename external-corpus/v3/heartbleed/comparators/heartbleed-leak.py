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
against the OpenSSL under test. On the leak path the probe:

  * exits 1,
  * writes the leaked heartbeat-response bytes (the echoed process memory)
    to stdout BEFORE the verdict line,
  * writes the verdict to stderr:
    "HEARTBLEED: the linked libssl echoed N bytes in the heartbeat response".

On the fixed path it exits 0 with a "hb: no leak (...)" line on stdout and
nothing on stderr. A leak is therefore a SEMANTIC signal, and this comparator
recognizes three independent signals (any one suffices, fail-open only toward
the leak — a miss is the dangerous direction):

  1. the probe's own verdict  — exit 1 + "HEARTBLEED" on stderr;
  2. a known sensitive marker in the echoed content — PEM private-key /
     certificate headers, SECRET_KEY= assignments (the seeded-leak challenge
     mutant prints exactly these);
  3. a binary dump (non-printable content beyond whitespace) whose Shannon
     entropy exceeds 0.9 bits/byte — the genuine key-material case the
     historical leak produced. (The probe's own buffer leak is low-entropy —
     mostly zeroed memory — which is why signals 1-2 carry the study; signal
     3 is the general detector for a real key dump.)

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
import collections
import hashlib
import json
import math
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


def shannon_entropy(data):
    if not data:
        return 0.0
    n = len(data)
    freq = collections.Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def looks_like_binary_dump(data):
    # Non-printable bytes beyond whitespace: the heartbeat-response dump is
    # binary process memory; the probe's ASCII verdict lines are not.
    return any(b < 0x09 or (0x0E <= b <= 0x1F) or b >= 0x7F for b in data)


def classify(exit_code, stdout_bytes, stderr_text):
    """Return (leak: bool, projection: str)."""
    signals = []
    projection = ""
    verdict = exit_code == "1" and "HEARTBLEED" in stderr_text
    if verdict:
        signals.append("probe-verdict")
    for marker in SENSITIVE_MARKERS:
        if marker in stdout_bytes:
            signals.append("marker")
            if not projection:
                # the first line containing a sensitive marker
                for line in stdout_bytes.split(b"\n"):
                    if marker in line:
                        projection = line.decode("utf-8", "replace")
                        break
    if looks_like_binary_dump(stdout_bytes) and len(stdout_bytes) > 64:
        ent = shannon_entropy(stdout_bytes)
        if ent > 0.9:
            signals.append("high-entropy")
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
