#!/usr/bin/env python3
"""The Heartbleed heap-noise normalizer — `strip-heap-noise`, applied to the
`stdout` stream under the spec {relation: mask-address-runs, applies_to:
stdout, relation_version: v1}.

The probe's leak dump is process memory: it carries ASLR-dependent
address-ish runs and long zero pads that differ between runs and between
builds, but are NOT the leak signal. This normalizer masks the volatile
hexadecimal runs (16+ hex digits — pointer/address-shaped) with a fixed
token before the comparator sees the stream, so the comparison focuses on
the leaked CONTENT (PEM markers, entropy-bearing material, the verdict
line), never on which heap addresses happened to be adjacent. Everything
else passes through byte-identical (the untouched stderr MUST come back
byte-identical or the court refuses).

Protocol (spec/normalizer.md): reads canonical JSON
frf-normalizer-request-v1 on stdin, writes canonical JSON
frf-normalizer-response-v1 on stdout, echoing `request_id` (the SHA-256 of
the exact request bytes).
"""
import base64
import hashlib
import json
import re
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-normalizer-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()

out_bytes = base64.b64decode(req["stdout_base64"])
err_bytes = base64.b64decode(req["stderr_base64"])

# Mask pointer/address-shaped runs: 16+ hex digits (with an optional 0x
# prefix) become a fixed token. Runs of 8-15 hex digits are kept — they may
# be real content. The verdict lines ("hb: no leak (...)", "HEARTBLEED: ...")
# contain no such runs and pass through untouched.
masked = re.sub(rb"(?:0x)?[0-9a-fA-F]{16,}", b"<addr>", out_bytes)

response = {
    "schema_version": "frf-normalizer-response-v1",
    "request_id": request_id,
    "stdout_base64": base64.b64encode(masked).decode(),
    "stderr_base64": base64.b64encode(err_bytes).decode(),
    "indeterminate": False,
    "failure": None,
}
json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
