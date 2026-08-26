#!/usr/bin/env python3
"""The Log4Shell JNDI-inject mutation provider — operator id `jndi-inject`,
mutation family {relation: seed-jndi-lookup, relation_version: v1}, target
axis `jndi.lookup`.

The court challenge is the sensitivity proof: a comparator that never sees a
JNDI lookup performed cannot be trusted to certify "no JNDI lookup". The
challenge runs ONE operator per target axis, and the operator's mutant must
move EXACTLY that dimension (specificity: nothing else may diverge). This
provider proposes the axis's OWN deterministic defect shape.

Unlike the synthetic-echo mutants of the earlier studies, this mutant
GENUINELY EXECUTES the historical defect: it is the vulnerable Log4j 2.14.1
launcher (builds/run-vuln.sh — the pinned, hermetic build product) run
against the court's fixture. The vulnerable stack performs the JNDI lookup
at log time (the "Error looking up JNDI resource" diagnostic fires), where
the fixed reference logs the message literally — so the mutant moves the
jndi.lookup axis and NOTHING else: exit stays 0 on both sides, and stderr
carries the identical log line on both sides. A court that fails to see the
seeded lookup, or conflates it with another axis, is refused — the
challenge records stay as evidence.

Protocol (spec/mutation.md): reads canonical JSON frf-mutation-request-v1,
writes canonical JSON frf-mutation-response-v1, echoing `request_id` (the
SHA-256 of the exact request bytes).
"""
import base64
import hashlib
import json
import sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-mutation-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()

target = req["target_axis"]
assert target == "jndi.lookup", req

# The mutant: run the vulnerable 2.14.1 stack against the court's fixture —
# the lookup is performed, the verdict line is emitted, exit stays 0. The
# launcher path is resolved relative to the staged case work directory (the
# side's cwd, exactly as the court's own sides resolve it).
MUTANT = (
    "#!/bin/sh\n"
    "# The seeded signal: the vulnerable Log4j 2.14.1 stack performs the\n"
    "# JNDI lookup the fixed reference leaves literal (CVE-2021-44228).\n"
    "exec builds/run-vuln.sh \"$1\"\n"
).encode()

response = {
    "schema_version": "frf-mutation-response-v1",
    "request_id": request_id,
    "mutant_base64": base64.b64encode(MUTANT).decode(),
    "expected_affected_surfaces": ["jndi.lookup"],
    "failure": None,
}

json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
