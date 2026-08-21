#!/usr/bin/env python3
# The external mutation provider for the heartbleed court: proposes a mutant
# of the reference that REINTRODUCES CVE-2014-0160 — the bounds check is
# disabled, so a truncated record is echoed instead of refused. The court
# decides the verdicts from the run.
import base64, hashlib, json, sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-mutation-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()
ref = base64.b64decode(req["reference_artifact"]["contents_base64"]).decode("utf-8")
marker = 'if [ "$decl_num" -gt "$actual" ]; then'
assert marker in ref, "the reference must contain the bounds check"
mutant = ref.replace(marker, "if false; then")
assert mutant != ref, "the mutant must differ from the reference"
response = {
    "schema_version": "frf-mutation-response-v1",
    "request_id": request_id,
    "mutant_base64": base64.b64encode(mutant.encode("utf-8")).decode("ascii"),
    "expected_affected_surfaces": ["bytes.wire"],
    "failure": None,
}
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
