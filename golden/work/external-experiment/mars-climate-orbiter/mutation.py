#!/usr/bin/env python3
# The external mutation provider for the mars-climate-orbiter court:
# proposes a mutant of the reference that REINTRODUCES the 1999 unit bug —
# the lbf-s to N-s conversion is dropped, so the raw value is consumed as
# newton-seconds. The court decides the verdicts from the run.
import base64, hashlib, json, sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-mutation-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()
ref = base64.b64decode(req["reference_artifact"]["contents_base64"]).decode("utf-8")
marker = "v * 4.4482216152605"
assert marker in ref, "the reference must carry the unit conversion"
mutant = ref.replace(marker, "v")
assert mutant != ref, "the mutant must differ from the reference"
response = {
    "schema_version": "frf-mutation-response-v1",
    "request_id": request_id,
    "mutant_base64": base64.b64encode(mutant.encode("utf-8")).decode("ascii"),
    "expected_affected_surfaces": ["structured.state"],
    "failure": None,
}
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
