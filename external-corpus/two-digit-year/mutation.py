#!/usr/bin/env python3
# The external mutation provider for the two-digit-year court: proposes a
# mutant of the reference that REINTRODUCES the Y2K bug — the 20YY window
# is removed, so every two-digit year maps to 19YY. The court decides the
# verdicts from the run.
import base64, hashlib, json, sys

raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
assert req["schema_version"] == "frf-mutation-request-v1", req
request_id = hashlib.sha256(raw).hexdigest()
ref = base64.b64decode(req["reference_artifact"]["contents_base64"]).decode("utf-8")
marker = '[0-6][0-9]) yyyy="20$yy"'
assert marker in ref, "the reference must carry the Y2K window"
mutant = ref.replace(marker, '[0-6][0-9]) yyyy="19$yy"')
assert mutant != ref, "the mutant must differ from the reference"
response = {
    "schema_version": "frf-mutation-response-v1",
    "request_id": request_id,
    "mutant_base64": base64.b64encode(mutant.encode("utf-8")).decode("ascii"),
    "expected_affected_surfaces": ["structured.state"],
    "failure": None,
}
json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
