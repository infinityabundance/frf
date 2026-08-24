#!/bin/sh
# The Goto Fail (CVE-2014-1266) semantic study — build the two verifiers.
#
# The defect is a duplicated `goto fail;` in Apple Secure Transport that
# skips the signature comparison, so every handshake is accepted. This kit
# builds a clean verifier and the buggy verifier (-DGO_TO_FAIL) from ONE C
# source, and pins both by SHA-256 in build-manifest.json — the same
# reproducibility discipline as the Heartbleed study, with no container
# needed (the program links nothing historical).
#
# Usage:  sh build/build.sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p builds

CC=${CC:-gcc}
$CC -O2 -o builds/sslcheck-clean src/sslcheck.c
$CC -O2 -DGO_TO_FAIL -o builds/sslcheck-buggy src/sslcheck.c

echo "== verifying the built artifacts against the pinned hashes =="
python3 - build/build-manifest.json <<'PY'
import hashlib, json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
drift = []
for rel, pinned in manifest["artifacts"].items():
    p = pathlib.Path(rel)
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != pinned:
        drift.append(f"DRIFT {rel}: got {got[:16]} pinned {pinned[:16]}")
if drift:
    print("\n".join(drift))
    sys.exit(1)
print("ok: all artifact hashes match build-manifest.json")
PY
echo "done: builds/sslcheck-clean + builds/sslcheck-buggy"
