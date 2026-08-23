#!/bin/sh
# The Heartbleed (CVE-2014-0160) study — reproducibility kit.
#
#   ./reproduce.sh build   hermetically rebuild the 7 probe binaries
#                          (pinned container base + pinned NEVRAs + official
#                          OpenSSL 1.0.1a..g tarballs by SHA-256)
#   ./reproduce.sh run     regenerate evidence/ — the full FRF flow: admit,
#                          leak courts, the version series a..g, the seed-leak
#                          challenge, the claimed-length minimization, and the
#                          sensitivity-backed claim
#   ./reproduce.sh verify  re-derive the study and check every committed
#                          artifact hash and evidence id against the pins
#
# The probe binaries are NOT committed (they are build products, pinned by
# SHA-256 in ../build/build-manifest.json): a fresh clone must run
# `./reproduce.sh build` first (needs podman/docker + network). run/verify
# refuse with a hint when the artifacts are absent; verify-artifacts treats
# an absent artifact as an unbuilt product and only fails on DRIFT.
#
# "Trust but verify": build/run produce the evidence, verify re-derives it.
set -eu

# The repo root (this script lives at external-corpus/v3/heartbleed/).
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
HB="$ROOT/external-corpus/v3/heartbleed"
V3="$ROOT/external-corpus/v3"
FRF="$ROOT/target/debug/frf"
FRF_SOURCE="$ROOT/target/debug/frf"
[ -x "$FRF_SOURCE" ] || { echo "build frf first: cargo build" >&2; exit 1; }

# The study stages these probe binaries; refuse with a hint if not built.
require_artifacts() {
  missing=""
  for f in hb-1.0.1a hb-1.0.1b hb-1.0.1c hb-1.0.1d hb-1.0.1e hb-1.0.1f hb-1.0.1g; do
    [ -f "$HB/builds/$f" ] || missing="$missing $f"
  done
  if [ -n "$missing" ]; then
    echo "missing build products:$missing" >&2
    echo "the probe binaries are NOT committed (they are pinned, hermetic build" >&2
    echo "products) — run ./reproduce.sh build first (needs podman/docker + network)" >&2
    exit 1
  fi
}

cmd=${1:-usage}
case "$cmd" in
  build)
    echo "== rebuilding the pinned native artifacts (containerized) =="
    (cd "$V3" && sh build/build-all.sh)
    echo "== verifying the rebuilt artifacts against the pinned hashes =="
    sh "$0" verify-artifacts
    ;;
  run)
    require_artifacts
    echo "== running the full FRF study =="
    sh "$HB/study.sh"
    echo "== committing the regenerated evidence =="
    rm -rf "$HB/evidence"
    cp -r "$ROOT/golden/work/heartbleed-leak-study/ev" "$HB/evidence"
    echo "evidence regenerated under $HB/evidence"
    ;;
  verify)
    sh "$0" verify-artifacts
    require_artifacts
    echo "== re-deriving the study and comparing the committed evidence =="
    sh "$HB/study.sh"
    if diff -r "$ROOT/golden/work/heartbleed-leak-study/ev" "$HB/evidence" >/dev/null 2>&1; then
      echo "evidence is deterministic: the regenerated tree matches the committed tree byte-for-byte"
    else
      echo "EVIDENCE DRIFT: the regenerated tree differs from the committed tree" >&2
      exit 1
    fi
    ;;
  verify-artifacts)
    echo "== checking the probe binaries against the pinned hashes =="
    python3 - "$HB" "$V3/build/build-manifest.json" <<'PY'
import hashlib, json, pathlib, sys
hb, manifest = pathlib.Path(sys.argv[1]), json.loads(open(sys.argv[2]).read())
drift, missing = [], []
for rel, pinned in manifest["artifacts"].items():
    p = hb.parent / rel
    if not p.exists():
        missing.append(rel)
        continue
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != pinned:
        drift.append(f"DRIFT {rel}: got {got[:16]} pinned {pinned[:16]}")
if drift:
    print("ARTIFACT DRIFT:\n" + "\n".join(drift))
    sys.exit(1)
if missing:
    print(f"note: {len(missing)} build product(s) absent — they are NOT committed;")
    print("      run ./reproduce.sh build to materialize them (needs podman/docker + network)")
else:
    print("ok: all artifact hashes match build-manifest.json")
PY
    ;;
  usage|*)
    echo "usage: ./reproduce.sh {build|run|verify}"
    exit 0
    ;;
esac
