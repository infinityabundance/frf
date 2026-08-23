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
# "Trust but verify": build/run produce the evidence, verify re-derives it.
set -eu

# The repo root (this script lives at external-corpus/v3/heartbleed/).
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
HB="$ROOT/external-corpus/v3/heartbleed"
V3="$ROOT/external-corpus/v3"
FRF="$ROOT/target/debug/frf"
FRF_SOURCE="$ROOT/target/debug/frf"
[ -x "$FRF_SOURCE" ] || { echo "build frf first: cargo build" >&2; exit 1; }

cmd=${1:-usage}
case "$cmd" in
  build)
    echo "== rebuilding the pinned native artifacts (containerized) =="
    (cd "$V3" && sh build/build-all.sh)
    echo "== verifying the rebuilt artifacts against the pinned hashes =="
    sh "$0" verify-artifacts
    ;;
  run)
    echo "== running the full FRF study =="
    sh "$HB/study.sh"
    echo "== committing the regenerated evidence =="
    rm -rf "$HB/evidence"
    cp -r "$ROOT/golden/work/heartbleed-leak-study/ev" "$HB/evidence"
    echo "evidence regenerated under $HB/evidence"
    ;;
  verify)
    sh "$0" verify-artifacts
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
    echo "== checking the committed probe binaries against the pinned hashes =="
    python3 - "$HB" "$V3/build/build-manifest.json" <<'PY'
import hashlib, json, pathlib, sys
hb, manifest = pathlib.Path(sys.argv[1]), json.loads(open(sys.argv[2]).read())
bad = []
for rel, pinned in manifest["artifacts"].items():
    p = (hb.parent / rel)
    if not p.exists():
        # log4j/shellshock artifacts live under the v3 root, not the case dir
        p = (hb.parent / rel)
    if not p.exists():
        bad.append(f"MISSING {rel}")
        continue
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != pinned:
        bad.append(f"DRIFT {rel}: got {got[:16]} pinned {pinned[:16]}")
print("ok: all committed artifact hashes match build-manifest.json"
      if not bad else "\n".join(bad))
sys.exit(1 if bad else 0)
PY
    ;;
  usage|*)
    echo "usage: ./reproduce.sh {build|run|verify}"
    exit 0
    ;;
esac
