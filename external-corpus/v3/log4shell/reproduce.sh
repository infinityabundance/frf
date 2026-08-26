#!/bin/sh
# The Log4Shell (CVE-2021-44228) study — reproducibility kit.
#
#   ./reproduce.sh build   hermetically rebuild the probe + fetch the pinned
#                          jars (pinned container base + pinned NEVRAs + a
#                          pinned JDK; the log4j jars are Maven Central
#                          artifacts pinned by SHA-256)
#   ./reproduce.sh run     regenerate the FULL LOCAL evidence tree under
#                          golden/work/log4shell-verdict-study/ — never the
#                          public tracked tree
#   ./reproduce.sh publish the PUBLICATION TRANSFORM: full local evidence
#                          -> publish-detached -> external-corpus/v3/
#                          log4shell/evidence/ (withholds the probe, the
#                          jars and the mutation request, writes
#                          detached-objects.json)
#   ./reproduce.sh verify  re-derive + publish + byte-compare the committed
#                          publication; check every artifact pin
#
# HOSTILE-CODE WARNING
# --------------------
# This kit deliberately CONSTRUCTS AND EXECUTES historically vulnerable
# software: the probe linked against the CVE-2021-44228-vulnerable Log4j
# 2.14.1/2.15.0/2.16.0 stacks. Running them is running real 2021-era
# exploit code against a loopback, self-contained, connection-refused
# endpoint (127.0.0.1:1 — no real exfiltration is possible), but still.
# Use an ISOLATED, DISPOSABLE environment. Every execution stage
# (run/publish/verify) requires an explicit acknowledgement:
#     FRF_L4S_ACK=yes ./reproduce.sh run
#
# PUBLICATION MODEL
# -----------------
# The public tracked tree (external-corpus/v3/log4shell/evidence/) is the
# DETACHED publication: canonical documents + content identities only, no
# payload bytes. It is produced ONLY by `publish` (the transform), never by
# `run` — a reproduction can never repopulate it by accident. `verify`
# re-derives the full tree, publishes it fresh, and diffs the two
# publications byte-for-byte: drift is a failure, and the committed tree can
# never silently absorb a new payload.
#
# The probe/jars are NOT committed (they are pinned, hermetic build/fetch
# products): a fresh clone runs `./reproduce.sh build` once.
#
# "Trust but verify": build/run produce the evidence, publish transforms it,
# verify re-derives and compares.
set -eu

# The repo root (this script lives at external-corpus/v3/log4shell/).
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
L4S="$ROOT/external-corpus/v3/log4shell"
V3="$ROOT/external-corpus/v3"
FRF="$ROOT/target/debug/frf"
FRF_SOURCE="$ROOT/target/debug/frf"
[ -x "$FRF_SOURCE" ] || { echo "build frf first: cargo build" >&2; exit 1; }

# The execution stages require an explicit acknowledgement: this kit runs
# CVE-2021-44228-vulnerable software on purpose.
acknowledge() {
  if [ "${FRF_L4S_ACK:-}" != "yes" ]; then
    echo "WARNING: this deliberately constructs and executes historically" >&2
    echo "vulnerable software (the CVE-2021-44228-vulnerable Log4j 2.14.1" >&2
    echo "stack). Run it in an ISOLATED, DISPOSABLE environment." >&2
    echo "acknowledge with:  FRF_L4S_ACK=yes $0 $1" >&2
    exit 1
  fi
}

# The study stages these launcher sets; refuse with a hint if not built.
require_artifacts() {
  missing=""
  for f in probe.jar lib/log4j-api-2.14.1.jar lib/log4j-core-2.14.1.jar \
           lib/log4j-api-2.15.0.jar lib/log4j-core-2.15.0.jar \
           lib/log4j-api-2.16.0.jar lib/log4j-core-2.16.0.jar \
           lib/log4j-api-2.17.1.jar lib/log4j-core-2.17.1.jar; do
    [ -f "$L4S/builds/$f" ] || missing="$missing $f"
  done
  if [ -n "$missing" ]; then
    echo "missing build products:$missing" >&2
    echo "the probe and jars are NOT committed (they are pinned, hermetic" >&2
    echo "build/fetch products) — run ./reproduce.sh build first (needs podman/docker + network)" >&2
    exit 1
  fi
}

# The portable-bundle step (Phase 3): a reviewer with ONLY the bundle — no
# source tree, no FRF installation — verifies the FIXED receipt from an
# EMPTY directory. `frf bundle export` carries the fixed receipt + its
# complete evidence closure; `frf bundle verify` (no --root) re-verifies it
# against the bundled evidence alone; the INDEPENDENT verifiers (xtask, Go
# — no frf library, no execution) reach the same verdict on the same bytes.
portable_bundle() {
  local ev="$1" receipt="$2" out="$3"
  echo "== the portable bundle: export + verify-from-empty-dir =="
  rm -rf "$(dirname "$out")"
  "$FRF" --root "$ev" bundle export "$receipt" --output "$out"
  EMPTY=$(mktemp -d)
  (cd "$EMPTY" && "$FRF" bundle verify "$out")
  rm -rf "$EMPTY"
  if [ -n "${XTASK_BIN:-}" ]; then
    "$XTASK_BIN" verify bundle "$out"
  elif [ -x "$ROOT/target/debug/xtask" ]; then
    "$ROOT/target/debug/xtask" verify bundle "$out"
  elif command -v cargo >/dev/null 2>&1; then
    (cd "$ROOT" && cargo xtask verify bundle "$out")
  fi
  if [ -n "${GO_VERIFIER:-}" ]; then
    "$GO_VERIFIER" verify bundle "$out"
  elif command -v go >/dev/null 2>&1; then
    (cd "$ROOT/verifier-go" && go run . verify bundle "$out")
  fi
}

# The full local evidence tree (complete, with objects) — the transform's
# input. Never committed (golden/work is ignored).
WORK="$ROOT/golden/work/log4shell-verdict-study"
EV="$WORK/ev"

cmd=${1:-usage}
case "$cmd" in
  build)
    echo "== rebuilding the pinned probe/jars (containerized + pinned fetch) =="
    (cd "$V3" && sh build/build-all.sh)
    echo "== verifying the rebuilt artifacts against the pinned hashes =="
    sh "$0" verify-artifacts
    ;;
  run)
    acknowledge run
    require_artifacts
    echo "== running the full FRF study (LOCAL tree under golden/work) =="
    echo "   this NEVER touches the public tracked evidence/ tree =="
    sh "$L4S/study.sh"
    echo
    echo "full local evidence tree: $EV"
    echo "to publish (withhold the probe + jars + write detached-objects.json):"
    echo "  ./reproduce.sh publish"
    ;;
  publish)
    acknowledge publish
    require_artifacts
    echo "== running the full FRF study (the transform's input) =="
    RECEIPT_FIXED=$(sh "$L4S/study.sh" 2>&1 | sed -n 's/^receipt_fixed=//p' | tail -1)
    echo "== deriving the publication policy (probe + jars + mutation request) =="
    POLICY=$(mktemp)
    trap 'rm -f "$POLICY"' EXIT
    python3 "$L4S/derive-publish-policy.py" "$EV" "$V3/build/build-manifest.json" "$POLICY"
    echo "== the publication transform: full local evidence -> publish-detached =="
    rm -rf "$L4S/evidence"
    "$FRF" --root "$EV" evidence publish-detached --policy "$POLICY" --output "$L4S/evidence"
    echo
    echo "== the committed publication =="
    "$FRF" --root "$L4S/evidence" evidence status
    echo
    portable_bundle "$EV" "$RECEIPT_FIXED" "$L4S/bundle/portable.frf"
    ;;
  verify)
    acknowledge verify
    sh "$0" verify-artifacts
    require_artifacts
    echo "== re-deriving the study and publishing fresh =="
    RECEIPT_FIXED=$(sh "$L4S/study.sh" 2>&1 | sed -n 's/^receipt_fixed=//p' | tail -1)
    POLICY=$(mktemp)
    PUB=$(mktemp -u "${TMPDIR:-/tmp}/frf-l4s-pub-XXXXXX")
    trap 'rm -f "$POLICY"; rm -rf "$PUB"' EXIT
    python3 "$L4S/derive-publish-policy.py" "$EV" "$V3/build/build-manifest.json" "$POLICY"
    "$FRF" --root "$EV" evidence publish-detached --policy "$POLICY" --output "$PUB"
    echo "== comparing the fresh publication against the committed one =="
    if diff -r "$PUB" "$L4S/evidence" >/dev/null 2>&1; then
      echo "publication is deterministic: the regenerated publication matches the committed tree byte-for-byte"
    else
      echo "PUBLICATION DRIFT: the regenerated publication differs from the committed tree" >&2
      diff -rq "$PUB" "$L4S/evidence" | head -20 >&2
      exit 1
    fi
    echo "== the committed publication's four-state verdict =="
    "$FRF" --root "$L4S/evidence" evidence status
    echo
    portable_bundle "$EV" "$RECEIPT_FIXED" "$L4S/bundle/portable.frf"
    ;;
  verify-artifacts)
    echo "== checking the probe/jars against the pinned hashes =="
    python3 - "$L4S" "$V3/build/build-manifest.json" <<'PY'
import hashlib, json, pathlib, sys
case, manifest = pathlib.Path(sys.argv[1]), json.loads(open(sys.argv[2]).read())
prefix = "log4shell/builds/"
drift, missing = [], []
for rel, pinned in manifest["artifacts"].items():
    if not rel.startswith(prefix):
        continue
    p = case.parent.parent / rel
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
    echo "usage: ./reproduce.sh {build|run|publish|verify}"
    echo
    echo "  build   hermetically rebuild the probe + fetch the pinned jars (needs podman/docker + network)"
    echo "  run     regenerate the FULL LOCAL evidence tree (golden/work; ignored; never the public tree)"
    echo "  publish the publication transform: full local evidence -> publish-detached -> evidence/"
    echo "  verify  re-derive + publish + byte-compare the committed publication; check pins"
    echo
    echo "execution stages require: FRF_L4S_ACK=yes (this kit runs CVE-2021-44228-vulnerable software)"
    exit 0
    ;;
esac
