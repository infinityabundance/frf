#!/bin/sh
# The Heartbleed (CVE-2014-0160) study — reproducibility kit.
#
#   ./reproduce.sh build   hermetically rebuild the 7 probe binaries
#                          (pinned container base + pinned NEVRAs + official
#                          OpenSSL 1.0.1a..g tarballs by SHA-256)
#   ./reproduce.sh run     regenerate the FULL LOCAL evidence tree under
#                          golden/work/heartbleed-leak-study/ — never the
#                          public tracked tree
#   ./reproduce.sh publish the PUBLICATION TRANSFORM: full local evidence
#                          -> publish-detached -> external-corpus/v3/
#                          heartbleed/evidence/ (withholds the probes + the
#                          mutation request, writes detached-objects.json)
#   ./reproduce.sh verify  re-derive + publish + byte-compare the committed
#                          publication; check every artifact pin
#
# HOSTILE-CODE WARNING
# --------------------
# This kit deliberately CONSTRUCTS AND EXECUTES historically vulnerable
# software: probe binaries linked against the CVE-2014-0160-vulnerable
# OpenSSL 1.0.1a..1.0.1f libraries. Running them is running real 2014-era
# exploit code against real vulnerable TLS stacks (loopback, self-contained,
# but still). Use an ISOLATED, DISPOSABLE environment. Every execution stage
# (run/publish/verify) requires an explicit acknowledgement:
#     FRF_HB_ACK=yes ./reproduce.sh run
#
# PUBLICATION MODEL
# -----------------
# The public tracked tree (external-corpus/v3/heartbleed/evidence/) is the
# DETACHED publication: canonical documents + content identities only, no
# payload bytes. It is produced ONLY by `publish` (the transform), never by
# `run` — a reproduction can never repopulate it by accident. `verify`
# re-derives the full tree, publishes it fresh, and diffs the two
# publications byte-for-byte: drift is a failure, and the committed tree can
# never silently absorb a new payload.
#
# The probe binaries are NOT committed (they are pinned, hermetic build
# products): a fresh clone runs `./reproduce.sh build` once.
#
# "Trust but verify": build/run produce the evidence, publish transforms it,
# verify re-derives and compares.
set -eu

# The repo root (this script lives at external-corpus/v3/heartbleed/).
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
HB="$ROOT/external-corpus/v3/heartbleed"
V3="$ROOT/external-corpus/v3"
FRF="$ROOT/target/debug/frf"
FRF_SOURCE="$ROOT/target/debug/frf"
[ -x "$FRF_SOURCE" ] || { echo "build frf first: cargo build" >&2; exit 1; }

# The execution stages require an explicit acknowledgement: this kit runs
# CVE-2014-0160-vulnerable software on purpose.
acknowledge() {
  if [ "${FRF_HB_ACK:-}" != "yes" ]; then
    echo "WARNING: this deliberately constructs and executes historically" >&2
    echo "vulnerable software (the CVE-2014-0160-vulnerable OpenSSL 1.0.1a..f" >&2
    echo "probes). Run it in an ISOLATED, DISPOSABLE environment." >&2
    echo "acknowledge with:  FRF_HB_ACK=yes $0 $1" >&2
    exit 1
  fi
}

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
WORK="$ROOT/golden/work/heartbleed-leak-study"
EV="$WORK/ev"

cmd=${1:-usage}
case "$cmd" in
  build)
    echo "== rebuilding the pinned native artifacts (containerized) =="
    (cd "$V3" && sh build/build-all.sh)
    echo "== verifying the rebuilt artifacts against the pinned hashes =="
    sh "$0" verify-artifacts
    ;;
  run)
    acknowledge run
    require_artifacts
    echo "== running the full FRF study (LOCAL tree under golden/work) =="
    echo "   this NEVER touches the public tracked evidence/ tree =="
    sh "$HB/study.sh"
    echo
    echo "full local evidence tree: $EV"
    echo "to publish (withhold the probes + write detached-objects.json):"
    echo "  ./reproduce.sh publish"
    ;;
  publish)
    acknowledge publish
    require_artifacts
    echo "== running the full FRF study (the transform's input) =="
    RECEIPT_FIXED=$(sh "$HB/study.sh" 2>&1 | sed -n 's/^receipt_g=//p' | tail -1)
    echo "== deriving the publication policy (probes + mutation request) =="
    POLICY=$(mktemp)
    trap 'rm -f "$POLICY"' EXIT
    python3 "$HB/derive-publish-policy.py" "$EV" "$V3/build/build-manifest.json" "$POLICY"
    echo "== the publication transform: full local evidence -> publish-detached =="
    rm -rf "$HB/evidence"
    "$FRF" --root "$EV" evidence publish-detached --policy "$POLICY" --output "$HB/evidence"
    echo
    echo "== the committed publication =="
    "$FRF" --root "$HB/evidence" evidence status
    echo
    portable_bundle "$EV" "$RECEIPT_FIXED" "$HB/bundle/portable.frf"
    ;;
  verify)
    acknowledge verify
    sh "$0" verify-artifacts
    require_artifacts
    echo "== re-deriving the study and publishing fresh =="
    RECEIPT_FIXED=$(sh "$HB/study.sh" 2>&1 | sed -n 's/^receipt_g=//p' | tail -1)
    POLICY=$(mktemp)
    PUB=$(mktemp -u "${TMPDIR:-/tmp}/frf-hb-pub-XXXXXX")
    trap 'rm -f "$POLICY"; rm -rf "$PUB"' EXIT
    python3 "$HB/derive-publish-policy.py" "$EV" "$V3/build/build-manifest.json" "$POLICY"
    "$FRF" --root "$EV" evidence publish-detached --policy "$POLICY" --output "$PUB"
    echo "== comparing the fresh publication against the committed one =="
    if diff -r "$PUB" "$HB/evidence" >/dev/null 2>&1; then
      echo "publication is deterministic: the regenerated publication matches the committed tree byte-for-byte"
    else
      echo "PUBLICATION DRIFT: the regenerated publication differs from the committed tree" >&2
      diff -rq "$PUB" "$HB/evidence" | head -20 >&2
      exit 1
    fi
    echo "== the committed publication's four-state verdict =="
    "$FRF" --root "$HB/evidence" evidence status
    echo
    portable_bundle "$EV" "$RECEIPT_FIXED" "$HB/bundle/portable.frf"
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
    echo "usage: ./reproduce.sh {build|run|publish|verify}"
    echo
    echo "  build   hermetically rebuild the 7 probe binaries (needs podman/docker + network)"
    echo "  run     regenerate the FULL LOCAL evidence tree (golden/work; ignored; never the public tree)"
    echo "  publish the publication transform: full local evidence -> publish-detached -> evidence/"
    echo "  verify  re-derive + publish + byte-compare the committed publication; check pins"
    echo
    echo "execution stages require: FRF_HB_ACK=yes (this kit runs CVE-2014-0160-vulnerable software)"
    exit 0
    ;;
esac
