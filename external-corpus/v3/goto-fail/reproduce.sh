#!/bin/sh
# The Goto Fail (CVE-2014-1266) study — reproducibility kit.
#
#   ./reproduce.sh build   build the two verifier binaries from src/sslcheck.c
#                          (clean, and -DGO_TO_FAIL) and verify the pins
#   ./reproduce.sh run     regenerate the FULL LOCAL evidence tree under
#                          golden/work/goto-fail-verdict-study/ — never the
#                          public tracked tree
#   ./reproduce.sh publish the PUBLICATION TRANSFORM: full local evidence
#                          -> publish-detached -> external-corpus/v3/
#                          goto-fail/evidence/ (withholds the binaries + the
#                          mutation request, writes detached-objects.json)
#   ./reproduce.sh verify  re-derive + publish + byte-compare the committed
#                          publication; check every artifact pin
#
# The programs model the CVE-2014-1266 defect (a duplicated `goto fail;`
# skips the signature comparison); they execute NO historical vulnerable
# software — the buggy build is a synthetic simulator whose observable
# (acceptance of tampered records) is the defect's shape. No acknowledgement
# is required.
#
# PUBLICATION MODEL — the tracked evidence tree is the DETACHED
# publication: canonical documents + content identities only, no build
# products. It is produced ONLY by `publish` (the transform); `verify`
# re-derives the full tree, publishes it fresh, and diffs the two
# publications byte-for-byte: drift is a failure.
set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
GF="$ROOT/external-corpus/v3/goto-fail"
V3="$ROOT/external-corpus/v3"
FRF="$ROOT/target/debug/frf"
[ -x "$FRF" ] || { echo "build frf first: cargo build" >&2; exit 1; }

require_artifacts() {
  missing=""
  for f in sslcheck-clean sslcheck-buggy; do
    [ -f "$GF/builds/$f" ] || missing="$missing $f"
  done
  if [ -n "$missing" ]; then
    echo "missing build products:$missing" >&2
    echo "run ./reproduce.sh build first" >&2
    exit 1
  fi
}

WORK="$ROOT/golden/work/goto-fail-verdict-study"
EV="$WORK/ev"

cmd=${1:-usage}
case "$cmd" in
  build)
    echo "== building the two verifiers from src/sslcheck.c =="
    sh "$GF/build/build.sh"
    ;;
  run)
    require_artifacts
    echo "== running the full FRF study (LOCAL tree under golden/work) =="
    echo "   this NEVER touches the public tracked evidence/ tree =="
    sh "$GF/study.sh"
    echo
    echo "full local evidence tree: $EV"
    echo "to publish (withhold the binaries + write detached-objects.json):"
    echo "  ./reproduce.sh publish"
    ;;
  publish)
    require_artifacts
    echo "== running the full FRF study (the transform's input) =="
    sh "$GF/study.sh"
    echo "== deriving the publication policy (binaries + mutation request) =="
    POLICY=$(mktemp)
    trap 'rm -f "$POLICY"' EXIT
    python3 "$GF/derive-publish-policy.py" "$EV" "$GF/build/build-manifest.json" "$POLICY"
    echo "== the publication transform: full local evidence -> publish-detached =="
    rm -rf "$GF/evidence"
    "$FRF" --root "$EV" evidence publish-detached --policy "$POLICY" --output "$GF/evidence"
    echo
    echo "== the committed publication =="
    "$FRF" --root "$GF/evidence" evidence status
    ;;
  verify)
    require_artifacts
    echo "== re-deriving the study and publishing fresh =="
    sh "$GF/study.sh"
    POLICY=$(mktemp)
    PUB=$(mktemp -u "${TMPDIR:-/tmp}/frf-gf-pub-XXXXXX")
    trap 'rm -f "$POLICY"; rm -rf "$PUB"' EXIT
    python3 "$GF/derive-publish-policy.py" "$EV" "$GF/build/build-manifest.json" "$POLICY"
    "$FRF" --root "$EV" evidence publish-detached --policy "$POLICY" --output "$PUB"
    echo "== comparing the fresh publication against the committed one =="
    if diff -r "$PUB" "$GF/evidence" >/dev/null 2>&1; then
      echo "publication is deterministic: the regenerated publication matches the committed tree byte-for-byte"
    else
      echo "PUBLICATION DRIFT: the regenerated publication differs from the committed tree" >&2
      diff -rq "$PUB" "$GF/evidence" | head -20 >&2
      exit 1
    fi
    echo "== the committed publication's four-state verdict =="
    "$FRF" --root "$GF/evidence" evidence status
    ;;
  usage|*)
    echo "usage: ./reproduce.sh {build|run|publish|verify}"
    echo
    echo "  build   build the two verifiers (gcc; no container needed)"
    echo "  run     regenerate the FULL LOCAL evidence tree (golden/work; ignored)"
    echo "  publish the publication transform: full local evidence -> publish-detached -> evidence/"
    echo "  verify  re-derive + publish + byte-compare the committed publication; check pins"
    exit 0
    ;;
esac
