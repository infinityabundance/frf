#!/bin/sh
# Golden path: the entire canonical loop in one command.
#
#   Authority -> Court -> Capture -> Residual -> Endoduction -> Route
#   -> Disposition -> Receipt -> Claim
#
# Run from the repository root:  ./golden/demo.sh
#
# You will watch, end to end: an authority admitted, a court run, raw output
# captured, two residuals preserved with open disposition, an endoduction
# token emitted for each, a positive claim refused while they are open, the
# candidate patched and verified by a NEW court run (the closure evidence a
# `fixed` disposition must point at), both residuals disposed (fixed +
# intentional), the original receipt kept forever as a failure record, and a
# bounded claim compiled from the run that actually observed the pass, with
# the Section 12 non-claim printed next to it.
set -u

cd "$(dirname "$0")/.."

if command -v frf >/dev/null 2>&1; then
  FRF_BIN=${FRF_BIN:-frf}
else
  cargo build --release --quiet
  # Absolute: the bundle-verify step runs from a subshell in golden/work.
  FRF_BIN=${FRF_BIN:-$PWD/target/release/frf}
fi
ROOT=frf

# Regenerate the evidence tree (courts/ is source and is kept).
rm -rf "$ROOT"/authorities "$ROOT"/captures "$ROOT"/residuals "$ROOT"/series "$ROOT"/trajectories "$ROOT"/receipts "$ROOT"/claims "$ROOT"/challenges "$ROOT"/reductions
mkdir -p "$ROOT"/authorities "$ROOT"/captures "$ROOT"/residuals "$ROOT"/series "$ROOT"/trajectories "$ROOT"/receipts "$ROOT"/claims "$ROOT"/challenges
rm -rf golden/work
mkdir -p golden/work

step() { printf '\n== %s ==\n' "$*"; }

step "1. admit the authority (golden/reference.sh as ref-cli 1.8.2)"
"$FRF_BIN" --root "$ROOT" authority admit golden/reference.sh --name ref-cli --version 1.8.2

step "2. run the court (authority vs candidate on the malformed fixture, 3 repetitions)"
RUN_ID=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-malformed-input/manifest.yaml --repeat 3)
echo "run: $RUN_ID"
echo "-- the deterministic divergence is re-observed every repetition: drift/slew become evidence (see trajectories/)"

step "2b. the negative controls — the court must prove it can see"
# A passing court proves nothing unless it can SEE the defect classes it
# declares: the challenge runs the court against a MUTANT candidate per
# declared observable (a deterministic wrapper of the reference that alters
# exactly that one dimension — exit class, or the first stderr line — and
# preserves everything else byte-for-byte) and requires a divergence on the
# targeted axis and only on it. A court that is blind to a seeded defect, or
# conflates it with another axis, is refused.
echo "-- exit-class mutant and stderr-first-line mutant: the court must see each seeded defect and nothing else"
"$FRF_BIN" --root "$ROOT" court challenge frf/courts/cli-malformed-input/manifest.yaml

step "3. try to compile a claim while both residuals are open (must be refused)"
RECEIPT_OPEN=$("$FRF_BIN" --root "$ROOT" receipt emit "$RUN_ID")
if "$FRF_BIN" --root "$ROOT" claim compile "$RECEIPT_OPEN" 2>golden/work/refusal.txt; then
  echo "FAIL: a positive claim compiled while residuals were open" >&2
  exit 1
fi
cat golden/work/refusal.txt

step "4. resolve: patch the candidate's exit class, verify with a NEW court run, then dispose"
sed -e 's/exit 1$/exit 2/' \
    -e "s/(1 instead of the reference's 2)/(2, matching the reference)/" \
    -e 's/This divergence is the whole point of the court./The remaining divergence is the diagnostic wording./' \
    golden/candidate.sh > golden/work/candidate-fixed.sh
chmod +x golden/work/candidate-fixed.sh
echo "-- re-run the court against the patched candidate (the exit axis must close; the wording divergence is re-observed)"
RESOLUTION_RUN=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-malformed-input/manifest-candidate-fixed.yaml)
echo "resolution run: $RESOLUTION_RUN"
echo "-- dispose cli-exit-0001 as fixed, backed by that run (a disposition is not evidence)"
"$FRF_BIN" --root "$ROOT" residual dispose cli-exit-0001 --disposition fixed \
  --resolution-run "$RESOLUTION_RUN" \
  --reason "candidate patched to preserve reference exit class (golden/work/candidate-fixed.sh)"
echo "-- dispose the wording divergence as intentional (documented, never parity)"
"$FRF_BIN" --root "$ROOT" residual dispose cli-text-0001 --disposition intentional \
  --reason "clearer diagnostic wording; documented divergence"
"$FRF_BIN" --root "$ROOT" residual dispose cli-text-0002 --disposition intentional \
  --reason "clearer diagnostic wording; documented divergence (re-observed by the resolution run)"

step "5. the original receipt stays what it was; the claim comes from the run that observed the pass"
RECEIPT_ORIGINAL=$("$FRF_BIN" --root "$ROOT" receipt emit "$RUN_ID")
echo "-- the original (failing) run's receipt can never yield a parity claim, however its residuals are disposed:"
if "$FRF_BIN" --root "$ROOT" claim compile "$RECEIPT_ORIGINAL" 2>golden/work/original-refusal.txt; then
  echo "FAIL: the failing run's receipt compiled a parity claim" >&2
  exit 1
fi
cat golden/work/original-refusal.txt

echo "-- emit the resolution run's receipt and compile the bounded claim from it"
RECEIPT_FINAL=$("$FRF_BIN" --root "$ROOT" receipt emit "$RESOLUTION_RUN")
if ! "$FRF_BIN" --root "$ROOT" claim compile "$RECEIPT_FINAL"; then
  echo "FAIL: the bounded claim did not compile from the resolution run's receipt" >&2
  exit 1
fi

step "6. the generalized trajectory axes — revisions, versions, environments"
# The candidate_revision axis: one run per candidate artifact (a version
# ladder of the candidate). The exit lineage is observed against the
# original candidate and ABSENT against the fixed one: a boundary-localized
# cessation across revisions.
REV_RUN=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-malformed-input/manifest.yaml --candidate-revisions golden/candidate.sh,golden/work/candidate-fixed.sh)
echo "candidate-revision series run: $REV_RUN"
# The environment axis: this run is one point of the environment experiment
# at the declared coordinate; re-running with another label on another
# machine accumulates the series.
ENV_RUN=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-malformed-input/manifest.yaml --environment-point golden-machine)
echo "environment series run: $ENV_RUN"

step "7. the portable bundle — verified away from the evidence tree"
BUNDLE=golden/work/portable.frf
"$FRF_BIN" --root "$ROOT" bundle export "$RECEIPT_FINAL" --output "$BUNDLE"
# Verify from inside golden/work, where no evidence tree exists: the bundle
# alone must authenticate the evidence graph (its closure carries the series
# and trajectory records the receipt's evidence participates in).
(cd golden/work && "$FRF_BIN" bundle verify portable.frf)

step "7b. the single-file bundle — one sealed archive, verified and replayed alone"
# The same evidence graph sealed as ONE deterministic tar archive (the
# manifest inside declares the container). Verification never depends on
# where it runs; replay from a foreign directory is a SEMANTIC reproduction
# (the working directory is part of the execution provenance, so the foreign
# cwd is admitted and reported), and exact replay works from the bundle
# alone from the observation's own cwd. No tree, no exporting installation.
BUNDLE_SINGLE=golden/work/portable-single.frf
"$FRF_BIN" --root "$ROOT" bundle export "$RECEIPT_FINAL" --output "$BUNDLE_SINGLE" --single
(cd golden/work && \
  "$FRF_BIN" bundle verify portable-single.frf && \
  "$FRF_BIN" bundle replay portable-single.frf --policy semantic)
"$FRF_BIN" bundle replay "$BUNDLE_SINGLE" --policy exact

step "8. minimization — the routed reducer turns the failure into a reproducer"
# The exit residual's kappa token routes to cli-exit-minimize; deterministic
# ddmin reduces the fixture (holding candidate/authority/comparator/
# environment fixed) until the divergence lineage stops surviving. Every
# attempt is recorded; the final reproducer is court-verified.
MIN_ID=$("$FRF_BIN" --root "$ROOT" court minimize cli-exit-0001)
echo "reduction: $MIN_ID"
echo "-- the reproducer (1 line vs the original 3):"
cat "$ROOT"/objects/sha256/$(grep final_fixture_sha256 "$ROOT"/reductions/$MIN_ID.yaml | awk '{print $2}')

step "9. replay — exact reproduction, and the declared-policy distinction"
# The run identity is rederived from the capture's recorded fields, the
# snapshots are re-verified and re-sealed, and the observation must
# reproduce byte-for-byte under the recorded profile and bounds.
echo "-- exact replay (same execution provenance, must reproduce)"
"$FRF_BIN" --root "$ROOT" replay "$RESOLUTION_RUN" --policy exact
# A declared provenance difference (a different capture cap in force)
# makes exact replay REFUSE and semantic replay report + reproduce.
echo "-- a changed capture bound: exact refuses, semantic reports and reproduces"
if FRF_EXEC_MAX_BYTES=2048 "$FRF_BIN" --root "$ROOT" replay "$RESOLUTION_RUN" --policy exact 2>golden/work/drift-refusal.txt; then
  echo "FAIL: exact replay reproduced under a changed capture bound" >&2
  exit 1
fi
cat golden/work/drift-refusal.txt
FRF_EXEC_MAX_BYTES=2048 "$FRF_BIN" --root "$ROOT" replay "$RESOLUTION_RUN" --policy semantic

step "7. the evidence tree (Section 19.3 layout)"
find "$ROOT" -type f | sort

echo
printf 'Done. Receipt (canonical JSON): %s/receipts/%s.json\n' "$ROOT" "$RECEIPT_FINAL"
echo "Claim:    $ROOT/claims/$RECEIPT_FINAL.yaml"
