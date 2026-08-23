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
rm -rf "$ROOT"/authorities "$ROOT"/captures "$ROOT"/residuals "$ROOT"/series "$ROOT"/trajectories "$ROOT"/receipts "$ROOT"/claims "$ROOT"/challenges "$ROOT"/reductions "$ROOT"/witnesses "$ROOT"/independence "$ROOT"/harness
mkdir -p "$ROOT"/authorities "$ROOT"/captures "$ROOT"/residuals "$ROOT"/series "$ROOT"/trajectories "$ROOT"/receipts "$ROOT"/claims "$ROOT"/challenges "$ROOT"/witnesses "$ROOT"/independence
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

step "2c. the first non-CLI court — the filesystem tree"
# The court observes what its sides BUILD, not what they print: each side
# writes its output tree to the declared produce path (golden/work/tree-out/,
# transient), the harness captures the produced trees immutably under the
# run, and the built-in filesystem.tree comparator diffs the produced files
# per path. The candidate writes src/main.c differently and drops
# build/config — the two divergences the court must see.
echo "-- treegen-ref vs treegen-cand: two produced files diverge, surfaced by path"
"$FRF_BIN" --root "$ROOT" authority admit golden/treegen-ref.sh --name treegen-ref --version 1.0
TREE_RUN=$("$FRF_BIN" --root "$ROOT" court run frf/courts/fs-tree-build/manifest.yaml)
echo "tree run: $TREE_RUN"
echo "-- the produced trees are captured under the run; the tree observation replays byte-for-byte"
"$FRF_BIN" --root "$ROOT" replay "$TREE_RUN" --policy exact
TREE_RECEIPT=$("$FRF_BIN" --root "$ROOT" receipt emit "$TREE_RUN")
echo "tree receipt: $TREE_RECEIPT"

step "2d. the normalizer extension protocol — the comparison surface"
# A normalizer maps one side's raw streams to the streams the court COMPARES.
# The reference's diagnostic carries trailing whitespace; the candidate's is
# identical except for it. Raw first lines diverge; the normalized surface is
# equivalent — the court passes ONLY because the declared normalizer applies,
# and the raw streams survive as the normalizer request evidence (an
# observation is never rewritten, the comparison surface is).
echo "-- admit the whitespace-carrying reference; the normalized court passes"
"$FRF_BIN" --root "$ROOT" authority admit golden/ref-ws.sh --name ref-ws --version 1.0
NORM_RUN=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-normalized/manifest.yaml)
echo "normalized run: $NORM_RUN"
echo "-- the normalizer invocation evidence (raw streams in, normalized surface out)"
ls "$ROOT"/captures/"$NORM_RUN"/normalizer/trim-trailing-ws/reference/
echo "-- the normalized observation replays byte-for-byte (the normalizer is re-invoked)"
"$FRF_BIN" --root "$ROOT" replay "$NORM_RUN" --policy exact

step "3. try to compile a claim while both residuals are open (must be refused)"
RECEIPT_OPEN=$("$FRF_BIN" --root "$ROOT" receipt emit "$RUN_ID")
if "$FRF_BIN" --root "$ROOT" claim compile "$RECEIPT_OPEN" 2>golden/work/refusal.txt; then
  echo "FAIL: a positive claim compiled while residuals were open" >&2
  exit 1
fi
cat golden/work/refusal.txt

# Residual ids are CONTENT ADDRESSES (FRF/RESIDUAL/v1 over the run +
# divergence), so the kit resolves the ids it needs from the evidence
# instead of assuming storage labels.
residual_id_of() { # <run> <axis>
  run=$1; axis=$2
  for id in $(grep -o '"residuals":\[[^]]*\]' "$ROOT/captures/$run/capture.json" | sed 's/.*\[\([^]]*\)\].*/\1/' | tr -d '"' | tr ',' ' '); do
    ax=$(grep -o '"axis":"[^"]*"' "$ROOT/residuals/$id.json" | sed 's/.*:"\([^"]*\)".*/\1/')
    if [ "$ax" = "$axis" ]; then echo "$id"; return 0; fi
  done
  echo "FATAL: no $axis residual in $run" >&2
  exit 1
}

step "4. resolve: patch the candidate's exit class, verify with a NEW court run, then dispose"
sed -e 's/exit 1$/exit 2/' \
    -e "s/(1 instead of the reference's 2)/(2, matching the reference)/" \
    -e 's/This divergence is the whole point of the court./The remaining divergence is the diagnostic wording./' \
    golden/candidate.sh > golden/work/candidate-fixed.sh
chmod +x golden/work/candidate-fixed.sh
echo "-- re-run the court against the patched candidate (the exit axis must close; the wording divergence is re-observed)"
RESOLUTION_RUN=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-malformed-input/manifest-candidate-fixed.yaml)
echo "resolution run: $RESOLUTION_RUN"
EXIT_ID=$(residual_id_of "$RUN_ID" exit)
TEXT_ID=$(residual_id_of "$RUN_ID" stderr)
RES_TEXT_ID=$(residual_id_of "$RESOLUTION_RUN" stderr)
echo "-- dispose the exit residual as fixed, backed by that run (a disposition is not evidence)"
"$FRF_BIN" --root "$ROOT" residual dispose "$EXIT_ID" --disposition fixed \
  --resolution-run "$RESOLUTION_RUN" \
  --reason "candidate patched to preserve reference exit class (golden/work/candidate-fixed.sh)"
echo "-- dispose the wording divergence as intentional (documented, never parity)"
"$FRF_BIN" --root "$ROOT" residual dispose "$TEXT_ID" --disposition intentional \
  --reason "clearer diagnostic wording; documented divergence"
"$FRF_BIN" --root "$ROOT" residual dispose "$RES_TEXT_ID" --disposition intentional \
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
MIN_ID=$("$FRF_BIN" --root "$ROOT" court minimize "$EXIT_ID")
echo "reduction: $MIN_ID"
echo "-- the reproducer (1 line vs the original 3):"
cat "$ROOT"/objects/sha256/$(grep -o '"final_fixture_sha256":"[0-9a-f]*"' "$ROOT"/reductions/$MIN_ID.json | head -1 | cut -d'"' -f4)

step "8b. the external minimizer extension protocol — a declared reducer, court-verified"
# The minimizer is a protocol participant: the court BINDS it at observation
# time (its program bytes are sealed and recorded in the capture), and
# `court minimize` consults the residual's capture for a minimizer matching
# its κ route. The minimizer proposes a reduced fixture; the core
# COURT-VERIFIES every proposal with the one comparison operation — a
# proposal that does not preserve the lineage would be recorded-but-not-
# accepted. The reduction record binds the minimizer's semantic +
# implementation identities and the content-addressed invocation evidence.
echo "-- run the external-minimizer court (its fixture carries comments the reducer can drop)"
MIN_RUN=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-external-minimizer/manifest.yaml)
MIN_RESIDUAL=$(grep -o '"residuals":\["[^"]*"' "$ROOT"/captures/"$MIN_RUN"/capture.json | head -1 | sed 's/.*\["//; s/"$//')
echo "external-minimizer run: $MIN_RUN (residual $MIN_RESIDUAL)"
MIN_EXT_ID=$("$FRF_BIN" --root "$ROOT" court minimize "$MIN_RESIDUAL")
echo "external reduction: $MIN_EXT_ID"
echo "-- the reduction record binds the external minimizer (semantic + implementation):"
grep -E 'minimizer_semantic_id|minimizer_implementation_hash' "$ROOT"/reductions/"$MIN_EXT_ID".json
echo "-- the minimizer's canonical request/response + invocation evidence:"
ls "$ROOT"/reductions/"$MIN_EXT_ID"/minimizer/

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

step "9b. the witness extension protocol — independent attestation"
# A witness is a protocol participant: it attests a content-addressed subject
# (the resolution run's identity digest is REDERIVED here, never read from
# the caller) and an exact statement. The attestation is recorded as a
# content-addressed WitnessStatement with the canonical request/response
# preserved as evidence — no one can attach an attestation to a different
# object after the fact.
WIT_ID=$("$FRF_BIN" --root "$ROOT" witness attest run "$RESOLUTION_RUN" \
  --id manual-review \
  --relation independent-confirmation \
  --program golden/witnesses/attest.py \
  --statement "candidate-fixed.sh preserves the reference exit class on the malformed fixture (independent review)")
echo "witness statement: $WIT_ID"
echo "-- the attested statement is content-addressed and re-verified on read:"
head -c 400 "$ROOT"/witnesses/"$WIT_ID".json; echo

step "9c. the claim under an admission policy — high-assurance"
# The claim compiles under the TOP assurance tier: sensitivity coverage (the
# step-2b challenges demonstrated the court can SEE the claimed exit
# surface), a verified witness attestation of this receipt, and the
# reference execution contract (profile + capture bounds). The compiled
# claim CARRIES the capability evidence — challenge ids, witness id, replay
# profile — so the admission re-derives from the claim alone; the bundles
# are re-exported so they carry it too.
echo "-- attest the receipt itself (the independently-witnessed tier):"
WIT_RECEIPT_ID=$("$FRF_BIN" --root "$ROOT" witness attest receipt "$RECEIPT_FINAL" \
  --id manual-review \
  --relation independent-confirmation \
  --program golden/witnesses/attest.py \
  --statement "the resolution receipt binds a verified observation of the passing candidate (independent review)")
echo "receipt witness statement: $WIT_RECEIPT_ID"
step "9d. the declared independence relation — the witness's own claim, never FRF's"
# Independence is a DECLARED relation (spec/witness.md §6): the operator
# records which independence claim the attestation rests on and its basis.
# FRF verifies the evidence structure (the statement verifies, the witness
# identity rederives, the relation is closed) — never the social truth of
# independence; a different executable hash is never by itself evidence of
# independent observation.
IND_ID=$("$FRF_BIN" --root "$ROOT" witness independence "$WIT_RECEIPT_ID" \
  --relation separate-party \
  --basis "the attestation was made by an unaffiliated reviewer against the exported bundle, not the producing installation")
echo "independence evidence: $IND_ID"
echo "-- the independence record is content-addressed and binds the statement:"
grep -o '"relation":"[^"]*"' "$ROOT"/independence/"$IND_ID".json
COMPILE_OUT=$("$FRF_BIN" --root "$ROOT" claim compile "$RECEIPT_FINAL" --policy high-assurance 2>&1) || {
  echo "FAIL: the high-assurance claim did not compile" >&2
  echo "$COMPILE_OUT" >&2
  exit 1
}
# The claim is content-addressed (FRF/CLAIM/v1): the compile prints its id,
# and the by-receipt index maps the receipt to its claim(s).
CLAIM_ID=$(printf '%s\n' "$COMPILE_OUT" | grep -o '^claim [0-9a-f]\{64\}$' | cut -d' ' -f2)
if [ -z "$CLAIM_ID" ]; then
  echo "FAIL: the claim id was not printed" >&2
  exit 1
fi
CLAIM_FILE="$ROOT"/claims/"$CLAIM_ID".json
if [ ! -f "$CLAIM_FILE" ]; then
  echo "FAIL: the content-addressed claim file is missing" >&2
  exit 1
fi
if [ ! -f "$ROOT"/claims/by-receipt/"$RECEIPT_FINAL"/"$CLAIM_ID" ]; then
  echo "FAIL: the by-receipt index does not bind the claim" >&2
  exit 1
fi
echo "claim id: $CLAIM_ID"
echo "-- the claim carries the independence evidence:"
grep -o '"independence_evidence":\[[^]]*\]' "$CLAIM_FILE"
echo "-- the claim's capability evidence (carried in the IR):"
grep -o '"capability":\[[^]]*\]' "$CLAIM_FILE"
echo "-- the renderer VERIFIES the claim before presenting it (a hand-written claim file is refused):"
"$FRF_BIN" --root "$ROOT" claim render "$CLAIM_ID" --format ci
"$FRF_BIN" --root "$ROOT" claim render "$RECEIPT_FINAL" --format prose >/dev/null
BUNDLE=golden/work/portable.frf
"$FRF_BIN" --root "$ROOT" bundle export "$RECEIPT_FINAL" --output "$BUNDLE"
BUNDLE_SINGLE=golden/work/portable-single.frf
"$FRF_BIN" --root "$ROOT" bundle export "$RECEIPT_FINAL" --output "$BUNDLE_SINGLE" --single
(cd golden/work && \
  "$FRF_BIN" bundle verify portable.frf && \
  "$FRF_BIN" bundle verify portable-single.frf)

step "7. the evidence tree (Section 19.3 layout)"
find "$ROOT" -type f | sort

echo
printf 'Done. Receipt (canonical JSON): %s/receipts/%s.json\n' "$ROOT" "$RECEIPT_FINAL"
echo "Claim:    $CLAIM_FILE"
