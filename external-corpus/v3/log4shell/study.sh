#!/bin/sh
# The Log4Shell (CVE-2021-44228) verdict study — full driver. Stages the
# study into a fresh workdir and runs: admit -> verdict court (vulnerable
# and fixed) -> clean control (both launchers, clean message) -> version
# series 2.14.1 -> 2.15.0 -> 2.16.0 -> 2.17.1 -> challenge (jndi-inject) ->
# minimize (message-suffix length) -> receipt -> claim
# (sensitivity-backed, compiled WITH the trajectory movement).
# Run from the repository root:
#   sh external-corpus/v3/log4shell/study.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
L4S="$ROOT/external-corpus/v3/log4shell"
WORK="$ROOT/golden/work/log4shell-verdict-study"
rm -rf "$WORK"
mkdir -p "$WORK/builds" "$WORK/fixtures" "$WORK/courts/log4shell"
cp -r "$L4S"/builds/probe.jar "$L4S"/builds/lib "$L4S"/builds/run-vuln.sh "$L4S"/builds/run-v150.sh "$L4S"/builds/run-v160.sh "$L4S"/builds/run-fixed.sh "$WORK/builds/"
cp "$L4S/fixtures/defect.conf" "$L4S/fixtures/clean.conf" "$WORK/fixtures/"
mkdir -p "$WORK/comparators" "$WORK/minimizers" "$WORK/mutations"
cp "$L4S"/comparators/jndi-lookup.py "$WORK/comparators/"
cp "$L4S/minimizers/jndi-message.py" "$WORK/minimizers/"
cp "$L4S/mutations/jndi-inject.py" "$WORK/mutations/"
chmod +x "$WORK"/comparators/*.py "$WORK"/minimizers/*.py "$WORK"/mutations/*.py
sed "s|path: {candidate}|path: builds/run-vuln.sh|" "$L4S/manifest.yaml" > "$WORK/courts/log4shell/manifest.yaml"
sed -e "s|path: {candidate}|path: builds/run-fixed.sh|" \
    -e "s|cand-log4j-2.14.1|cand-log4j-2.17.1|" \
    -e 's|version_or_commit: "2.14.1"|version_or_commit: "2.17.1"|' \
    "$L4S/manifest.yaml" > "$WORK/courts/log4shell/manifest-fixed.yaml"
sed "s|path: {candidate}|path: builds/run-fixed.sh|" "$L4S/manifest-clean.yaml" > "$WORK/courts/log4shell/manifest-clean.yaml"
sed "s|path: {candidate}|path: builds/run-vuln.sh|" "$L4S/manifest-clean.yaml" > "$WORK/courts/log4shell/manifest-clean-vuln.yaml"

FRF="$ROOT/target/debug/frf"
cd "$WORK"

step() { echo; echo "== $* =="; }

step "admit the fixed reference (Log4j 2.17.1 launcher) as authority ref-log4j-2.17.1"
"$FRF" --root ev authority admit builds/run-fixed.sh --name ref-log4j --version 2.17.1

step "verdict court: vulnerable 2.14.1 (must diverge on jndi.lookup)"
RUN_VULN=$("$FRF" --root ev court run courts/log4shell/manifest.yaml | tail -1)
echo "run: $RUN_VULN"

step "verdict court: fixed 2.17.1 (must be clean)"
RUN_FIXED=$("$FRF" --root ev court run courts/log4shell/manifest-fixed.yaml | tail -1)
echo "run: $RUN_FIXED"

step "clean control: BOTH launchers on the clean message (must be clean)"
RUN_CLEAN_FIXED=$("$FRF" --root ev court run courts/log4shell/manifest-clean.yaml | tail -1)
echo "run (clean, fixed): $RUN_CLEAN_FIXED"
RUN_CLEAN_VULN=$("$FRF" --root ev court run courts/log4shell/manifest-clean-vuln.yaml | tail -1)
echo "run (clean, vulnerable): $RUN_CLEAN_VULN"

step "version series 2.14.1 -> 2.15.0 -> 2.16.0 -> 2.17.1 (the CVE-2021-44228 lifecycle: onset in 2.14.1, cessation in 2.15.0)"
REVS="builds/run-vuln.sh,builds/run-v150.sh,builds/run-v160.sh,builds/run-fixed.sh"
SERIES_OUT=$("$FRF" --root ev court run courts/log4shell/manifest.yaml --candidate-revisions "$REVS")
echo "$SERIES_OUT"
for r in $SERIES_OUT; do echo "  series run: $r"; done

step "challenge: jndi-inject mutation (the sensitivity proof — the vulnerable stack genuinely performs the lookup)"
"$FRF" --root ev court challenge courts/log4shell/manifest.yaml --operators jndi-inject

step "minimize the jndi.lookup residual (message-suffix length -> empirical floor: the bare lookup token)"
RESID=$(python3 - "$RUN_VULN" <<'PY'
import json, os, sys
run = sys.argv[1]
root = "ev/residuals"
for name in sorted(os.listdir(root)):
    if not name.endswith(".json"):
        continue
    rec = json.load(open(os.path.join(root, name)))
    if rec.get("axis") == "jndi.lookup" and rec.get("run") == run:
        print(name[:-5])
        sys.exit(0)
sys.exit(1)
PY
)
echo "residual: $RESID"
"$FRF" --root ev court minimize "$RESID"

step "receipts"
RECEIPT_VULN=$("$FRF" --root ev receipt emit "$RUN_VULN" | tail -1)
RECEIPT_FIXED=$("$FRF" --root ev receipt emit "$RUN_FIXED" | tail -1)
echo "receipt (vulnerable 2.14.1): $RECEIPT_VULN"
echo "receipt (fixed 2.17.1):      $RECEIPT_FIXED"

step "claim: sensitivity-backed 'no JNDI lookup' for the fixed release, compiled WITH the trajectory movement"
# The trajectory premise (v12): the jndi.lookup movement over the
# candidate_revision series — onset in 2.14.1, cessation in 2.15.0 — is
# COMPILED as a claim clause BOUND TO ITS SUBJECT: the premise names the
# anchored premise receipt (RECEIPT_FIXED) whose run is the clean point of
# the series, so the movement is compiled about the claim's own subject, not
# merely a valid graph on a matching axis.
TRAJ=$(python3 - "$RUN_VULN" "$RUN_FIXED" <<'PY'
import json, os, sys
run_vuln, run_fixed = sys.argv[1], sys.argv[2]
root = "ev/trajectories"
for name in sorted(os.listdir(root)):
    # lineage.coordinate_system.series.json — pick the candidate_revision
    # trajectory whose series spans both runs.
    if "candidate_revision" not in name:
        continue
    t = json.load(open(os.path.join(root, name)))
    runs = {o["run"] for o in t["observations"]}
    if run_vuln in runs and run_fixed in runs:
        print(name[:-5])
        sys.exit(0)
sys.exit(1)
PY
)
echo "trajectory premise: $TRAJ"
"$FRF" --root ev claim compile "$RECEIPT_FIXED" --policy sensitivity-backed --trajectory "$TRAJ@$RECEIPT_FIXED"

step "summary"
echo "run_vuln=$RUN_VULN"
echo "run_fixed=$RUN_FIXED"
echo "run_clean_fixed=$RUN_CLEAN_FIXED"
echo "run_clean_vuln=$RUN_CLEAN_VULN"
echo "receipt_vuln=$RECEIPT_VULN"
echo "receipt_fixed=$RECEIPT_FIXED"
