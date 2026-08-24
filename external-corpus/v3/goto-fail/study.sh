#!/bin/sh
# The Goto Fail (CVE-2014-1266) verdict study — full driver. Stages the
# study into a fresh workdir and runs: admit -> verdict court (buggy and
# clean) -> version series buggy->clean -> challenge (signature-skip) ->
# minimize (record length) -> receipt -> claim (sensitivity-backed).
# Run from the repository root:
#   sh external-corpus/v3/goto-fail/study.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
GF="$ROOT/external-corpus/v3/goto-fail"
WORK="$ROOT/golden/work/goto-fail-verdict-study"
rm -rf "$WORK"
mkdir -p "$WORK/builds" "$WORK/fixtures" "$WORK/courts/ssl"
cp "$GF"/builds/sslcheck-clean "$GF"/builds/sslcheck-buggy "$WORK/builds/"
cp "$GF/fixtures/defect.conf" "$GF/fixtures/clean.conf" "$WORK/fixtures/"
mkdir -p "$WORK/comparators" "$WORK/minimizers" "$WORK/mutations"
cp "$GF"/comparators/tls-verdict.py "$WORK/comparators/"
cp "$GF/minimizers/record-length.py" "$WORK/minimizers/"
cp "$GF/mutations/signature-skip.py" "$WORK/mutations/"
chmod +x "$WORK"/comparators/*.py "$WORK"/minimizers/*.py "$WORK"/mutations/*.py
sed "s|path: {candidate}|path: builds/sslcheck-buggy|" "$GF/manifest-verdict.yaml" > "$WORK/courts/ssl/manifest-verdict.yaml"
sed "s|path: {candidate}|path: builds/sslcheck-clean|" "$GF/manifest-verdict.yaml" > "$WORK/courts/ssl/manifest-verdict-clean.yaml"

FRF="$ROOT/target/debug/frf"
cd "$WORK"

step() { echo; echo "== $* =="; }

step "admit the fixed verifier (sslcheck-clean) as authority ref-ssl-2014"
"$FRF" --root ev authority admit builds/sslcheck-clean --name ref-ssl-2014 --version 1.0.1

step "verdict court: buggy verifier (must diverge on tls.verdict)"
RUN_BUGGY=$("$FRF" --root ev court run courts/ssl/manifest-verdict.yaml | tail -1)
echo "run: $RUN_BUGGY"

step "verdict court: clean verifier (must be clean)"
RUN_CLEAN=$("$FRF" --root ev court run courts/ssl/manifest-verdict-clean.yaml | tail -1)
echo "run: $RUN_CLEAN"

step "version series buggy -> clean (the CVE-2014-1266 lifecycle: acceptance in buggy, cessation in clean)"
SERIES_OUT=$("$FRF" --root ev court run courts/ssl/manifest-verdict.yaml --candidate-revisions "builds/sslcheck-buggy,builds/sslcheck-clean")
echo "$SERIES_OUT"
for r in $SERIES_OUT; do echo "  series run: $r"; done

step "challenge: signature-skip mutation (the sensitivity proof)"
"$FRF" --root ev court challenge courts/ssl/manifest-verdict.yaml --operators signature-skip

step "minimize the tls.verdict residual (tampered record length -> empirical floor)"
# Pick the residual of the BUGGY court run specifically (its candidate is the
# real buggy verifier): the challenge's mutant run also records a tls.verdict
# residual whose candidate accepts everything — the boundary does not hold
# for the mutant, so it is not the reduction's subject.
RESID=$(python3 - "$RUN_BUGGY" <<'PY'
import json, os, sys
run = sys.argv[1]
root = "ev/residuals"
for name in sorted(os.listdir(root)):
    if not name.endswith(".json"):
        continue
    rec = json.load(open(os.path.join(root, name)))
    if rec.get("axis") == "tls.verdict" and rec.get("run") == run:
        print(name[:-5])
        sys.exit(0)
sys.exit(1)
PY
)
echo "residual: $RESID"
"$FRF" --root ev court minimize "$RESID"

step "receipts"
RECEIPT_BUGGY=$("$FRF" --root ev receipt emit "$RUN_BUGGY" | tail -1)
RECEIPT_CLEAN=$("$FRF" --root ev receipt emit "$RUN_CLEAN" | tail -1)
echo "receipt (buggy): $RECEIPT_BUGGY"
echo "receipt (clean): $RECEIPT_CLEAN"

step "claim: sensitivity-backed 'no acceptance of tampered records' for the fixed verifier"
"$FRF" --root ev claim compile "$RECEIPT_CLEAN" --policy sensitivity-backed

step "summary"
echo "run_buggy=$RUN_BUGGY"
echo "run_clean=$RUN_CLEAN"
echo "receipt_buggy=$RECEIPT_BUGGY"
echo "receipt_clean=$RECEIPT_CLEAN"
