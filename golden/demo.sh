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
# token emitted for each, a positive claim refused while they are open, both
# residuals disposed (fixed + intentional), a receipt emitted, and a bounded
# claim compiled with the Section 12 non-claim printed next to it.
set -u

cd "$(dirname "$0")/.."

if command -v frf >/dev/null 2>&1; then
  FRF_BIN=${FRF_BIN:-frf}
else
  cargo build --release --quiet
  FRF_BIN=${FRF_BIN:-target/release/frf}
fi
ROOT=frf

# Regenerate the evidence tree (courts/ is source and is kept).
rm -rf "$ROOT"/authorities "$ROOT"/captures "$ROOT"/residuals "$ROOT"/receipts "$ROOT"/claims
mkdir -p "$ROOT"/authorities "$ROOT"/captures "$ROOT"/residuals "$ROOT"/receipts "$ROOT"/claims
rm -rf golden/work
mkdir -p golden/work

step() { printf '\n== %s ==\n' "$*"; }

step "1. admit the authority (golden/reference.sh as ref-cli 1.8.2)"
"$FRF_BIN" --root "$ROOT" authority admit golden/reference.sh --name ref-cli --version 1.8.2

step "2. run the court (authority vs candidate on the malformed fixture)"
RUN_ID=$("$FRF_BIN" --root "$ROOT" court run frf/courts/cli-malformed-input/manifest.yaml)
echo "run: $RUN_ID"

step "3. try to compile a claim while both residuals are open (must be refused)"
RECEIPT_OPEN=$("$FRF_BIN" --root "$ROOT" receipt emit "$RUN_ID")
if "$FRF_BIN" --root "$ROOT" claim compile "$RECEIPT_OPEN" 2>golden/work/refusal.txt; then
  echo "FAIL: a positive claim compiled while residuals were open" >&2
  exit 1
fi
cat golden/work/refusal.txt

step "4. resolve: patch the candidate's exit class, then dispose both residuals"
sed -e 's/exit 1$/exit 2/' \
    -e "s/(1 instead of the reference's 2)/(2, matching the reference)/" \
    -e 's/This divergence is the whole point of the court./The remaining divergence is the diagnostic wording./' \
    golden/candidate.sh > golden/work/candidate-fixed.sh
chmod +x golden/work/candidate-fixed.sh
"$FRF_BIN" --root "$ROOT" residual dispose cli-exit-0001 --disposition fixed \
  --reason "candidate patched to preserve reference exit class (golden/work/candidate-fixed.sh)"
"$FRF_BIN" --root "$ROOT" residual dispose cli-text-0001 --disposition intentional \
  --reason "clearer diagnostic wording; documented divergence"

step "5. emit the final receipt and compile the bounded claim"
RECEIPT_FINAL=$("$FRF_BIN" --root "$ROOT" receipt emit "$RUN_ID")
"$FRF_BIN" --root "$ROOT" claim compile "$RECEIPT_FINAL"

step "6. the evidence tree (Section 19.3 layout)"
find "$ROOT" -type f | sort

echo
echo "Done. Receipt: $ROOT/receipts/$RECEIPT_FINAL.yaml"
echo "Claim:    $ROOT/claims/$RECEIPT_FINAL.yaml"
