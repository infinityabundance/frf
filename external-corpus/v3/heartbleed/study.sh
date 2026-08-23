#!/bin/sh
# The Heartbleed leak study — full driver. Stages the study into a fresh
# workdir and runs: admit -> leak court (f and g) -> version series a..g ->
# challenge (seed-leak) -> minimize (claimed length) -> receipt -> claim
# (sensitivity-backed). Run from the repository root:
#   sh external-corpus/v3/heartbleed/study.sh
set -eu
ROOT=/run/media/one/1tb_kingston1/frf
HB="$ROOT/external-corpus/v3/heartbleed"
WORK="$ROOT/golden/work/heartbleed-leak-study"
rm -rf "$WORK"
mkdir -p "$WORK/builds" "$WORK/fixtures" "$WORK/courts/hb"
cp "$HB"/builds/hb-1.0.1? "$WORK/builds/"
cp "$HB/fixtures/defect.conf" "$HB/fixtures/clean.conf" "$WORK/fixtures/"
mkdir -p "$WORK/comparators" "$WORK/minimizers" "$WORK/mutations"
cp "$HB"/comparators/heartbeat-verdict.py "$HB"/comparators/heartbeat-canary.py "$WORK/comparators/"
cp "$HB/minimizers/heartbeat-length.py" "$WORK/minimizers/"
cp "$HB/mutations/seed-leak.py" "$WORK/mutations/"
chmod +x "$WORK"/comparators/*.py "$WORK"/minimizers/*.py "$WORK"/mutations/*.py
sed "s|path: {candidate}|path: builds/hb-1.0.1f|" "$HB/manifest-leak.yaml" > "$WORK/courts/hb/manifest-leak.yaml"
sed "s|path: {candidate}|path: builds/hb-1.0.1g|" "$HB/manifest-leak.yaml" > "$WORK/courts/hb/manifest-leak-g.yaml"

FRF="$ROOT/target/debug/frf"
cd "$WORK"

step() { echo; echo "== $* =="; }

step "admit the fixed reference (1.0.1g) as authority ref-hb"
"$FRF" --root ev authority admit builds/hb-1.0.1g --name ref-hb --version 1.0.1g

step "leak court: vulnerable 1.0.1f (must diverge on both leak observables)"
RUN_F=$("$FRF" --root ev court run courts/hb/manifest-leak.yaml | tail -1)
echo "run: $RUN_F"

step "leak court: fixed 1.0.1g (must be clean)"
RUN_G=$("$FRF" --root ev court run courts/hb/manifest-leak-g.yaml | tail -1)
echo "run: $RUN_G"

step "version series 1.0.1a..g (the CVE-2014-0160 lifecycle: onset in a, cessation in g)"
REVS=$(printf 'builds/hb-1.0.1%c,' a b c d e f g | sed 's/,$//')
SERIES_OUT=$("$FRF" --root ev court run courts/hb/manifest-leak.yaml --candidate-revisions "$REVS")
echo "$SERIES_OUT"
for r in $SERIES_OUT; do echo "  series run: $r"; done

step "challenge: seed-leak mutation (the sensitivity proof)"
"$FRF" --root ev court challenge courts/hb/manifest-leak.yaml --operators seed-leak

step "minimize the canary residual (claimed payload length -> empirical floor)"
# The two leak observables are separate residuals; the minimizer reduces the
# fixture's claimed payload length, and the information-leak proposition is
# the seeded-canary one — pick ITS residual explicitly.
RESID=$(python3 - <<'PY'
import json, os, sys
root = "ev/residuals"
for name in sorted(os.listdir(root)):
    if not name.endswith(".json"):
        continue
    rec = json.load(open(os.path.join(root, name)))
    if rec.get("axis") == "memory.leak.seeded_canary":
        print(name[:-5])
        sys.exit(0)
sys.exit(1)
PY
)
echo "residual: $RESID"
"$FRF" --root ev court minimize "$RESID"

step "receipts"
RECEIPT_F=$("$FRF" --root ev receipt emit "$RUN_F" | tail -1)
RECEIPT_G=$("$FRF" --root ev receipt emit "$RUN_G" | tail -1)
echo "receipt (vulnerable f): $RECEIPT_F"
echo "receipt (fixed g):      $RECEIPT_G"

step "claim: sensitivity-backed 'no leak' for the fixed release"
"$FRF" --root ev claim compile "$RECEIPT_G" --policy sensitivity-backed

step "summary"
echo "run_f=$RUN_F"
echo "run_g=$RUN_G"
echo "receipt_f=$RECEIPT_F"
echo "receipt_g=$RECEIPT_G"
