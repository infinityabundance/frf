# Goto Fail — CVE-2014-1266, judged semantically

## The measured story

Apple's Secure Transport "goto fail" defect (CVE-2014-1266) was a duplicated
`goto fail;` that skipped the signature comparison, so every handshake was
accepted. This study models the defect's OBSERVABLE — a verifier that
accepts tampered handshake records — as the semantic `tls.verdict` domain:
the SECOND semantic axis of the v3 corpus, proving the information-leak
study's recipe (semantic comparator + minimizer κ-route + mutation
challenge) is a general protocol facility, not a one-off.

* the **buggy verifier** (the `-DGO_TO_FAIL` build) accepts a record whose
  signature does not match its data — the court observes the `tls.verdict`
  divergence against the fixed reference;
* the **fixed verifier** accepts exactly the records the reference accepts —
  the clean court is clean, and the version series buggy → fixed classifies
  `boundary-localized` / `abrupt` / `start`: the defect ceases exactly when
  the comparison lands;
* the **signature-skip challenge** passes: the court can SEE the seeded
  defect (a verifier that accepts every record) and nothing else — a court
  that never sees a skipped signature check cannot certify "no acceptance of
  tampered records";
* the **court-verified minimal trigger** is a single-byte record with a
  wrong signature — the `tls.handshake.record_data_length` boundary: at
  length 1 the tampered-signature divergence survives, at length 0 the
  record is malformed (both sides refuse, no divergence). The typed
  adjacent-boundary is proven by the core's own two observations, with the
  domain projection (`len=`, embedded-integer) deriving both coordinates
  from the executed fixtures;
* the **fixed verifier's claim** compiles under the `sensitivity-backed`
  policy, backed by that challenge: it asserts parity on the `tls.verdict`
  surface — never byte-identical stderr, never a drop-in claim.

## What is here

| path | what |
|---|---|
| `src/sslcheck.c` | one C source, two verifiers: the clean build performs the checksum comparison; the `-DGO_TO_FAIL` build carries the duplicated `goto fail;` that skips it (the CVE's exact shape). The record carries a `len=` field — the TLS record header's length — so the payload length is a first-class, minimizable dimension |
| `builds/` | the two verifier binaries, built by `build/build.sh` and pinned by SHA-256 in `build/build-manifest.json`. NOT committed (v3 discipline): `./reproduce.sh build` materializes them |
| `fixtures/` | `clean.conf` (valid record — accepted by both) and `defect.conf` (tampered record — refused by the fixed verifier, accepted by the buggy one) |
| `comparators/tls-verdict.py` | the semantic comparator: the `tls.verdict` axis under `eq(verdict-scan)` — did the side ACCEPT the record? A verdict is a semantic observable, never a byte diff |
| `minimizers/record-length.py` | the κ-route minimizer (`ssl-handshake-minimize`): reduces the declared payload length to the empirical floor 1, declaring the typed adjacent-boundary the core proves |
| `mutations/signature-skip.py` | the challenge operator: proposes a verifier that accepts every record — the defect's observable shape, deterministic and synthetic |
| `evidence/` | the committed, deterministic evidence tree: the 2-run series + boundary-localized trajectory, both receipts, the signature-skip challenge, the court-verified reduction, and the sensitivity-backed claim |
| `claims/goto-fail-verdict.md` | this comparative claim |
| `study.sh` | the full FRF flow driver (regenerates the evidence under `golden/work`) |
| `reproduce.sh` | `build` / `run` / `publish` / `verify` — the reproducibility kit |

## Reproduce

```sh
./reproduce.sh build    # gcc; no container needed — the program links nothing historical
./reproduce.sh run      # regenerate evidence/ under golden/work (never the public tree)
./reproduce.sh publish  # full local evidence -> publish-detached -> evidence/
./reproduce.sh verify   # re-derive + publish + byte-compare the committed publication
```
