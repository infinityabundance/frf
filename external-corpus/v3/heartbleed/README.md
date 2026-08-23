# Heartbleed — CVE-2014-0160

The strongest case in the v3 corpus: the full version lifecycle, a semantic
information-leak axis, a court-verified minimal trigger, a sensitivity
challenge, and a sensitivity-backed claim — all from the OFFICIAL OpenSSL
1.0.1a..g source tarballs, pinned by SHA-256.

## What is here

| path | what |
|---|---|
| `src/hb.c` | the probe: the exact historical exploit message sequence, linked against the OpenSSL under test. RAW-MEMORY PUBLICATION BOUNDARY: on the leak path it never writes the echoed process memory to any observed stream — it plants a deterministic synthetic canary in its heap, hashes the echoed window, and prints a projection (`hb-leak-projection len=… sha256=… canary=… fraction=…`). Reads an optional claimed payload length from the fixture marker (`malformed 0x0FE9`) so a minimizer can reduce the trigger |
| `builds/hb-1.0.1a..g` | the seven probe binaries (one per release), built by the digest- and version-pinned reproducible recipe (pinned container base + pinned NEVRAs + official tarballs) (see `../build/build-manifest.json`). Build products are NOT committed: `./reproduce.sh build` materializes them (needs podman/docker + network) |
| `manifest.yaml` | the v3 exit/stderr court (the classic byte-level comparison) |
| `manifest-leak.yaml` | the semantic court: TWO leak observables — `tls.heartbeat.illegal_response` (served by `comparators/heartbeat-verdict.py`) and `memory.leak.seeded_canary` (served by `comparators/heartbeat-canary.py`) — plus minimizer `leak-minimize` and mutation provider `seed-leak` |
| `comparators/heartbeat-verdict.py` | the illegal-response comparator: did the malformed heartbeat get an ANSWER (RFC 6520 §4 requires discarding it) — the probe's HEARTBLEED verdict, no content interpretation |
| `comparators/heartbeat-canary.py` | the seeded-canary comparator: did the EXACT planted synthetic canary bytes escape — the projection's `canary=present`, no entropy heuristic, no markers |
| `minimizers/heartbeat-length.py` | reduces the claimed payload length; proposes the empirical floor 0x0FE9 for court verification |
| `mutations/seed-leak.py` | the challenge operator: proposes a mutant reproducing the EXACT observable shape of a real leak — the projection with `canary=present` + the HEARTBLEED verdict — deterministic and deliberately synthetic |
| `fixtures/` | `defect.conf` (`malformed 0x4000` — the historical trigger), `clean.conf` (`handshake` — the clean control) |
| `evidence/` | the committed, deterministic evidence tree: 7-run series + boundary-localized trajectory, the f/g receipts, the seed-leak challenge, the court-verified reduction (reproducer `malformed 0x0FE9`), and the sensitivity-backed claim |
| `claims/heartbleed-trajectory.md` | the comparative claim: the measured lifecycle table, the minimized trigger, the sensitivity proof |
| `study.sh` | the full FRF flow driver (regenerates the evidence under `golden/work`) |
| `reproduce.sh` | `build` / `run` / `verify` — the zero-click reproducibility kit |

## The measured story

* every vulnerable release (1.0.1a..f) answers the malformed heartbeat and
  echoes 16384 bytes of process memory; 1.0.1g silently discards it —
  the engine classifies the 7-point series as `boundary-localized`, `abrupt`,
  one band on BOTH leak observables. The published evidence carries each
  echo as a projection (length + SHA-256 commitment + planted-canary
  observation), never the raw process-memory bytes;
* the court-verified minimal trigger is a claimed payload length of
  **0x0FE9 (4073)** — the lowest claimed length at which this admitted
  1.0.1f court/probe configuration produces the observable residual (an
  observation boundary, not an intrinsic Heartbleed minimum: below it the
  vulnerable library constructs the response but never flushes it — a
  deterministic 1.0.1f write-path quirk);
* the seed-leak challenge passes: the court can SEE both leak-shaped
  divergences — the illegal response and the escaped canary — and nothing
  else;
* the fixed release's claim compiles under the `sensitivity-backed` policy,
  backed by that challenge.

## Reproduce

```sh
./reproduce.sh build   # rebuild the probes from the pinned recipe (pinned container + NEVRAs + official tarballs; needs network for the live package repository)
./reproduce.sh run     # regenerate evidence/
./reproduce.sh verify  # re-derive and compare — evidence is deterministic
```

The probe binaries are NOT committed (they are pinned build products): a
fresh clone runs `./reproduce.sh build` once, then `run`/`verify`. Hosted CI
does not build or execute them — its V3 publication-integrity gate verifies
the detached publication instead (prohibited payloads absent, source hashes
declared, reconstruction recipes present, evidence canonical).
