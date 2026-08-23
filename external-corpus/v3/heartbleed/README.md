# Heartbleed — CVE-2014-0160

The strongest case in the v3 corpus: the full version lifecycle, a semantic
information-leak axis, a court-verified minimal trigger, a sensitivity
challenge, and a sensitivity-backed claim — all from the OFFICIAL OpenSSL
1.0.1a..g source tarballs, pinned by SHA-256.

## What is here

| path | what |
|---|---|
| `src/hb.c` | the probe: the exact historical exploit message sequence, linked against the OpenSSL under test. RAW-MEMORY PUBLICATION BOUNDARY: on the leak path it never writes the echoed process memory to any observed stream — it plants a deterministic synthetic canary in its heap, hashes the echoed window, and prints a projection (`hb-leak-projection len=… sha256=… canary=… fraction=…`). Reads an optional claimed payload length from the fixture marker (`malformed 0x0FE9`) so a minimizer can reduce the trigger |
| `builds/hb-1.0.1a..g` | the seven probe binaries (one per release), built hermetically inside the pinned container from the official tarballs (see `../build/build-manifest.json`). Build products are NOT committed: `./reproduce.sh build` materializes them (needs podman/docker + network) |
| `manifest.yaml` | the v3 exit/stderr court (the classic byte-level comparison) |
| `manifest-leak.yaml` | the semantic court: observable `memory.leak.sensitive` served by `comparators/heartbleed-leak.py`, minimizer `leak-minimize`, mutation provider `seed-leak` |
| `comparators/heartbleed-leak.py` | the information-leak comparator: flags the probe's HEARTBLEED verdict, a well-formed leak projection (len + SHA-256 commitment + canary), or a sensitive marker in the echoed content |
| `minimizers/heartbeat-length.py` | reduces the claimed payload length; proposes the empirical floor 0x0FE9 for court verification |
| `mutations/seed-leak.py` | the challenge operator: proposes a mutant that dumps a seeded PEM key + `SECRET_KEY=12345` |
| `fixtures/` | `defect.conf` (`malformed 0x4000` — the historical trigger), `clean.conf` (`handshake` — the clean control) |
| `evidence/` | the committed, deterministic evidence tree: 7-run series + boundary-localized trajectory, the f/g receipts, the seed-leak challenge, the court-verified reduction (reproducer `malformed 0x0FE9`), and the sensitivity-backed claim |
| `claims/heartbleed-trajectory.md` | the comparative claim: the measured lifecycle table, the minimized trigger, the sensitivity proof |
| `study.sh` | the full FRF flow driver (regenerates the evidence under `golden/work`) |
| `reproduce.sh` | `build` / `run` / `verify` — the zero-click reproducibility kit |

## The measured story

* every vulnerable release (1.0.1a..f) echoes 16384 bytes of process memory
  in response to the malformed heartbeat; 1.0.1g silently discards it —
  the engine classifies the 7-point series as `boundary-localized`, `abrupt`,
  one band. The published evidence carries each echo as a projection
  (length + SHA-256 commitment + planted-canary observation), never the raw
  process-memory bytes;
* the court-verified minimal trigger is a claimed payload length of
  **0x0FE9 (4073)** — the lowest claimed length at which this admitted
  1.0.1f court/probe configuration produces the observable residual (an
  observation boundary, not an intrinsic Heartbleed minimum: below it the
  vulnerable library constructs the response but never flushes it — a
  deterministic 1.0.1f write-path quirk);
* the seed-leak challenge passes: the court can SEE a leak-shaped divergence
  on `memory.leak.sensitive` and nothing else;
* the fixed release's claim compiles under the `sensitivity-backed` policy,
  backed by that challenge.

## Reproduce

```sh
./reproduce.sh build   # hermetically rebuild the probes (pinned container + official tarballs)
./reproduce.sh run     # regenerate evidence/
./reproduce.sh verify  # re-derive and compare — evidence is deterministic
```

The probe binaries are NOT committed (they are pinned, hermetic build
products): a fresh clone runs `./reproduce.sh build` once, then
`run`/`verify`. CI does not build them — its v3/v4/v5 empirical programs
skip a case whose build products are absent and record the skip in the
report.
