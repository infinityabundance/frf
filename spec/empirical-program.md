# The empirical program

The empirical program (`cargo xtask experiment`, Phase 9) is the
measurement arm of FRF: it drives the REAL reference engine over a
deterministic cross-domain corpus of seeded mutations and measures the
framework against conventional suites. It is a MEASUREMENT harness,
distinct from the independent verifier: the verifier proves protocol
separation without executing anything; the experiment executes the
reference engine to measure it.

## The corpus

Five courts across the domains, each with a clean control and seeded
mutants (generated under `golden/work/experiment/`; the report is written
to the given path, by default `golden/work/experiment.json`):

| Court                | Surface              | Seeded mutants                              |
| -------------------- | -------------------- | ------------------------------------------- |
| `cli-malformed-input`| exit, stderr         | exit-class change; first-stderr-line change |
| `fs-tree-build`      | filesystem.tree      | file content change; file dropped           |
| `wire-encode`        | bytes.wire           | one byte flipped                            |
| `state-json`         | structured.state     | one JSON field changed                      |
| `timing-bench`       | timing.latency       | latency outside the 2x envelope             |

## The measurements

1. **Defect discovery** — every seeded mutation must produce a residual on
   its targeted axis (sensitivity). Undetected seeds are misses.
2. **Specificity** — every clean control must produce ZERO residuals.
   Residuals on a clean run are false positives.
3. **Claim inflation** — on a defective run, a claim may compile only
   scoped to the CLEAN axes (the scope algebra: the claim must not cover
   the seeded-defect axis). A claim covering a defective axis is
   inflation. On a clean run, the bounded claim must compile and its
   observable scope must cover exactly the court's declared axes.
4. **Minimization cost** — deterministic ddmin per routed residual:
   attempts and fixture reduction. A surface with no reducer (the
   produced-tree axis) is refused HONESTLY, never silently skipped.
5. **Replay stability** — every run replayed three times, exact policy;
   every replay must reproduce byte-for-byte.
6. **Evidence overhead** — the bytes FRF records per observation (capture
   + residuals + tokens) vs a conventional pass/fail baseline (one short
   line per run).

## The report and the gates

The report is canonical JSON: the corpus, all six measurements, the
per-run residual surfaces, and the per-run evidence bytes. `--check`
(default) exits non-zero when any measurement violates the standards —
any undetected seed, any false positive, any claim inflation, any clean
claim that did not compile (or missed a declared axis), or any replay that
did not reproduce. `--no-check` writes the report without gating.

The corpus is deterministic and self-contained: the same binary produces
the same measurements; the report is the empirical record CI asserts on.
