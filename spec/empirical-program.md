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

# The EXTERNAL empirical program

The internal program is FRF testing FRF on a corpus FRF controls. The
credibility mover is external evidence: REAL historical defects,
reconstructed as minimal deterministic reproducers
(`cargo xtask external-experiment`, Phase 10; corpus in `external-corpus/`;
report at `golden/work/external-experiment.json`).

## The corpus

Six real, documented historical defects across the domains they actually
occurred in:

| Case | Defect | Domain | Surface |
| --- | --- | --- | --- |
| `goto-fail` | Apple Secure Transport CVE-2014-1266 — the duplicated `goto fail;` skipped certificate verification | cli | exit, stderr |
| `shellshock` | bash CVE-2014-6271 — importing a function executed trailing code | cli | stdout, exit |
| `heartbleed` | OpenSSL CVE-2014-0160 — the heartbeat responder echoed a declared length without bounds-checking it | wire | bytes.wire |
| `log4shell` | Log4j CVE-2021-44228 — nested `${key}` lookups without cycle detection | state | structured.state |
| `mars-climate-orbiter` | 1999 — lbf-s consumed as N-s (the unit mismatch that lost the orbiter) | state | structured.state |
| `two-digit-year` | the endemic pre-Y2K 19YY mapping | state | structured.state |

Each case is a court whose REFERENCE is the fixed implementation; the
BUGGY candidate carries the historical defect; the CLEAN candidate is a
distinct implementation with identical fixed behavior (so "clean" is not
"the reference again"); the DEFECT fixture triggers the bug; the CLEAN
fixture does not.

## The measurements

1. **Defect discovery** — the buggy candidate must produce a residual on
   its targeted axis under the fixed reference.
2. **False positives** — the clean candidate must produce zero residuals
   on the clean fixture.
3. **Claim behavior** — on a defective run, the claim compiler is either
   refused or scoped to the clean axes only (never the defect axis); on a
   clean run the bounded claim must compile covering every declared axis.
4. **Minimization cost** — deterministic ddmin where a text reducer
   exists (the CLI cases); the honest refusal where a surface has none
   (the wire/state cases — the reducer cannot re-observe those surfaces,
   and fail-closed beats silently comparing the wrong thing).
5. **Replay stability** — exact replays of every defect run, byte-identical.
6. **Challenge sensitivity** — the court must prove it can SEE the defect
   class: the built-in mutation operators for the CLI axes, and an
   EXTERNAL MUTATION PROVIDER (spec/mutation.md) for the wire/state axes
   — a domain program that proposes a mutant REINTRODUCING the historical
   defect; the court decides the verdicts from the run. A court that is
   blind to its own domain's defect class is refused.
7. **Evidence overhead** — FRF bytes per observation vs a conventional
   pass/fail baseline.

## The report and the gates

The report is canonical JSON: the corpus metadata, all seven measurements,
per-case residuals/claims/minimization/replay, and the evidence bytes.
`--check` (default) exits non-zero when any measurement violates the
standards — an undetected historical defect, a false positive, claim
inflation, a clean claim that did not compile, an insensitive court, or a
replay that did not reproduce. CI runs both experiments on every push.

The conventional-suite comparison is stated honestly: a unit or golden
suite tests only the cases its fixtures happen to cover and misses the
bugs its fixtures do not exercise. FRF's measured differentiators are the
residual (the preserved disagreement, not a pass/fail bit), the
challenge-proven sensitivity, the minimized reproducer, and the replayed
observation.
