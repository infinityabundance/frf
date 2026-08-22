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

## The trajectory program on reconstructed reproducers (v2)

`cargo xtask external-experiment-v2` (Phase 10) drives the same
reconstructed corpus through the three generalized trajectory axes
(series + trajectories, spec/trajectory.md):

1. **Version ladders** (`candidate_revision`) — the buggy and clean
   candidates are two revisions; the DEFECT lineage is observed at the
   buggy revision and ABSENT at the clean one, classifying
   `boundary-localized`/`abrupt`/`start` (the historical fix boundary);
2. **Environment matrices** (`environment`) — the defect court at three
   deterministic TZ/LANG coordinates; a real historical defect is not
   environment-specific, so the lineage must be `persistent`/`stable`;
3. **Authority transitions** (`authority_version`) — the historical
   VULNERABLE program is admitted as the pre-fix oracle; the buggy
   candidate's defect becomes observable exactly when the oracle was
   fixed (`boundary-localized` onset), and the clean candidate's stricter
   behavior ceases (`boundary-localized` cessation).

Every classification must rederive from the recorded observations; `--check`
(default) gates on any misclassification or lost defect.

## The trajectory program on ACTUAL upstream releases (v3)

The v1/v2 corpus is explicit that its cases are "real historical software
defects, reconstructed as minimal deterministic reproducers". v3 closes the
remaining credibility gap: the sides ARE the actual upstream releases,
built from the pinned sources by hermetic recipes
(`external-corpus/v3/build/build-all.sh` — containerized native builds on
a pinned fedora:41 image with the exact gcc/make/perl toolchain; Maven
Central jars pinned by SHA-256). The committed `builds/` artifacts make
the corpus self-contained: the experiment needs no network and no compiler
(a JVM is required to execute the Log4j case).

| Case | Vulnerable release | Fixed release | The real interaction |
| --- | --- | --- | --- |
| `shellshock` (CVE-2014-6271) | bash 4.3.0 (pristine upstream) | bash 4.3.30 (final 4.3 patch) | the side IS the bash binary; the fixture is a script; the trigger is the malicious function-import environment variable — the exact historical condition |
| `heartbleed` (CVE-2014-0160) | OpenSSL 1.0.1f | OpenSSL 1.0.1g (the fix release) | the side is a probe statically linked against the real libssl; it performs the exact historical exploit message sequence — ClientHello with the heartbeat extension, then the malformed heartbeat immediately after ServerHelloDone — and reports whether the linked library echoed process memory |
| `log4shell` (CVE-2021-44228) | Log4j 2.14.1 | Log4j 2.17.1 (JNDI disabled by default) | the side runs the probe on the real jars; the fixture logs a message containing the JNDI lookup; the probe reports whether the lookup error path fired |

`cargo xtask external-experiment-v3` drives each case through the same
four experiments as v2 — the version ladder, the environment matrix, and
both authority transitions — PLUS a **clean control**: the VULNERABLE
side against the clean fixture must produce ZERO residuals. The clean
control proves the divergence is the historical defect, not a spurious
difference between two real builds. The historical fix boundary must
classify exactly as declared:

```text
ladder (buggy -> fixed):      [observed, absent]   boundary-localized/abrupt/start
environment matrix:           [observed x3]        persistent/stable/none
authority transition (buggy): [absent, observed]   boundary-localized/abrupt/end
authority transition (fixed): [observed, absent]   boundary-localized/abrupt/start
clean control:                zero residuals       (the vulnerable side without the trigger)
```

The build provenance (`external-corpus/v3/build/build-manifest.json`)
pins every input: source URLs + SHA-256, the container image ID, the
toolchain versions, the compat patches (era-correct `-std=gnu89` for bash;
the documented `termio.h` removal workaround for openssl), and the SHA-256
of every committed artifact. Rebuilding from these exact inputs reproduces
the committed bytes. The native runtime closure (spec/execution-profile.md
§ native runtime closure) binds what the real binaries loaded at
observation time.
