# frf — the Forensic Residual Framework kernel, executed

[![ci](https://github.com/infinityabundance/frf/actions/workflows/ci.yml/badge.svg)](https://github.com/infinityabundance/frf/actions/workflows/ci.yml)

> de Beer, R. (2026). The Forensic Residual Framework - Evidence-First Software
> Construction, Behavioral Reconstruction, and Deterministic Residual
> Endoduction from the DSFB Prior-Art Stack (Version v1.2). Zenodo.
> <https://doi.org/10.5281/zenodo.22027039>

A minimal reference implementation of the FRF kernel (de Beer, 2026):

```
Authority → Court → Capture → Residual → Endoduction → Route → Disposition → Receipt → Claim
```

Seven verbs, raw captures never rewritten, one bounded claim per receipt,
and no code path that emits claim prose except the claim compiler.

The canonical object model, field names, and schema are defined in
*The Forensic Residual Framework* (de Beer, 2026; see the reference above).
This README does not re-explain FRF. Read Section 2 (kernel), Section 6
(endoduction), Section 10 (formal model), Section 12 (the worked court this
tool reproduces), and Appendix A (receipt schema) there.

## Install

```
cargo install --path .
```

(or `cargo build --release`, then use `target/release/frf`).

## The one command

```
./golden/demo.sh
```

Runs the full loop against the repo's own reference/candidate pair and
prints each stage: admission, court run, raw capture, two `open` residuals,
their endoduction tokens, the refused claim, the candidate patched and
verified by a NEW court run, the exit residual disposed `fixed` only after
that run closes it, the wording divergence disposed `intentional`, the
original receipt kept forever as a failure record, and the bounded claim
compiled from the resolution run's receipt — the run that actually observed
the passing candidate — with the Section 12 non-claim printed next to it.
Allow five minutes; it takes about five seconds.

## The verbs

| verb | what it does |
|---|---|
| `frf authority admit PATH --name N --version V` | admits an executable reference (sha-256, platform), writes `authorities/N-V.yaml`; admission is once |
| `frf court run MANIFEST.yaml` | executes authority and candidate against the fixture, captures raw stdout/stderr/exit, writes `open` residuals + endoduction tokens for each declared-axis disagreement |
| `frf residual dispose ID --disposition D --reason "..."` | appends an immutable disposition event: `fixed \| intentional \| environmental \| oracle_version \| harness \| unknown`; a one-line reason is mandatory, `open` is not settable, and `fixed` requires `--resolution-run` — a court run that reran the same question under a compatible envelope and shows the residual no longer reproduces (a disposition is not evidence). The observation file is never rewritten; the current disposition is the projection of the event list |
| `frf receipt emit RUN_ID` | binds court + authority + candidate + fixture + captures + residuals + dispositions into a trimmed Appendix A receipt |
| `frf claim compile RECEIPT_ID` | the only path that can emit a positive claim. Refuses while any residual is `open`/`unknown`/`harness`, and refuses a receipt whose run observed divergence — a failing run's receipt can never become parity, however its residuals are disposed; the refusal names the resolution run to compile from instead. Otherwise emits one conservative sentence + the non-claim, attributed to the exact candidate artifact the run executed |

Residual creation and endoduction happen inside `court run`; re-run
`receipt emit` after disposing to bind the new dispositions. `--root DIR`
(default `.frf`, or `$FRF_ROOT`) is the evidence root; paths in manifests and
authority records are working-directory-relative.

## Testing: regression, verification, fuzzing

Three suites, mirroring the framework's own discipline:

| suite | command | what it does |
|---|---|---|
| regression | `cargo test` | the invariant bank: every verb, every rejection path, reason-gate, re-disposition, id/path-safety boundary, timeout kill, and a zero-residual positive control |
| verification | `cargo test --test verify_tree` | walks the checked-in `frf/` tree and re-derives every artifact with the tool's own pure functions — authority hashes, raw-capture hashes, κ tokens, content-addressed receipt ids, and claim sentences byte-for-byte. Fails if any generated file was hand-edited |
| fuzzing | `cargo test --test fuzz` (deterministic, seeded, runs in CI) · `cargo +nightly fuzz run yaml_types\|cli_args\|store_ids` (libFuzzer, corpus-guided) | the negative controls: YAML deserializers never panic and never produce a forbidden disposition state, the CLI parser never panics, and ids that pass validation can never escape the store root |

`make test`, `make verify`, and `make fuzz-iters` wrap the same commands
(`FRF_FUZZ_ITERS` scales the deterministic harness). The libFuzzer targets
live in `fuzz/` with seed corpora checked in; they need nightly + clang +
`cargo install cargo-fuzz`.

## Where evidence lives

```
frf/
  authorities/   admitted once, never rewritten
  courts/        hand-authored court declarations (question, envelope, fixture)
  captures/      raw observations, content-addressed, immutable
  residuals/     immutable observations + derived tokens + <id>.events/ dispositions
  receipts/      bindings, content-addressed
  claims/        compiled claims, written only by `frf claim compile`
```

## Dogfood

The `frf/` tree checked into this repo is generated by the tool itself, by
running the golden path. What it establishes about this tool is exactly what
the checked-in claim says — malformed-input **exit class** for the repo's own
fixture pair on the recorded environment — and nothing more. This README
says no more than that receipt licenses.

## Known limitations (v0) — deliberate exclusions, not gaps

- **Densors, densorial inference, tekmeric framing** — philosophy left in the paper.
- **Taste Codex gates** (representation, boundary quarantine, misuse
  resistance, performance grounding) — the one executable piece (disposition
  requires a reason) is implemented; the rest is a later milestone.
- **Corpus admission, version ladders, environment matrices, independent
  witness maps** — v0 proves the kernel on one authority, one candidate, one fixture.
- **Wire/timing/filesystem/state courts** — `exit` and `stderr` only; a new
  axis is a new comparator, not a core change.
- **No GUI, dashboard, or metrics**; **no networked admission** — local executables, YAML on disk.
- **stdout is captured but not compared** in v0; claims never mention it.
- **Minimization courts are not implemented**: `next_court` routes are
  recorded nominally, and claims scope to the executed court, not the routed one.
- **`drift`/`slew` are `not-observed`** (sign block): v0 runs each court once;
  measuring them needs a repeated-run court.
- **Execution timeout is 60 s by default**, overridable via `FRF_EXEC_TIMEOUT_MS`
  (a test hook used by the regression suite's kill-path test; not a public knob).
- **`receipt.claims.positive` stays empty**: receipts are immutable, so the
  positive sentence is compiled into `claims/<receipt-id>.yaml` instead.
- **Dispositions are append-only events** under `residuals/<id>.events/`; the
  observation record is byte-immutable and never carries a disposition, and
  the current disposition is the projection of the last event — so a residual
  trajectory (`open` → suspected `harness` → … → `fixed`) survives
  re-disposition. The event chain is flat for now: parent-hash chaining and
  resolution-receipt edges are future work.
- **`fixed` never licenses parity from the run that observed the failure**:
  the positive claim must be compiled from the resolution run's receipt, the
  run that actually observed the passing candidate. This is enforced by the
  claim compiler, not by convention.
- **Receipt and run ids expose the first 8 hex digits (32 bits) of a SHA-256
  digest as a display identity**; lookup is exact within a store, but a
  canonical OpenReceipt (deterministic JSON, RFC 8785) with full-digest
  addressing is future work.
- **The environment digest covers os + architecture + kernel release only**;
  environment admission (libc, locale, timezone data, dynamic dependencies,
  container/Nix digests) is future work.
- **The subprocess runner drains pipes concurrently and records signals by
  number**, but the `ETXTBSY` spawn retry has no deadline of its own, and
  descendant processes that inherit stdout/stderr are not reaped (process-
  group / descendant policy is future work).
- **`environmental` and `oracle_version` weaken the envelope**: they close the
  residual but never license parity on its axis (the claim compiler excludes
  the axis). Envelope refinement records are future work.
- **The mandatory `reason` field, the `resolution_run_id` edge +
  `closure_predicate`, candidate `identity_hash` binding, residual
  `axis`/`authority`/`scope`, and per-axis hashes are v0 traceability
  additions** to the paper's minimal snippets, required to bind the mandatory
  disposition reason, attribute observations to the exact candidate artifact,
  and scope the claim sentences.
- **Residual ids are hardcoded to the `cli` domain** (`cli-exit-0001`), and
  `grammar_state` is derived from disposition via a fixed table.
- **Receipt replay commands and paths are working-directory-relative**; run
  from the same place you ran the court.
