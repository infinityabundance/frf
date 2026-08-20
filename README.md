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
| `frf court run MANIFEST.yaml` | hashes every artifact BEFORE executing, materializes immutable content-addressed snapshots under `objects/sha256/`, and executes THOSE; binds runner + comparator identity and the court's semantic identity at observation time; captures raw stdout/stderr/exit; writes `open` residuals + endoduction tokens for each declared-axis disagreement |
| `frf residual dispose ID --disposition D --reason "..."` | appends an immutable disposition event: `fixed \| intentional \| environmental \| oracle_version \| harness \| unknown`; a one-line reason is mandatory, `open` is not settable, and `fixed` requires `--resolution-run` — a court run that reran the same question under a compatible envelope and shows the residual no longer reproduces (a disposition is not evidence). The observation file is never rewritten; the current disposition is the projection of the event list |
| `frf receipt emit RUN_ID` | binds court + authority + candidate + fixture + captures + residuals + dispositions into an OpenReceipt, written as canonical JSON (RFC 8785) and content-addressed by the full SHA-256 of those canonical bytes; the runner, comparators, artifact, and semantic identities are copied from the capture, never reconstructed |
| `frf claim compile RECEIPT_ID` | the only path that can emit a positive claim. Claim dependency algebra: `harness` invalidates the run's evidence entirely; `open`/`unknown` residuals block only their axis; an axis this run observed diverging is never parity from this receipt, however its residuals are disposed (the refusal names the resolution run to compile from instead). Emits one conservative sentence scoped to the clean axes + the non-claim, attributed to the exact candidate artifact the run executed |
| `frf replay RUN_ID \| RECEIPT_ID` | re-executes the exact snapshotted artifacts + captured argv under a checked environment and requires the observation to reproduce byte-for-byte (identical sides, matching residual fingerprints, no new/missing residuals). Writes nothing: replay is evidence verification, not re-observation |

Residual creation and endoduction happen inside `court run`; re-run
`receipt emit` after disposing to bind the new dispositions. `--root DIR`
(default `.frf`, or `$FRF_ROOT`) is the evidence root; paths in manifests and
authority records are working-directory-relative.

## Testing: regression, verification, fuzzing

Three suites, mirroring the framework's own discipline:

| suite | command | what it does |
|---|---|---|
| regression | `cargo test` | the invariant bank: every verb, every rejection path, reason-gate, re-disposition, id/path-safety boundary, fail-closed envelope enforcement, object-store corruption refusal, timeout kill, and a zero-residual positive control |
| verification | `cargo test --test verify_tree` | walks the checked-in `frf/` tree and re-derives every artifact with the tool's own pure functions — authority hashes, raw-capture hashes, κ tokens, content-addressed receipt ids (re-serialized as canonical RFC 8785 JSON), and claim sentences byte-for-byte. Fails if any generated file was hand-edited. The canonicalizer itself is pinned against the RFC's own vectors plus a cross-implementation hash in `src/canon.rs` |
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
  objects/       content-addressed execution snapshots (sha256/<H>), verified + sealed
  residuals/     immutable observations + derived tokens + <id>.events/ dispositions
  receipts/      OpenReceipts, canonical JSON (RFC 8785), content-addressed by full digest
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
- **Wire/timing/filesystem/state courts** — `exit`, `stderr`, and `stdout`
  (first line only) are the v0.1.6 axes; a new axis is a new comparator,
  never a core change. Comparator identity is recorded in every receipt.
- **No GUI, dashboard, or metrics**; **no networked admission** — local executables, YAML on disk.
- **stdout is compared on its first line only, and only when the court
  declares the `stdout` axis**; the full stdout stream is captured and
  hashed but byte-identity is never claimed. The golden path deliberately
  stays on `exit` + `stderr` (Section 12's axes).
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
- **Claim dependency algebra is implemented**: a residual blocks only
  claims whose observable scope intersects it — `open`/`unknown` block
  their axis, `harness` invalidates the run's evidence entirely, and any
  residual on an axis excludes that axis from parity. Claims carry their IR
  (`observable_scope`, `excluded_residuals`); prose is one renderer. A
  full scope algebra (`fixture_scope`, `environment_scope`, `requires[]`,
  set-containment admission `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)`) is future work.
- **`fixed` never licenses parity from the run that observed the failure**:
  the positive claim must be compiled from the resolution run's receipt, the
  run that actually observed the passing candidate. This is enforced by the
  claim compiler, not by convention.
- **Receipts are canonical JSON (RFC 8785); every other artifact is YAML.**
  The receipt body is encoded with sorted keys, no whitespace, and the
  RFC's exact escaping, so its bytes — and therefore its identity — are
  reproducible by any implementation (the paper's cross-language
  OpenReceipt goal). The mixed tree is deliberate and documented here.
- **Run and receipt ids are full 64-hex SHA-256 digests** (`run-{court}-{sha256}`, `receipt-{run}-{sha256}`), the complete digest, not a display prefix. A short prefix is not accepted as input; ids are meant to be copied whole. CBOR (RFC 8949) as an alternative canonical encoding is future work.
- **The environment identity is captured structurally at court time** (os,
  architecture, kernel release, digest) and copied into receipts — a
  receipt never asks its own host what environment an old court ran under.
  The strata are still minimal; environment admission (libc, locale,
  timezone data, dynamic dependencies, container/Nix digests, clock source)
  is future work.
- **The subprocess runner is hostile to its own process tree (unix)**: each
  side runs in its own process group, pipes are drained concurrently with the
  wait loop, signals are recorded by number, and the whole group is
  terminated when the side exits or times out — a descendant that inherits
  stdout/stderr can never hold the capture open. `ETXTBSY` spawn retries are
  bounded to 1 s. Remaining: a side that escapes via `setsid` is outside the
  policy, and the capture is the process group's output, not byte-timed.
- **Artifacts execute from content-addressed snapshots** (`objects/sha256/<H>`):
  bytes are hashed BEFORE execution, materialized via temp-write → fsync →
  verify → atomic rename → seal (executed `0555`, data `0444`), RE-HASHED on
  every use (a corrupt or hand-planted object is refused, never executed),
  and re-sealed on every use. `{fixture}` resolves to the snapshot path; a
  script's `$0` is the snapshot path, so sides must not depend on their own
  path. This is content-addressed and corruption-checked; it is not
  cryptographically impossible for the same OS user to mutate between
  verification and execution (sealed memfd + execveat is future work).
- **Script interpreter identity is bound for scripts with resolvable
  shebangs** (path + hash of the resolved interpreter); binaries carry no
  interpreter binding yet (ELF loader + dynamic dependencies are future
  work). An `env` shebang (`#!/usr/bin/env python3`) records the
  downstream interpreter, not `/usr/bin/env` itself — the kernel interpreter
  chain (`InterpreterChain`) is a future refinement. Interpreter hashes are
  machine-specific: the checked-in tree's recorded values are evidence, not
  re-derivable cross-machine.
- **Runner + comparator implementations are bound at court time** (frf
  version, frf executable hash, per-axis implementation hashes) in the
  capture's `provenance` block and copied into receipts; a receipt never
  reconstructs provenance from the binary that emits it later. Comparator
  RELATION versions must be bumped when a relation's semantics change.
- **Semantic identity is separated from implementation provenance**: the
  court's semantic identity hashes the question, falsifier, authority
  ARTIFACT bytes, fixture bytes + arguments, the full envelope, and
  comparator SEMANTIC identities (specification hashes) — never
  implementation hashes, and never the court id or candidate name (labels).
  Two independent FRF implementations that implement the same comparator
  specifications ask the same question; resolution requires the same
  semantic identity + environment digest, and deliberately does NOT require
  equal provenance (a stricter reproducibility policy is future work).
- **The admissibility envelope is fail-closed**: declared `normalizers`,
  non-`single-run` `replay_scope`, a current platform outside the declared
  `platforms`, or an authority admitted for another platform all REFUSE the
  court — declaration never masquerades as enforcement.
- **Every evidence identity uses a domain-separated structured preimage**
  (`FRF/<KIND>/v1` + canonical JSON): run ids, court semantic identity,
  comparator specifications, and residual fingerprints. No
  delimiter-assembled strings, so no field-boundary ambiguity.
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
- **Replay is a first-class evidence operation** (`frf replay <run|receipt>`):
  it re-executes the snapshotted artifacts + argv under a checked
  environment (declared platforms, matching environment digest) and
  requires byte-identical reproduction with matching residual fingerprints.
  The receipt's replay block is structured (`program`, `evidence_root`,
  `argv`, `expected_run_identity`); a residual's `reproducer` is the run
  that observes it. Replay writes nothing.
