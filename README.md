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
| `frf authority admit PATH --name N --version V` | admits an executable reference (sha-256, platform), writes `authorities/N-V.json`; admission is once |
| `frf court run MANIFEST.yaml [--repeat N] [--candidate-revisions P1,P2,…] [--authority-versions V1,V2,…] [--environment-point LABEL] [--time-point LABEL] [--series-parent SERIES_ID]` | hashes every artifact BEFORE executing, materializes immutable content-addressed snapshots under `objects/sha256/`, and executes THOSE; binds runner + comparator identity and the court's semantic identity at observation time; captures raw stdout/stderr/exit (and, with a `produce` clause, the sides' PRODUCED ARTIFACT TREES — the filesystem-tree surface: each side's output directory is walked after execution, every produced file copied under the run and hashed, so the court observes what its sides BUILD, not only what they print — `spec/produced-artifacts.md`); writes `open` residuals + endoduction tokens for each declared-axis disagreement — each axis evaluated through the ONE evaluation plan (spec/evaluation.md). Observable axes are PROTOCOL IDENTIFIERS (the built-ins are `exit`, `stderr`, `stdout`, `filesystem.tree`, `bytes.wire`, `structured.state`; any valid id can be declared) and each declared observable must be SERVED by a comparator: an in-binary registry row, or an EXTERNAL comparator program the manifest declares (`comparators:` — the extension protocol: canonical JSON request on stdin with base64 side streams, a response that must cryptographically name the request it answers, fail-closed interpretation). An externally served axis's canonical request + response + content-addressed invocation/result records are preserved under the run — the instrument is part of the evidence. The comparison SURFACE can be built by declared EXTERNAL NORMALIZERS (`normalizers:` + the envelope's `normalizers` list, spec/normalizer.md): raw streams in, the normalized streams the court compares out, in envelope order on BOTH sides — the raw streams survive as each invocation's request evidence (an observation is never rewritten, the comparison surface is), the capture's compared hashes derive from the recorded chain end to end, and a normalizer that moves a stream it is not declared to move refuses the run. A declared CAPTURE ADAPTER (`capture_adapters:`, spec/capture-adapter.md) captures the ADAPTED observation for an externally served domain axis (`dns.wire`, …) — the core runs observables without knowing what packets or filesystems are. Declared MINIMIZERS (`minimizers:`, spec/minimizer.md) bind the κ-route reducers at observation time. One axis may be declared: `--repeat N` (re-execute N times — nondeterminism is the point), `--candidate-revisions` (one run per candidate artifact), `--authority-versions` (one run per admitted authority version), `--environment-point`/`--time-point` (this run is one point of the environment/time experiment at a declared coordinate; the series accumulates — every observation COORDINATE is a point, identical evidence sharing the content-addressed run; a branched experiment refuses an implicit append, `--series-parent` chooses the branch). A series court writes a parent-linked, content-addressed `ExecutionSeries` (`series/<id>.json`, `frf-series-v3` — every append is a new immutable snapshot of the experiment's history) and derives one residual TRAJECTORY per observed lineage (`trajectories/<lineage>.<coordinate-system>.<series>.json`): the ordered observations plus the deterministic drift/slew/localization/bands classification. The lineage identity (`FRF/RESIDUAL-LINEAGE/v1`) is stable across candidate revisions, authority versions, environments, and time — a trajectory records the MOVEMENT of a divergence, not merely the exact recurrence of one byte pattern. Runs never know which experiments reference them |
| `frf court minimize RESIDUAL_ID` | the routed minimizer (the residual's κ token routes `cli-exit-minimize`/`cli-diagnostic-minimize`): the built-in deterministic ddmin over the fixture's lines, OR the EXTERNAL minimizer the court declared for that route (spec/minimizer.md — bound at observation time, its program sealed and recorded in the capture; it PROPOSES a reduced fixture and the core COURT-VERIFIES the proposal with the one evaluation plan — a proposal that does not preserve the lineage is recorded-but-not-accepted, the refusal itself content-addressed evidence, and no reduction is ever accepted unverified), holding the candidate, authority, comparator, and environment fixed (each bound by IDENTITY in the record), while the fixture shrinks. Preservation is decided by the SAME evaluation plan that observed the residual (spec/evaluation.md) — never a re-derived built-in projection — with the declared normalizers re-applied on every executable attempt. Every EXECUTABLE attempt is recorded in a content-addressed `ReductionRecord` (`reductions/<id>.json`, `frf-reduction-v4`) with its role (baseline/candidate/final_verification), outcome (preserved/lost/harness_failure — an unevaluable attempt aborts), and acceptance; the attempt budget is a HARD gate around every execution; minimality is stated precisely (one-minimal at line granularity, proven only when the search completed); the final reproducer is court-verified; an external reduction binds the minimizer's semantic + implementation identities and its content-addressed invocation/result records. v0.1.31 reducers: text fixtures at line granularity (binary fixtures are refused honestly; a produced-artifact surface — `filesystem.tree` — refuses minimization: the reducer cannot re-observe produced trees, and fail-closed beats silently comparing the wrong surface) |
| `frf court challenge MANIFEST [--operators exit-class,stderr-first-line,…]` | the negative controls (spec/challenge.md + spec/mutation.md): a passing court proves nothing unless it can SEE the defect classes it declares. For every built-in mutation operator whose targeted axis the court declares (default) or the requested set, the challenge runs the court against a MUTANT candidate — a deterministic wrapper of the admitted reference that alters exactly one observable dimension (`exit-class`, `stderr-first-line`, `stdout-first-line`; the wrapper resolves the reference relative to itself, so the mutant bytes are root-independent and rederivable) — and requires a divergence on the targeted axis and ONLY on it. Domain surfaces are covered by DECLARED EXTERNAL MUTATION PROVIDERS (`mutations:`, spec/mutation.md): the provider receives the court's question + the exact reference and fixture artifacts (canonical JSON request) and PROPOSES one mutant candidate; the court runs the proposal and independently derives the verdicts from the run — the extension proposes, the court decides, and the proposal's request/response/invocation/result evidence is preserved under `challenges/<id>/mutation/` and cross-verified on read. Each challenge writes a content-addressed `CourtChallenge` (`challenges/<id>.json`; the verdicts `saw_defect`/`specificity_clean` rederive from the run, never from the file); the mutant runs are ordinary content-addressed runs that replay like any other. A court that is BLIND to a seeded defect, or conflates it with another axis, is refused — the records remain as evidence, the command exits non-zero |
| `frf residual dispose ID --disposition D --reason "..."` | appends an immutable, content-addressed disposition EVENT to `residuals/<id>.events/` (`fixed \| intentional \| environmental \| oracle_version \| harness \| unknown`); a one-line reason is mandatory, `open` is not settable, and `fixed` requires `--resolution-run` — a court run that reran the same question under a compatible envelope and shows the residual no longer reproduces (a disposition is not evidence). Events are hash-chained: each carries its own `event_id` (SHA-256 of its content), its `parent_event_id`, and its `evidence_refs` (the resolution run). The observation file is never rewritten; the current disposition is the projection of the last event |
| `frf receipt emit RUN_ID` | binds court + authority + candidate + fixture + captures + residuals + dispositions into an OpenReceipt, written as canonical JSON (RFC 8785) and content-addressed by the full SHA-256 of those canonical bytes; the runner, comparators, artifact, and semantic identities are copied from the capture, never reconstructed, each residual binds the EXACT disposition event (`disposition_event_id`) that supplied its state, and each residual carries TRAJECTORY EVIDENCE per coordinate system (`sign.trajectory_evidence`, OpenReceipt v12) — every entry PINs the exact ExecutionSeries snapshot its drift/slew were derived from — so a receipt points at immutable nodes in the evidence graph, it does not merely copy state. v13 also copies the normalizer relations applied to the compared streams and the normalizer/capture-adapter/minimizer implementations the court bound at observation time. v14 copies the capture-adapter relations (`adapter_semantics`) — the extraction schemes that defined the observations delivered to externally served axes, part of the court's question (FRF/COURT/v2) |
| `frf claim compile RECEIPT_ID [--json] [--policy baseline\|sensitivity-backed\|independently-witnessed\|high-assurance]` | the only path that can emit a positive claim, and it accepts ONLY a *verified* receipt: the id must equal the SHA-256 of the canonical DOCUMENT (hashed as raw strict JSON — duplicate property names refused, unknown properties refused — never as a typed projection), the document must pass OpenReceipt semantic conformance, and it must derive from its verified capture (fingerprints, κ tokens, disposition events, and `fixed` resolution edges re-checked). The full Claim IR is the paper's scope algebra: `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)` — K carries authority/candidate/fixture/family/observable/environment/version/temporal scopes, `requires` (the premise receipts), `blockers`, and `excluded_evidence`. `harness` invalidates a premise run; `open`/`unknown` residuals block EXACTLY the claims whose scope intersects their surface — wherever the divergence was recorded (the compiler scans the whole store), so an unexplained divergence on the claimed candidate/axis/fixture/environment blocks even a later passing run, while a divergence about a different candidate or axis never does. An axis this run observed diverging is never parity from this receipt, however its residuals are disposed (the refusal names the resolution run to compile from instead). The claim is compiled under a declared ADMISSION POLICY (spec/claim.md §0): `baseline` (observation evidence only), `sensitivity-backed` (every claimed axis must have CHALLENGE coverage — the court demonstrated it can SEE the surface's defect class: same court semantic identity, same reference artifact, targeted axis, verdicts recomputed from the mutant run), `independently-witnessed` (sensitivity + a verified witness attestation of this receipt), `high-assurance` (independently witnessed + the reference execution profile and capture bounds). The compiled claim CARRIES the capability evidence — per-axis challenge ids, witness ids, the replay profile — so admission re-derives from the claim alone, and the bundle export carries that evidence. Emits one conservative sentence scoped to the clean axes + the non-claim, attributed to the exact candidate artifact the run executed; `--json` renders the same IR canonically (prose is one renderer) |
| `frf replay RUN_ID \| RECEIPT_ID [--policy exact\|semantic]` | rederives the run identity from the capture's own recorded fields (the name is a claim until recomputed) and re-executes the exact snapshotted artifacts + captured argv under a checked environment, requiring the observation to reproduce byte-for-byte (identical sides, matching residual fingerprints, no new/missing residuals). Each declared axis is re-observed with the SAME comparator that observed it: a built-in axis rederives its projection; an externally served axis RE-INVOKES the exact snapshotted comparator program against the reproduced sides — the rebuilt request must rederive to the recorded `request_cid` and the outcome must match the recorded result. The comparison surface is re-built first: the declared NORMALIZERS are re-invoked (exact: each rebuilt request must rederive; semantic: the normalized surface must reproduce) and the CAPTURE ADAPTERS are re-invoked to reproduce the adapted observations. A receipt id additionally enforces its `expected_run_identity`. The reproduction policy is declared, never implicit: **exact** (default) additionally requires the same execution profile + capture bounds, the same environment digest, working directory, and interpreter chains (kernel interpreter, env resolver, downstream interpreter, PATH digest) — any provenance drift REFUSES; **semantic** admits and REPORTS provenance differences (env, interpreters, profile, bounds) and requires the same bounded observation anyway. Writes nothing: replay is evidence verification, not re-observation |
| `frf bundle export RECEIPT_ID [--output PATH] [--single]` | exports a receipt's portable closure — manifest + receipt + captures (+ the externally served axes' comparator request/response/invocation/result evidence + the normalizer/capture-adapter invocation evidence and any external-minimizer refusal evidence) + content-addressed objects (the executed artifacts AND the comparator/normalizer/adapter/minimizer instrumentation, walked via the capture's typed `evidence_refs`) + the admitted authority record + residuals + disposition-event chains (+ the compiled claim when present, WITH its capability evidence — the challenge records and mutant runs a sensitivity-backed claim was compiled under, and the witness statements + preserved documents an independently-witnessed claim names), sealed read-only, only after the receipt verifies against the source tree. The manifest (frf-bundle-v3) declares its own CONTAINER: a `directory` tree (default, `bundles/<receipt-id>.frf`), or `--single` — ONE deterministic tar archive with the manifest inside: fixed metadata, entries in path order, so two exports of the same receipt are byte-identical |
| `frf bundle verify BUNDLE.frf` | verifies a bundle against ITSELF (either container — a directory, or a single-file archive, auto-detected and verified from a temp extraction): every inventory file must exist and hash to its recorded digest, the manifest must cover the receipt's complete re-computed closure, the declared container must match the actual one, and the receipt must verify against the bundled evidence alone — no original source tree, no exporting FRF installation. Verification never executes anything |
| `frf bundle replay BUNDLE.frf [--policy exact\|semantic]` | re-executes the bundle's snapshots with the captured argv under a checked environment, from the bundle ALONE: the bundle is first proven against itself, then the receipt is replayed with the reproduction policy. The temp store is laid out under the receipt's declared evidence root and the sides execute from that reconstructed invocation root — recorded root-relative argv paths resolve to the BUNDLE's own verified objects, never the surrounding tree. Exact replay additionally requires the same execution provenance (profile, bounds, environment digest, recorded working directory); semantic reports any drift and requires the same bounded observation |
| `frf witness attest run\|receipt\|residual SUBJECT_ID --id WITNESS_ID --relation R --program PATH --statement "..."` | the witness extension protocol (spec/witness.md): an external program attests a content-addressed subject — the subject's content address (run identity digest / receipt digest / residual fingerprint) is REDERIVED from the verified evidence object, never read from the caller; the response must name the request it answers and attest EXACTLY the requested statement (a decline is a refusal). The attestation is recorded as a content-addressed `WitnessStatement` (`witnesses/<id>.json`, canonical JSON) with the canonical request/response preserved as evidence, and re-verified on every read |

Residual creation and endoduction happen inside `court run`; re-run
`receipt emit` after disposing to bind the new dispositions. `--root DIR`
(default `.frf`, or `$FRF_ROOT`) is the evidence root; paths in manifests and
authority records are working-directory-relative.

## Testing: regression, verification, fuzzing

Three suites, mirroring the framework's own discipline:

| suite | command | what it does |
|---|---|---|
| regression | `cargo test` | the invariant bank: every verb, every rejection path, reason-gate, re-disposition, id/path-safety boundary, fail-closed envelope enforcement, object-store corruption refusal, timeout kill, the court-challenge negative controls (spec/challenge.md), and a zero-residual positive control |
| verification | `cargo test --test verify_tree` | walks the checked-in `frf/` tree and re-derives every artifact with the tool's own pure functions — authority hashes, raw-capture hashes, κ tokens, content-addressed receipt ids (re-serialized as canonical RFC 8785 JSON), and claim sentences byte-for-byte. The tree is *self-authenticating*: every capture and receipt is consumed through the verified loaders, which rederive run identities and receipt ids from recorded fields and refuse any drift. Fails if any generated file was hand-edited. The canonicalizer itself is pinned against the RFC's own vectors plus a cross-implementation hash in `src/canon.rs` |
| fuzzing | `cargo test --test fuzz` (deterministic, seeded, runs in CI) · `cargo +nightly fuzz run yaml_types\|cli_args\|store_ids` (libFuzzer, corpus-guided) | the negative controls: the YAML manifest parser and the canonical-JSON evidence deserializers never panic and never produce a forbidden disposition state, the CLI parser never panics, and ids that pass validation can never escape the store root |
| conformance | `cargo test --test conformance` | walks the OpenReceipt protocol corpus in `conformance/` at TWO levels: **structural** — every `valid/` fixture must parse, deserialize, canonicalize to the pinned bytes, and hash to the pinned digest; `invalid/` fixtures must be refused; the JSON Schema (`spec/openreceipt.schema.json`) is enforced, including the closed disposition set and the schema version — and **semantic** — every `invalid-semantic/` fixture (structurally valid, semantically broken) must fail `validate_semantics`: disposition cross-field rules, rederivable environment digest + court semantic identity, verdict consistency, replay target, κ-token rederivation, interpreter-chain consistency, argv/declared-argument correspondence |
| independent | `cargo test --test independent` · `cargo xtask verify corpus conformance` · `cargo xtask verify bundle golden/work/portable.frf` · `go test ./verifier-go/...` · `go run ./verifier-go verify bundle golden/work/portable.frf` | the protocol-separation milestone: TWO deliberately small SECOND implementations of FRF must agree with the Rust reference engine on the same corpus and the same bundle. The Rust xtask verifier (`cargo xtask verify`, xtask/, no execution, no dependency on the frf library) rederives canonical bytes, pinned hashes, structural + semantic refusals (duplicate property names refused per RFC 8785 I-JSON; unknown properties refused per schema key sets), run/court/fingerprint/event identities, κ tokens, disposition-event chains, trajectory signs, resolution edges, and the admissible Claim IR. The GO verifier (verifier-go/, same contract, sharing no parsing library with either Rust implementation — it parses evidence with its own strict JSON reader and its own RFC 8785 encoder, not even `encoding/json`) must reach the same verdicts on the same corpus and the same bundles. Three implementations agreeing on one bundle is the difference between a protocol and a Rust file format |
| empirical | `make experiment` · `cargo xtask experiment golden/work/experiment.json` · `cargo xtask external-experiment golden/work/external-experiment.json` | the empirical program (spec/empirical-program.md): seeded mutations over the cross-domain corpus (CLI, filesystem tree, byte/wire, structured state, timing — 7 seeded defects + 5 clean controls), measured against conventional suites — defect discovery (every seed detected), specificity (zero false positives), claim inflation (no claim covers a seeded-defect axis; every clean claim is bounded), minimization cost (ddmin attempts + reduction), replay stability (36/36 byte-identical replays), and evidence overhead (FRF bytes vs a pass/fail baseline). The EXTERNAL program drives the same measurements over REAL historical defects — Apple's `goto fail` (CVE-2014-1266), bash's Shellshock (CVE-2014-6271), OpenSSL's Heartbleed (CVE-2014-0160), Log4j's Log4Shell (CVE-2021-44228), the Mars Climate Orbiter unit mismatch, and the two-digit-year Y2K bug — each with a fixed reference, the buggy historical candidate, a distinct clean control, and a challenge that proves the court can SEE its domain's defect class (external mutation providers for the wire/state domains). Exits non-zero if any measurement violates the standards |

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
  series/        ExecutionSeries records: the experiments (content-addressed;
                 every append is a new snapshot)
  trajectories/  derived residual trajectories: lineage × coordinate system × series
  reductions/    minimization experiments: every ddmin attempt + the court-
                 verified reproducer, content-addressed
  receipts/      OpenReceipts, canonical JSON (RFC 8785), content-addressed by full digest
  claims/        compiled claims, written only by `frf claim compile`
```

`cargo xtask verify` (xtask/) and `frf-verifier-go` (verifier-go/) are two
independent implementations (Rust without the frf library; Go without any
shared parsing library), neither executing anything: both verify bundles and
run the conformance corpus without any frf installation, so a bundle's
evidence graph can be authenticated on a machine that never built the
reference engine.

## Independent verifier

FRF is a protocol, not a Rust file format, only if an independent implementation
can take the same evidence and reach the same verdict. There are now TWO
independent implementations, each deliberately small and deliberately boring:

- **`cargo xtask verify`** (xtask/, Rust) — no execution, no dependency on the
  reference engine's library. It loads a bundle and rederives everything: the
  RFC 8785 canonical bytes and pinned hashes of every receipt (hashed as the
  DOCUMENT — strict I-JSON parsing refuses duplicate property names, and every
  object is checked against its schema's key set, mirroring
  `deny_unknown_fields`), the run identity from the capture's own recorded
  fields, the court semantic identity, residual fingerprints, κ tokens and
  `blocks_claims`, disposition-event chains (content-addressed, parent-hashed),
  trajectory signs (the drift/slew classification REDERIVES from the
  observations — it is not read from the file), resolution edges, and the
  admissible Claim IR with the full scope algebra.
- **`frf-verifier-go`** (verifier-go/, Go) — the same contract, written in a
  genuinely different ecosystem. It shares not a single parsing library with
  either Rust implementation: it never reads court manifests, and it parses
  every evidence document as strict canonical JSON with its OWN RFC 8785
  encoder (duplicate property names refused, UTF-16 code-unit key sorting,
  numbers refused at canonical encode — the FRF value domain), not even
  `encoding/json`. Given only `conformance/` + a bundle, it rederives the same
  JCS bytes, the same CIDs, the same run/court/fingerprint identities, the same
  κ tokens, the same disposition chains, the same knowledge-snapshot root, and
  the same admissible Claim IR.

Both verifiers share the same two oracles:

- **Same corpus, same verdict.** The structural (`conformance/invalid/`) and
  semantic (`conformance/invalid-semantic/`) corpora are the shared oracle:
  the Rust engine, the xtask verifier, and the Go verifier must ALL accept
  every `valid/` fixture byte-for-byte (canonical form + digest) and refuse
  every `invalid*/` fixture. `cargo xtask verify corpus conformance` and
  `go run ./verifier-go verify corpus conformance` are that check.
- **Same bundle, same claim set.** `cargo xtask verify bundle <dir>` and
  `go run ./verifier-go verify bundle <dir>` each verify a portable bundle
  against itself — manifest hash proof, receipt content-addressing, capture
  run-identity rederivation, side-file rehash, event-chain/sign/token
  rederivation, resolution-edge verification, closure completeness — and print
  the Claim IR the Rust claim compiler would license. A tampered bundle is
  refused with the corruption named.

The integration suite (`tests/independent.rs`) runs the Rust verifier's three
properties in CI: it accepts the golden bundle, passes the corpus, and refuses
a tampered bundle. The demo job additionally runs `cargo xtask verify` AND the
Go verifier against the regenerated bundle and corpus, so the conformance
triangle — Rust reference engine, Rust xtask verifier, Go verifier — is over
bytes, not over a shared parser.

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
- **Observable axes are OPEN PROTOCOL IDENTIFIERS, not a closed enum** —
  the in-binary registry serves SIX built-in comparators: the three
  Section-12 CLI surfaces (`exit`, `stderr`, `stdout`) and three
  domain-general surfaces (`filesystem.tree` over PRODUCED ARTIFACTS,
  `bytes.wire` over the raw stdout stream, `structured.state` over stdout
  JSON); any valid lowercase identifier (`dns.wire`, `tzif.bytes`, …) can
  be declared in the envelope and served by an external comparator through
  the extension protocol, and residual kinds are extensible identifiers
  too (the built-in classifiers are `exit` and `text`; an external
  comparator's declaration names its own). The evidence core runs
  observables without knowing what stdout, packets, or filesystem trees
  are. Comparator identity is recorded in every receipt.
- **Comparator extension protocol** (`spec/comparator.md`): an observable
  axis can be served by an EXTERNAL program — any language — through a
  canonical stdin/stdout protocol (base64 raw streams, canonical JSON
  request/response, response `request_id` binding: a response must
  cryptographically name the exact request it answers). The declared
  relation/extractor/residual-classifier/version define the comparator's
  SEMANTIC identity (the same formula as the in-binary registry: same spec,
  same question); the program's bytes define its IMPLEMENTATION identity,
  snapshotted and re-hashed before every use, with its interpreter chain
  recorded (the same `ArtifactIdentity` discipline as candidates), and
  recorded in the capture's provenance alongside the runner hash. Every
  external invocation preserves its canonical request, canonical response,
  and content-addressed invocation/result records under the run; the
  bundle closure carries them (and the instrument bytes) via the capture's
  typed evidence references; replay RE-INVOKES the exact snapshotted
  comparator and requires the request to rederive and the outcome to
  reproduce. Failing, indeterminate, contradictory, or undeclared
  comparators refuse the court. The remaining extension protocols are now
  executable too: **normalizers** (`spec/normalizer.md` — external programs
  that map raw streams to the COMPARISON SURFACE; the raw streams survive
  as request evidence, the capture's compared hashes derive from the
  recorded chain end to end, replay re-invokes them, and a normalizer that
  moves what it is not declared to move is refused), **capture adapters**
  (`spec/capture-adapter.md` — external programs that capture the ADAPTED
  observation for a domain axis like `dns.wire`, so the core observes
  surfaces it has no built-in capture for), **external minimizers**
  (`spec/minimizer.md` — a declared reducer per κ route, bound at
  observation time; the core COURT-VERIFIES every proposal with the one
  comparison operation, and an uncourt-verifiable proposal is
  recorded-but-not-accepted), and **witnesses** (`spec/witness.md` —
  `frf witness attest` records a content-addressed attestation of a
  rederived subject content address).
- **No GUI, dashboard, or metrics**; **no networked admission** — local executables, canonical-JSON evidence on disk (YAML only for human-authored court manifests).
- **stdout is compared on its first line only, and only when the court
  declares the `stdout` axis**; the full stdout stream is captured and
  hashed but byte-identity is never claimed. The golden path deliberately
  stays on `exit` + `stderr` (Section 12's axes).
- **Verified-on-read evidence (the evidentiary validity layer)**: a
  content-addressed evidence object is never consumed semantically until its
  identity AND derivation are verified. `claim compile` and `replay` accept
  only `ReceiptVerified`/`CaptureVerified` (`src/verify.rs`): a receipt's
  content address is computed from the raw DOCUMENT — strict I-JSON parsing
  refuses duplicate property names (RFC 8785 §2), the canonical bytes hash
  the document itself, and every OpenReceipt type carries
  `deny_unknown_fields`, so an unknown property is refused, never
  deserialized away before the digest is checked — then semantic
  conformance, derivation from the verified capture, dispositions evidenced
  against the append-only event history, and re-verified `fixed` resolution
  edges. Parsing data cannot turn it into evidence. The type distinction is
  structural — a `ReceiptVerified` cannot be fabricated outside the verifier.
- **The resolution edge references a run, not a resolution RECEIPT**: a
  `fixed` event's `evidence_refs` names the closing run; a resolution-receipt
  edge and `frf status` (materializing the current graph state as a
  projection) are future work.
- **The receipt is a root into the evidence graph, not the whole graph**:
  trajectories, minimization attempts (reductions), and witness statements
  are now first-class protocol objects of their own; bundles make the
  receipt's closure portable.
- **The semantic validator is document-level by design**: cross-store
  checks (a `fixed` resolution edge actually closing, run existence) happen
  in the verified loader, not in `validate_semantics`; the corpus in
  `conformance/invalid-semantic/` therefore covers document-level rules
  only. The independent verifier (`cargo xtask verify`) closes the gap:
  it rederives the cross-store identities a document alone cannot — run
  identity, residual fingerprints, disposition-event chains, resolution
  edges — from the bundle, and the Rust engine and the verifier are both
  run against the same corpus in CI.
- **Minimization is executable**: `frf court minimize` routes the residual's
  κ token (`cli-exit-minimize`/`cli-diagnostic-minimize`) to the reducer for
  that route: the built-in deterministic ddmin over fixture lines, or an
  EXTERNAL minimizer the court declared and bound at observation time
  (spec/minimizer.md — the core COURT-VERIFIES every proposal with the one
  comparison operation; an uncourt-verifiable proposal is
  recorded-but-not-accepted and no reduction is ever accepted unverified).
  Candidate, authority, comparator, and environment stay fixed, with every
  attempt recorded in a content-addressed `ReductionRecord`
  (`frf-reduction-v4`, which binds the external minimizer's semantic +
  implementation identities when one reduced) and the final reproducer
  court-verified. v0.1.31 reducers: text fixtures at line granularity
  (binary fixtures refused; a produced-artifact surface — `filesystem.tree`
  — refuses minimization, because the reducer cannot re-observe produced
  trees: fail-closed beats silently comparing the wrong surface). Domain
  reducers (argv, environment variables,
  AST nodes, protocol message sequences) are future work; claims scope to
  the executed court, not the routed one.
- **Courts prove they can see (the negative controls)**: `frf court
  challenge` (spec/challenge.md) runs the court against a MUTANT candidate
  per declared observable — a deterministic wrapper of the admitted
  reference that alters exactly one dimension (exit class, first stderr
  line, first stdout line; the wrapper resolves the reference relative to
  itself, so the mutant bytes are root-independent and rederivable from
  operator + reference hash) — and requires a divergence on the targeted
  axis and only on it, recording a content-addressed `CourtChallenge` whose
  verdicts rederive from the run. A blind or conflation-prone court is
  refused. Challenge evidence ENTERS claim admission through the claim
  policies (spec/claim.md §0): `sensitivity-backed` and above require
  challenge coverage per claimed axis, and the compiled claim carries the
  exact challenge ids. Domain surfaces are challenged through EXTERNAL
  MUTATION PROVIDERS (spec/mutation.md — the extension proposes, the court
  decides, and the proposal's request/response/invocation/result evidence
  is preserved and cross-verified); the built-in operators remain CLI-only.
- **The first non-CLI courts exist** (Phase 8, `spec/produced-artifacts.md`
  + `tests/noncli_courts.rs`): a court observes what its sides BUILD and
  what they emit on ANY surface, not only CLI text. `produce` captures the
  sides' output trees immutably (every produced file copied under the run,
  hashed, recorded in the side capture; the manifest formula is shared with
  the independent verifier) and the built-in `filesystem.tree` comparator
  diffs them per path; `bytes.wire` compares the raw stdout stream
  byte-exactly; `structured.state` diffs stdout JSON field by field
  (residuals surfaced by JSON pointer); `timing.latency` is served by an
  EXTERNAL envelope comparator through the extension protocol. The full
  pipeline runs on every surface — capture, residuals, tokens, receipts,
  claim gating, replay, bundles — and the golden demo now runs the
  filesystem-tree court. v0 produced capture refuses symlinks and
  non-regular files; a mutation operator for the domain surfaces (and
  produced trees in the challenge battery) awaits the mutation extension
  protocol.
- **Residual trajectories are executable over five axes**: the repeat
  axis (`--repeat N`), the candidate-revision axis (`--candidate-revisions`),
  the authority-version axis (`--authority-versions`), and the
  accumulating environment/time axes (`--environment-point`/`--time-point`
  with declared coordinate labels). The trajectory SUBJECT is the residual
  LINEAGE (`FRF/RESIDUAL-LINEAGE/v1` — kind/axis/surface/fixture/family/
  authority name), stable across candidate revisions, authority versions,
  environments, and time: the same lineage at three commits has three
  different exact fingerprints but ONE trajectory, so the MOVEMENT of a
  divergence is recorded, not just the recurrence of one byte pattern.
  Trajectories are DERIVED from the referenced `ExecutionSeries` snapshot
  (a run never knows its experiments; the series references the runs).
  Series snapshots are content-addressed and PARENT-LINKED
  (`frf-series-v3`): an append is a new immutable node of the experiment's
  history, identical evidence shares the content-addressed run while every
  observation COORDINATE is still a point (three environment observations
  of the same deterministic evidence are three points, not one), and a
  BRANCHED experiment (two heads) refuses an implicit append —
  `--series-parent` chooses the branch. A residual does not have one
  universal drift: the receipt entry carries TRAJECTORY EVIDENCE per
  coordinate system (`sign.trajectory_evidence`, OpenReceipt v13), each
  entry pinning the exact series snapshot its drift/slew were derived
  from, so later experiments that reference the same content-addressed run
  can never change what an emitted receipt means. The classification is a
  deterministic table: drift
  (persistent/transient/recurrent) × slew (stable/abrupt/burst/recurrent)
  plus localization (start/end/both/interior — the paper's
  boundary-localized) and bands (2+ = the paper's version-stratified along
  a version axis). `gradual` needs a magnitude dimension (presence is
  binary) and is deliberately not claimed; `fixture_reduction` belongs to
  the minimization protocol.
- **Execution profiles are declared contracts, and replay distinguishes exact
  from semantic reproduction** (`spec/execution-profile.md`): the reference
  profile is `frf-exec-linux-v1` — direct exec (no shell), one process
  group per side with group termination on exit/timeout/overflow, concurrent
  pipe draining, bounded spawn retries, a 60 s execution timeout (override
  via `FRF_EXEC_TIMEOUT_MS`, a test hook), 16 MiB per-stream capture caps
  (overflow REFUSES the run — truncated output is never evidence), and child
  resource limits (`RLIMIT_AS` 2 GiB, `RLIMIT_CPU` 30 s, `RLIMIT_NOFILE`
  1024; a side that hits one dies by the kernel's signal outcome, which the
  capture records). The profile + the exact capture bounds that applied are
  recorded at observation time (capture v10, OpenReceipt v13) and copied into
  every receipt — a receipt never guesses what the harness enforced.
  `frf replay --policy exact` requires the same profile, bounds,
  environment digest (os/arch/kernel/locale/timezone/umask), working
  directory, and interpreter chains, and refuses on any drift;
  `--policy semantic` admits and reports provenance differences and requires
  the same bounded observation. Profiles other than the reference one, and
  non-Linux process capture (container/VM profiles), are future work.
- **`receipt.claims.positive` stays empty**: receipts are immutable, so the
  positive sentence is compiled into `claims/<receipt-id>.json` instead.
- **Dispositions are append-only, content-addressed, hash-chained events**
  under `residuals/<id>.events/`: each event carries its own `event_id`
  (SHA-256 of `FRF/DISPOSITION-EVENT/v1` over its content), its
  `parent_event_id` (the previous event — the chain link), and
  `evidence_refs` (the resolution run for a `fixed` closure). The
  observation record is byte-immutable and never carries a disposition; the
  current disposition is the projection of the last event; and a receipt
  binds the exact `disposition_event_id` that supplied each disposition, so
  the verifier reloads that event and requires its fields to match exactly.
  Rewriting any event breaks every subsequent link and is refused on read.
- **Bundles are portable in both containers and replayable alone**: the
  same evidence graph ships as a sealed `directory` or as `--single` — one
  deterministic tar archive with the manifest inside — and `frf bundle
  replay` re-executes a bundle's snapshots from the bundle alone (the sides
  run from a reconstructed invocation root, so recorded argv paths resolve
  to the bundle's own objects; exact replay additionally requires the
  recorded working directory, and an observation that embeds filesystem
  content reproduces only under that environment). Bundle verification is
  read-only and never executes.
- **Claim IR — the full scope algebra is implemented, RELATIVE to a
  committed evidence universe**: admission is `Scope(K) ⊆ Scope(P₁ ∪ … ∪
  Pₙ)` over structured scopes
  (authority/candidate/fixture/family/observable/environment/version/
  temporal); the premise union is a UNION OF SCOPE CELLS, never a
  dimension-set merge (a merged product would invent unsupported evidence
  points — evidence-space inflation); `harness` invalidates a premise run;
  `open`/`unknown` residuals block EXACTLY the claims whose surface
  intersects their scope. The absence of blockers is established over the
  EVIDENCE UNIVERSE U committed at compile time (every residual head with
  its disposition + event, every receipt/run/authority/series/reduction
  present), and the compiled claim CARRIES U (`knowledge_snapshot`, content
  addressed) — so the negative search is portable, a later store mutation is
  a NEW universe rather than a silent rewrite of the old claim, and a bundle
  carrying a claim carries the snapshot's residual heads, events, runs, and
  reductions (the verifier rehashes every object the absence search
  depended on). Claims carry their IR (`scope`, `requires`, `blockers`,
  `excluded_evidence`, `knowledge_snapshot`); prose and `--json` are two
  renderers. A
  multi-premise compiler (union admission over several receipts) is future
  work — the cell-region algebra already defines it without inflation.
- **`fixed` never licenses parity from the run that observed the failure**:
  the positive claim must be compiled from the resolution run's receipt, the
  run that actually observed the passing candidate. This is enforced by the
  claim compiler, not by convention.
- **Every generated evidence object is canonical JSON (RFC 8785); YAML is
  reserved for HUMAN-AUTHORED input** — court manifests and configuration.
  v0.1.32 completed the migration the protocol always implied: captures,
  residuals, disposition events, series, trajectories, reductions,
  challenges, witness statements, knowledge snapshots, claim IRs, and
  authorities are all written with sorted keys, no whitespace, and the
  RFC's exact escaping, and every evidence loader REFUSES a document that
  is not its own canonical serialization (strict I-JSON parsing rejects
  duplicate property names before any typed projection). The independent
  verifier therefore parses evidence with its own strict JSON reader and
  shares not a single parsing library with the reference engine — two
  implementations agree on the same bytes, not on the same parser. Court
  manifests stay YAML because they are human-authored source, not
  evidence.
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
- **Script interpreter identity is the full interpreter CHAIN**: the
  executable the kernel directly invoked (`kernel_interpreter`), the raw
  shebang argument bytes (verbatim — `-S` flags, env assignments — recorded
  as evidence even where v0 does not execute them), the env resolver when
  the kernel interpreter is env(1) (with the `$PATH` digest), and the
  downstream language interpreter. `#!/bin/sh` binds kernel == downstream
  with no resolver; `#!/usr/bin/env -S python3 -O` binds env as the kernel
  + the resolver + python3 as downstream. Binaries carry no interpreter
  binding yet (ELF loader + dynamic dependencies are future work).
  Interpreter hashes are machine-specific: the checked-in tree's recorded
  values are evidence, not re-derivable cross-machine.
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
