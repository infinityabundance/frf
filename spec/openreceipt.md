# OpenReceipt — the Forensic Residual Framework receipt protocol

*Version: `frf-receipt-v15` (this document).*

An OpenReceipt binds a court run's evidence: the court question, the runner
and comparator identities that observed it, the exact artifacts that
executed, the environment, the raw projections, the residuals and their
dispositions, the endoduction tokens, and the structured replay data.

OpenReceipt is a **protocol**, not a paper schema: any implementation that
produces the same canonical bytes produces the same receipt identity, so
implementations in Rust, Go, Python, or an air-gapped appliance can be
mutually verified. The reference implementation's receipts live in
`receipts/`; the machine-readable definition and the conformance corpus
live in `spec/` and `conformance/`.

## 0. Storage convention — canonical JSON for all generated evidence

v0.1.32 made the storage convention match the protocol: **every generated
identity-bearing evidence object is canonical JSON (RFC 8785)** — captures,
residuals, disposition events, series snapshots, trajectories, reduction
records, court challenges, witness statements, knowledge snapshots, claim
IRs, authorities, and receipts. YAML is reserved for HUMAN-AUTHORED input
(court manifests, user configuration), which is source, not evidence. Every
evidence loader parses strict I-JSON (duplicate property names refused) and
REFUSES a document that is not its own canonical serialization — one
semantic document has one byte sequence, so two implementations that agree
on the bytes agree on the evidence without sharing a parser. The paths below
are a reference-engine storage convention, not part of the protocol.

## 1. Serialization — canonical JSON (RFC 8785)

The receipt body is a JSON object encoded exactly per RFC 8785 (JCS):

- object keys sorted recursively by **UTF-16 code units** (not UTF-8 bytes,
  not code points) — see RFC 8785 §3.2.3;
- no whitespace between tokens (§3.2.1);
- strings escape only `"`, `\`, U+0000–U+001F (U+0008/0009/000A/000C/000D as
  `\b \t \n \f \r`, the rest as lower-hex `\u00xx`); every other code point,
  U+007F and U+0080 included, is emitted raw as UTF-8 (§3.2.2.2);
- **the value domain is strings, arrays, booleans, and null only** — the
  OpenReceipt schema emits no numbers, and a compliant encoder must refuse a
  number rather than serialize it (RFC 8785 number serialization is
  ECMAScript's and out of scope here).

A conformant encoder MUST terminate with an error on lone surrogates (they
cannot occur when the input strings are valid UTF-8).

## 2. Identity

The receipt identity is the **full SHA-256** of the canonical bytes:

    receipt-{run}-{sha256(canonical bytes)}

The `{run}` component is the content-addressed run identity
(`run-{court}-{sha256}`). No truncated digest is ever an identity.

The run digest is the `FRF/RUN/v2` composition of two separately
addressable identities: the **observation identity** (`FRF/OBSERVATION/v1`
— what was observed: the question, the inputs, the effective environment,
and the observed answer) and the **execution identity** (`FRF/EXECUTION/v1`
— under exactly what machinery/contract it was observed: the execution
profile, the effective capture bounds including any `FRF_EXEC_*`
overrides, the runner executable, the side interpreter chains, and every
comparator/normalizer/adapter/minimizer implementation). The capture
records both identities, and the run id commits the contract: two
executions that coincide on outputs under different profiles, bounds, or
overrides are different bounded observations, while a repeated execution
can legitimately share an observation identity with exact provenance
separately addressable.

## 3. Provenance rules

An OpenReceipt is immutable evidence. It never asks its own host what
environment or executable observed an old court:

- `provenance.runner` — the frf executable (version + binary hash) that ran
  the court, captured at observation time;
- `provenance.comparator_implementations` — which implementation of each
  comparator observed the run;
- `environment` — os, architecture, kernel release, and the digest over
  them, captured at observation time;
- `authority` / `candidate` `interpreter` — the interpreter CHAIN of script
  artifacts (kernel-invoked executable, raw shebang argument bytes, env
  resolver, downstream interpreter).

Semantic identity is separate from implementation provenance: the court's
`semantic_identity` (FRF/COURT/v2) hashes the question, falsifier, authority
artifact bytes, fixture, envelope, the comparator **semantic** identities,
the normalizer **semantic** identities in application order (a normalizer
changes the comparison surface, so its relation and the streams it moves are
part of the question), and the capture-adapter **semantic** identities
axis-keyed (an adapter's extraction scheme defines the observation delivered
to an externally served axis) — never implementation hashes. Two
independent implementations that implement the same comparator, normalizer,
and adapter specifications ask the same question; two courts that differ in
any observation-defining semantics ask different questions.

The semantic identity is computed over the fixture's **declared** arguments
(the question); the `fixtures[].arguments` block records the **resolved**
argv the side actually received (the execution). A receipt carries both, so
its semantic identity can be rederived from the document alone.

## 3.5 Disposition events — the evidence graph root

A residual's disposition is never copied state: it is supplied by an
immutable, content-addressed **disposition event**, and a receipt binds the
exact event that supplied it (`residuals[].disposition_event_id`). Events
live in the reference engine under `residuals/<id>.events/NNNN.json`
(a storage convention; the protocol object is the event itself):

```
DispositionEvent {
    event_id         SHA-256 of FRF/DISPOSITION-EVENT/v1 over the event's
                     own content (residual, parent, disposition, evidence_refs)
    residual_id
    parent_event_id  the previous event for the same residual (the hash link),
                     None for the first event
    disposition      kind + reason, plus the kind's evidence edges:
                     fixed      resolution_run_id + closure_predicate
                     nonreproduced  observation_run_id
                     stabilized trajectory_id + consecutive_passes +
                                 stabilization_bound
    evidence_refs    the kind's evidence edge (the resolution run, the
                     observation run, or the trajectory document)
}
```

The chain is a hash chain: rewriting any event breaks every subsequent
link, and `disposition_event_id` lets a receipt say "this disposition was
supplied by this exact immutable event" — which the verifier proves by
reloading that event and requiring its fields to match exactly. `open` is
not an event: it is the projection of no events, so open entries carry
`disposition_event_id: null`.

## 4. Schema

`spec/openreceipt.schema.json` (JSON Schema draft-07) is the normative
machine-readable definition. `schema_version` MUST be `frf-receipt-v15`; a
conformant parser refuses any other version.

### 4.1 Observable axes and residual kinds — protocol identifiers

Observable axis ids and residual kinds are **open protocol identifiers**, not
closed enums. The grammar is: lowercase ASCII letter first, then lowercase
letters, digits, `.`, `_`, `-`; 1..=64 characters. The reference engine ships
three in-binary comparators (`exit`, `stderr`, `stdout`) whose residual
classifiers are `exit` and `text`; any other axis (`dns.wire`,
`filesystem.tree`, …) is served by an external comparator via the extension
protocol (`spec/comparator.md`), and the comparator's declared
`residual_classifier` names the kind every divergence on the axis is
recorded as. The kind is part of the residual fingerprint, the lineage, and
the residual id, so a new kind is a new residual class, never a silent
reinterpretation of an old one.

Each `comparator_semantics[]` entry carries its full specification
(`relation_id`, `extractor`, `residual_classifier`) next to its
`specification_hash`, so the hash REDERIVES from the entry's own fields — a
receipt cannot claim a specification its own semantics do not hash to.

### 4.2 Externally served observables

An observable served by an external comparator binds the exact instrument
that produced its verdict: `comparator_request` (the content address of the
canonical request the comparator received) and `comparator_result` (the
content address of its result record) are both present, and the observable's
`raw_reference_hash`/`raw_candidate_hash` are the SHA-256s of the canonical
`reference`/`candidate` subtrees of that request. An in-binary observable
binds neither, and its raw hashes rederive from the captured projections.
The invocation/result evidence is preserved under the run, verified on every
read (identities rederive, documents hash to their cids, the response names
its request), carried by the bundle closure, and re-invoked by replay.

## 5. Conformance — two levels

### 5.1 Structural conformance

`conformance/`:

- `valid/` — receipt source documents (some deliberately non-canonical:
  unsorted keys, whitespace) that MUST parse and deserialize;
- `canonical/` — for each valid fixture, the expected canonical bytes;
- `hashes/` — for each valid fixture, the expected SHA-256 of the canonical
  bytes;
- `invalid/` — documents that MUST fail to parse or deserialize.

An external implementation passes structural conformance when, for every
fixture in `valid/`, it parses the document, emits exactly the bytes in
`canonical/`, and hashes to the value in `hashes/`, and for every fixture in
`invalid/` it refuses. The reference implementation runs this corpus in
`tests/conformance.rs`.

### 5.2 Semantic conformance

The schema says what *shapes* are legal; semantic conformance says what
*documents* are. It is a pure document-level algorithm — no execution, no
evidence tree — so any independent implementation can run it. The reference
algorithm is `Receipt::validate_semantics` (`src/verify.rs`); the negative
corpus is `conformance/invalid-semantic/`, one document per violated rule
(structurally valid, semantically refused). The rules:

1. **Disposition cross-field rules.** `open` carries no `reason` or evidence
   edge, and no `disposition_event_id`; `fixed` carries `reason` +
   `resolution_run_id` + the fix-court `closure_predicate` (which now
   includes the CANDIDATE ARTIFACT IDENTITY CHANGED clause — a fix is a
   change in the thing being compared, so a later pass on the same candidate
   is a non-reproduction, not a fix) and `disposition_event_id` naming the
   exact event that supplied it; `nonreproduced` carries `reason` +
   `observation_run_id` (a pass under the SAME candidate); `stabilized`
   carries `reason` + `trajectory_id` + `consecutive_passes` +
   `stabilization_bound` (repeated passes under the SAME candidate, with
   `consecutive_passes >= stabilization_bound >= 2`); every other
   disposition (`intentional`, `environmental`, `oracle_version`, `harness`,
   `unknown`) carries a `reason` and a `disposition_event_id`, and nothing
   else. No kind may borrow another kind's evidence edge: only `fixed` may
   carry `resolution_run_id`/`closure_predicate`, only `nonreproduced` may
   carry `observation_run_id`, only `stabilized` may carry trajectory
   evidence. `nonreproduced` and `stabilized` still block positive claims:
   nondeterminism must never become remediation evidence.
2. **Declared axes** are valid protocol identifiers and unique; every
   `observables[]` block is declared, a valid identifier, and unique.
3. **Comparator semantics** are a bijection with the observable axes, each
   with exactly one implementation in `provenance`, and every
   `specification_hash` REDERIVES from its entry's own
   relation/extractor/residual-classifier fields.
4. **Residuals** have unique ids, valid + declared axes, a `kind` equal to
   the axis's comparator's `residual_classifier`, a `grammar_state` that
   rederives from the disposition, v0 `sign` fields, and a `reproducer`
   equal to the receipt's run.
5. **Observable comparator bindings** are all-or-nothing: an externally
   served observable carries BOTH `comparator_request` and
   `comparator_result` (64-hex content addresses); an in-binary observable
   carries neither.
6. **Verdict consistency.** `verdict: residual` iff a residual exists on the
   axis; `verdict: pass` excludes one.
7. **Environment digest rederives** as the FRF/ENVIRONMENT/v2 canonical-JSON
   formula over the host strata (os, arch, kernel, locale, timezone, umask)
   AND the declared execution environment map (the exact environment the
   sides ran under — a declared variable is content-addressed input).
8. **Court semantic identity rederives** from the document (declared
   arguments, authority artifact hash, fixture, envelope, comparators).
9. **Replay target.** `program == "frf"`, `expected_run_identity == run`,
   `argv` is a court-run invocation.
10. **Endoduction tokens** mirror residuals one-to-one and each rederives
    from kind/axis/disposition via the κ table (built-in rows as in Section
    12; any other axis gets the deterministic generic row: surface
    `{axis}-divergence`, magnitude `observed`, `next_court: none`, blocked
    phrase `{scope} {axis} parity`).
11. **Interpreter chains** are internally consistent: an `env` resolver must
    BE the kernel interpreter it resolved through; without a resolver the
    kernel must BE the downstream interpreter.
12. **Resolved argv** corresponds to the declared arguments: every resolved
    argument is either the declared argument or a `{fixture}` substitution.
13. **Claims.** v0 receipts never carry positive claims; the claim compiler
    writes `claims/` from a verified receipt.

### 5.3 Evidentiary verification (reference engine)

Beyond the document, the reference engine verifies a receipt against its
evidence tree before any semantic use (replay, claim compilation): the id
MUST equal the SHA-256 of the canonical bytes; the referenced run MUST
exist and its recorded fields MUST rederive its run identity; the receipt's
court, artifacts, environment, provenance, comparator semantics,
observables, and residual set MUST match the capture; residual fingerprints
and κ tokens MUST rederive; each disposition MUST be bound to the exact
content-addressed event it names (the event must exist in the residual's
hash chain and its fields must match the receipt exactly — the chain itself
is verified, so a hand-edited or broken event is refused); and `fixed`
closures MUST be backed by a resolution run that reran the same question
and closed the axis. Claim compilation accepts only a `ReceiptVerified` —
parsing data cannot turn it into evidence.

#### Verified-on-read is closed under ALL evidence transforms (0.1.59)

The type discipline is structural, not aspirational. The raw store loaders
(`Store::load_residual`, `load_capture`, `load_receipt`) parse ONLY and
return `Unverified<T>`; the verified loaders (`verify::load_residual_verified`
etc.) — the only producers of the private-field `ResidualVerified` /
`CaptureVerified` / `ReceiptVerified` types — run the identity + derivation
proofs and then unwrap. Every semantic consumer operates on verified types:

- `receipt emit` accepts only a `CaptureVerified` and verified residuals — a
  tampered capture directory cannot mint a receipt;
- `residual dispose` accepts only a `ResidualVerified` — a forged residual
  cannot gain a closure, and a `fixed` disposition's resolution
  comparability is decided on verified captures;
- trajectory derivation consumes verified captures + residuals;
- minimization accepts a `ResidualVerified`;
- challenge verdicts (saw_defect / specificity_clean) recompute from
  verified mutant-run residuals;
- the claim blocker scan verifies every committed residual head and refuses
  on any mismatch against the committed universe;
- replay compares only verified recorded residuals — a residual that no
  longer verifies REFUSES the replay (fail-closed, never silently dropped);
- witness subjects re-derive their content address from verified
  run/residual/receipt objects;
- the bundle closure walks verified residuals for lineages and committed
  heads.

`Unverified::into_inner` is reserved for producers (the court constructs
the records it just wrote) and for the verified loaders themselves; the
marker makes every raw load visible at its call site, so new consumers
default to the verified path and the compiler surfaces any regression.

### 5.4 The independent verifier

OpenReceipt is a protocol only if a SECOND implementation can take the same
evidence and reach the same verdict. `cargo xtask verify` (xtask/) is that
implementation: a deliberately small Rust verifier that does NO execution and
depends on nothing from the reference engine. It implements the RFC 8785
canonicalizer, strict I-JSON parsing (duplicate property names refused),
schema key-set validation (unknown properties refused), the identity
preimages, the structural + semantic conformance algorithms, and the
evidentiary checks of §5.3 — and runs them against the same corpora and the
same bundles as the reference engine:

- **Corpus.** `cargo xtask verify corpus conformance/` must pass every
  fixture the Rust engine passes and refuse every fixture it refuses:
  canonical bytes and pinned hashes (`valid/` + `canonical/` + `hashes/`),
  structural refusals (`invalid/` — including duplicate property names and
  unknown properties), and semantic refusals (`invalid-semantic/`).
- **Bundle.** `cargo xtask verify bundle <bundle.frf>` verifies a bundle
  against itself — manifest hash proof, container/evidence-root checks,
  receipt content-addressing, run-identity rederivation, side-file rehash,
  event-chain/sign/token rederivation (the drift/slew classification
  REDERIVES from the trajectory observations), resolution edges, closure
  completeness — and derives the admissible Claim IR the claim compiler
  would license. Both container forms are accepted: a directory, or a
  single-file archive (verified from a temp extraction, like the engine).

CI runs both engines against both oracles (the Rust suite in
`tests/conformance.rs` and `tests/independent.rs`, the verifier in the demo
job). If the Rust reference engine and the independent verifier agree on the
same bundle and the same corpus, FRF is a protocol, not a Rust file format.

## 6. The OpenReceipt bundle — a portable evidence root

A bundle (`frf bundle export`) is a receipt plus the complete object closure
it references, laid out as a self-contained evidence tree with a
canonical-JSON manifest:

```text
bundle.frf/
  manifest.json        frf-bundle-v3: schema_version, container,
                       receipt_id, run, created_by, and the
                       content-addressed inventory (path, sha256, kind
                       per file)
  receipts/<id>.json
  captures/<run>/      capture.json + raw side files, for the receipt's run
                       and — transitively — every resolution run its
                       disposition events reference, plus
                       comparator/<axis>/{request,response,invocation,
                       result}.json for every externally served axis
  objects/sha256/<H>   content-addressed execution snapshots — the executed
                       artifacts AND the comparator instrumentation, walked
                       via the capture's typed evidence references
  residuals/           residual records + <id>.events/ event chains
  claims/<id>.json     the compiled claim, when present
```

The bundle's defining property:

> If you possess the bundle, you do not need the original source tree or
> the original FRF installation to verify the evidence graph. Execution
> (replay) may still require an appropriate environment; verification does
> not.

`frf bundle verify` proves (1) every inventory file exists and hashes to
its recorded digest (objects must be named by their digest; inventory paths
must not escape the bundle); (2) the receipt verifies against the bundled
evidence alone — identity, derivation, event chains, and resolution edges
all rechecked against the bundle; and (3) the manifest covers the receipt's
complete required closure, recomputed from the bundle. Export only ever
carries VERIFIED evidence: `frf bundle export` refuses a receipt that does
not verify against the source tree first.

### 6.1 Container forms — directory or single-file

The same evidence graph ships in two containers, declared by the manifest
itself (`container`, `frf-bundle-v3`):

| Container    | Form                                                             |
| ------------ | ---------------------------------------------------------------- |
| `directory`  | the tree above, sealed read-only (0444)                          |
| `single-tar` | ONE deterministic tar archive carrying the identical layout, the |
|              | manifest at its root, fixed metadata (epoch mtime, root         |
|              | ownership), entries in path order — two exports of the same     |
|              | receipt are byte-identical                                       |

`frf bundle export --single` writes the archive; `verify` and `replay`
auto-detect the container (a directory is used in place, an archive is
verified from a temp extraction and never mutated). A bundle whose manifest
claims one container while the filesystem provides the other is refused.
The verifier refuses hostile archives the same way the engine does: escaped
paths, links, and unbounded extractions.

### 6.2 Replay from the bundle — re-execution without the tree

`frf bundle replay BUNDLE.frf [--policy exact|semantic]` re-executes the
bundle's snapshots with the captured argv under a checked environment, from
the bundle ALONE. The bundle is first proven against itself (manifest,
closure, receipt), then the receipt is replayed with the reproduction
policy.

The temp store is laid out under the receipt's declared evidence root
(`replay.evidence_root`, the `--root` the observation ran under), and the
sides execute from that reconstructed invocation root: a recorded
root-relative argv path like `frf/objects/sha256/<H>` resolves to the
BUNDLE's own verified object — the sides never silently read the surrounding
tree, and the replay works even when the original tree's objects are gone.
The sealed bundle (directory or archive) is never mutated; re-materialization
re-seals what it executes inside the temp copy.

The exact/semantic distinction is unchanged: exact replay additionally
requires the same execution provenance — profile, bounds, environment
digest, and the recorded working directory — so an exact bundle replay
reproduces from the recorded cwd; replaying from a foreign directory is a
semantic reproduction (the cwd drift is reported), and an observation whose
output embeds the recorded working directory or other filesystem content
reproduces only when that environment is actually present.

## 7. Residual trajectories — the generalized protocol

## 7. Residual trajectories — the generalized protocol

A trajectory is an ordered series of observations of one residual LINEAGE
over a declared coordinate system, with a deterministic classification. The
subject is the lineage identity (`FRF/RESIDUAL-LINEAGE/v1` — kind, axis,
surface, fixture, fixture family, authority NAME), deliberately NOT the
exact observed bytes: the lineage is stable across candidate revisions,
authority versions, environments, and time, so a trajectory records the
MOVEMENT of a divergence (the same lineage at three commits has three
different exact fingerprints but one trajectory).

Five coordinate systems are executable:

- `repeat_index` — `frf court run --repeat N`: the same court re-executed N
  times (fresh processes — nondeterminism is the point);
- `candidate_revision` — `--candidate-revisions P1,P2,...`: one run per
  candidate artifact;
- `authority_version` — `--authority-versions V1,V2,...`: one run per
  admitted authority version;
- `environment` — `--environment-point LABEL`: this run is one point of the
  environment experiment at the declared coordinate; the series accumulates
  as more machines declare more coordinates;
- `time` — `--time-point LABEL`: the same, over time.

A series court writes an ExecutionSeries record (`series/<id>.json`,
`frf-series-v3`), content-addressed over the experiment (experiment key,
parent snapshot, court, coordinate system, ordered points) — every append is
a NEW immutable, PARENT-LINKED snapshot, so the growth of a series is itself
evidence, identical evidence shares the content-addressed run while every
observation COORDINATE is still a point, and a branched experiment (two
heads) refuses an implicit append (`--series-parent` chooses the branch). A
run NEVER knows its experiments: the series references the runs.
Trajectories (`frf-trajectory-v4`, under
`trajectories/<lineage>.<coordinate-system>.<series>.json`) are DERIVED from
a series snapshot and reference it:

```text
Trajectory {
    subject            the residual lineage (FRF/RESIDUAL-LINEAGE/v1)
    axis
    coordinate_system  repeat_index | candidate_revision | authority_version |
                       environment | time
    series             the ExecutionSeries snapshot this is derived from
    observations[]     { point_index, coordinate, run, observed, residual?,
                       fingerprint?, magnitude? } — identical evidence shares
                       the run; an observed point names the exact fingerprint
                       and (when the axis declares a magnitude measure) the
                       divergence DEGREE at that point
    derivation         { drift, slew, localization, bands, trend,
                       magnitude_kind }
}
```

The classification is a deterministic table (never a model): given the
observed pattern `o[1..=N]` with `T = {i | o[i]}` non-empty —

```text
|T| == N                     -> persistent,        stable,   localization=none,   bands=1
T contiguous, start          -> boundary-localized, abrupt,   localization=start (cessation)
T contiguous, end            -> boundary-localized, abrupt,   localization=end   (onset)
T contiguous, interior       -> transient,         burst,    localization=interior
T non-contiguous, 2+ bands on a version/revision axis
                             -> version-stratified, recurrent, localization by the ends touched
T non-contiguous, both ends  -> recurrent,         recurrent, localization=both
otherwise                    -> transient,         recurrent, localization by the ends touched
```

The v4 vocabulary makes the paper's extended terms first-class: `drift` is
`boundary-localized` for a single contiguous band touching exactly one bound
(cessation/onset) and `version-stratified` for 2+ bands along an ordered
version or revision ladder; `localization` (start/end/both/interior) and
`bands` (2+) carry the detail; and `gradual` is the slew when the divergence's
DEGREE moves monotonically across the axis.

`gradual` needs a magnitude dimension, and v4 provides it: each axis's
comparator declares a deterministic distance measure (`exit-code-distance`,
`line-edit-distance`, `value-edit-distance` — computed on the compared
projections, bounded and documented; the filesystem-tree, byte-wire, and
all external surfaces declare `none` because their projections are an
identity, not a degree). Each observation carries the measure's value as a
string, and the derivation carries the `trend` of those values in coordinate
order — `flat` / `increasing` / `decreasing` / `non-monotonic`, or `unknown`
when no measure exists or fewer than two observed points cannot establish a
trend. `gradual` is claimed EXACTLY when the trend is monotonic
(`increasing` or `decreasing`): a ramp, not a step. An axis without a
measure never claims gradual (fail-closed — presence is binary, degree is
the measure).

A single-run court cannot observe drift or slew, and its receipts honestly
carry NO trajectory evidence (`sign: {trajectory_evidence: []}` — the
paper's restraint, kept). A receipt entry whose run belongs to a series
derives ONE trajectory-evidence entry per coordinate system the run
participates in, and each entry PINs the exact series snapshot its drift/
slew were derived from (`sign.trajectory_evidence`, OpenReceipt v12): the
verifier replays each pinned series (it must exist, contain the run, and its
trajectory must yield the recorded drift/slew), so later experiments that
reference the same content-addressed run can never change what an emitted
receipt means. A residual does not have one universal drift — it has a
trajectory with respect to a coordinate system. Claim semantics are
unchanged: a divergence observed at ANY point is still an observation.

Trajectories are derived projections (regenerable from the immutable runs);
the runs and the series snapshots are the immutable evidence.
