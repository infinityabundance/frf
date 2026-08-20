# OpenReceipt — the Forensic Residual Framework receipt protocol

*Version: `frf-receipt-v8` (this document).*

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
`semantic_identity` hashes the question, falsifier, authority artifact
bytes, fixture, envelope, and comparator **semantic** identities — never
implementation hashes. Two independent implementations that implement the
same comparator specifications ask the same question.

The semantic identity is computed over the fixture's **declared** arguments
(the question); the `fixtures[].arguments` block records the **resolved**
argv the side actually received (the execution). A receipt carries both, so
its semantic identity can be rederived from the document alone.

## 3.5 Disposition events — the evidence graph root

A residual's disposition is never copied state: it is supplied by an
immutable, content-addressed **disposition event**, and a receipt binds the
exact event that supplied it (`residuals[].disposition_event_id`). Events
live in the reference engine under `residuals/<id>.events/NNNN.yaml`
(a storage convention; the protocol object is the event itself):

```
DispositionEvent {
    event_id         SHA-256 of FRF/DISPOSITION-EVENT/v1 over the event's
                     own content (residual, parent, disposition, evidence_refs)
    residual_id
    parent_event_id  the previous event for the same residual (the hash link),
                     None for the first event
    disposition      kind + reason (+ resolution_run_id, closure_predicate
                     for fixed)
    evidence_refs    for a fixed event, the resolution run that closed it
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
machine-readable definition. `schema_version` MUST be `frf-receipt-v8`; a
conformant parser refuses any other version.

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

1. **Disposition cross-field rules.** `open` carries no `reason`,
   `resolution_run_id`, `closure_predicate`, or `disposition_event_id`;
   `fixed` carries all four (with `closure_predicate` equal to the fix-court
   predicate and `disposition_event_id` naming the exact event that supplied
   it); every other disposition (`intentional`, `environmental`,
   `oracle_version`, `harness`, `unknown`) carries a `reason` and a
   `disposition_event_id`, and nothing else.
2. **Declared axes** are parseable and unique; every `observables[]` block
   is declared and unique.
3. **Comparator semantics** are a bijection with the observable axes, each
   with exactly one implementation in `provenance`.
4. **Residuals** have unique ids, declared axes, kind/axis consistency
   (`exit`↔exit, `text`↔stderr/stdout), a `grammar_state` that rederives
   from the disposition, v0 `sign` fields, and a `reproducer` equal to the
   receipt's run.
5. **Verdict consistency.** `verdict: residual` iff a residual exists on the
   axis; `verdict: pass` excludes one.
6. **Environment digest rederives** as
   `sha256("os={os}\narch={arch}\nkernel={kernel}")`.
7. **Court semantic identity rederives** from the document (declared
   arguments, authority artifact hash, fixture, envelope, comparators).
8. **Replay target.** `program == "frf"`, `expected_run_identity == run`,
   `argv` is a court-run invocation.
9. **Endoduction tokens** mirror residuals one-to-one and each rederives
   from kind/axis/disposition via the κ table.
10. **Interpreter chains** are internally consistent: an `env` resolver must
    BE the kernel interpreter it resolved through; without a resolver the
    kernel must BE the downstream interpreter.
11. **Resolved argv** corresponds to the declared arguments: every resolved
    argument is either the declared argument or a `{fixture}` substitution.
12. **Claims.** v0 receipts never carry positive claims; the claim compiler
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

## 6. The OpenReceipt bundle — a portable evidence root

A bundle (`frf bundle export`) is a receipt plus the complete object closure
it references, laid out as a self-contained evidence tree with a
canonical-JSON manifest:

```text
bundle.frf/
  manifest.json        frf-bundle-v1: schema_version, receipt_id, run,
                       created_by, and the content-addressed inventory
                       (path, sha256, kind per file)
  receipts/<id>.json
  captures/<run>/      capture.yaml + raw side files, for the receipt's run
                       and — transitively — every resolution run its
                       disposition events reference
  objects/sha256/<H>   content-addressed execution snapshots
  residuals/           residual records + <id>.events/ event chains
  claims/<id>.yaml     the compiled claim, when present
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

## 7. Residual trajectories — the executable repeat axis

A trajectory is an ordered series of observations of one residual
FINGERPRINT over a declared coordinate system, with a deterministic
classification. `frf court run --repeat N` executes the `repeat_index`
axis: the same court is re-executed N times (fresh processes —
nondeterminism is the point), and each observed divergence fingerprint gets
a record under `trajectories/<fingerprint>.yaml` (`frf-trajectory-v1`):

```text
Trajectory {
    subject            the residual fingerprint (FRF/RESIDUAL-FINGERPRINT/v1)
    axis
    coordinate_system  "repeat_index" (v0.1.17; the other axes — candidate
                       revision, authority version, environment, fixture
                       reduction, time — become executable as those protocol
                       objects exist)
    repeat_count
    observations[]     { repetition, run, observed, residual? } — identical
                       repetitions share the content-addressed run
    derivation         { drift, slew }
}
```

The classification is a deterministic table (never a model): given the
observed pattern `o[1..=N]` with `T = {i | o[i]}` non-empty —

```text
|T| == N                     -> drift=persistent, slew=stable
T contiguous, touching an end -> drift=transient,  slew=abrupt
T contiguous, interior        -> drift=transient,  slew=burst
T non-contiguous, both ends   -> drift=recurrent,  slew=recurrent
otherwise                     -> drift=transient,  slew=recurrent
```

A single-run court cannot observe drift or slew, and its receipts honestly
say so (`sign: {norm: single-run, drift: not-observed, slew: not-observed}`
— the paper's restraint, kept). A repeated-run court's captures record
`repeat_index`/`repeat_count` (`frf-capture-v5`), and its receipts derive
the `sign` from the trajectory — the receipt verifier rederives it, and the
bundle closure carries the trajectory. Claim semantics are unchanged: a
divergence observed in ANY repetition is still an observation.

Trajectories are immutable: the record is a snapshot of one repeated
court, keyed by the subject fingerprint, so the same divergence re-observed
by later runs (later candidates, authorities, environments) can extend the
series once those axes exist.
