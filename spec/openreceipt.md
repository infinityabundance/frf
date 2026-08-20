# OpenReceipt — the Forensic Residual Framework receipt protocol

*Version: `frf-receipt-v7` (this document).*

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

## 4. Schema

`spec/openreceipt.schema.json` (JSON Schema draft-07) is the normative
machine-readable definition. `schema_version` MUST be `frf-receipt-v7`; a
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
   `resolution_run_id`, or `closure_predicate`; `fixed` carries all three,
   with `closure_predicate` equal to the fix-court predicate; every other
   disposition (`intentional`, `environmental`, `oracle_version`, `harness`,
   `unknown`) carries a `reason` and nothing else.
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
and κ tokens MUST rederive; dispositions MUST be evidenced by the
append-only event history; and `fixed` closures MUST be backed by a
resolution run that reran the same question and closed the axis. Claim
compilation accepts only a `ReceiptVerified` — parsing data cannot turn it
into evidence.
