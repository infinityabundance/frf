# OpenReceipt — the Forensic Residual Framework receipt protocol

*Version: `frf-receipt-v6` (this document).*

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

## 4. Schema

`spec/openreceipt.schema.json` (JSON Schema draft-07) is the normative
machine-readable definition. `schema_version` MUST be `frf-receipt-v6`; a
conformant parser refuses any other version.

## 5. Conformance corpus

`conformance/`:

- `valid/` — receipt source documents (some deliberately non-canonical:
  unsorted keys, whitespace) that MUST parse and deserialize;
- `canonical/` — for each valid fixture, the expected canonical bytes;
- `hashes/` — for each valid fixture, the expected SHA-256 of the canonical
  bytes;
- `invalid/` — documents that MUST fail to parse or deserialize.

An external implementation passes the corpus when, for every fixture in
`valid/`, it parses the document, emits exactly the bytes in `canonical/`,
and hashes to the value in `hashes/`, and for every fixture in `invalid/`
it refuses. The reference implementation runs this corpus in
`tests/conformance.rs`.
