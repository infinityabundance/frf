# Versioning, supersession, and old-evidence compatibility

FRF's protocol objects are content-addressed and IMMUTABLE: a record's
identity rederives from its own fields, so an old record never changes
meaning when the protocol evolves. What evolves is the SCHEMA — the shape a
current implementation parses and the vocabulary it accepts. This document
is the versioning policy (the 0.2 protocol freeze).

## 1. Schema versions

Every protocol object carries `schema_version` (e.g. `frf-receipt-v19`,
`frf-reduction-v4`, `frf-stream-publication-v1`). The registry
(`protocol/registry.json`) lists every schema with a status:

- `active` — the CURRENT shape the reference engine writes and every
  verifier must accept;
- `superseded` — a previous shape, replaced by a newer active schema. The
  registry entry remains: superseded ids are documented history, and a
  superseded id must never reappear as active;
- `reserved-invalid` — a deliberately RESERVED id that is invalid: it
  exists so nothing can collide with it, and it can never become active.

Versioning rules:

- An additive, backward-compatible field (optional, default-absent, no
  identity-preimage change for records written before it) does NOT bump the
  schema version: old records keep parsing and rederiving identically
  (e.g. `ReductionMinimality.proposal_minimality_claimed`,
  `CaptureManifest.publication_surface`).
- A change that alters the identity preimage, the field set a current
  parser requires, or the closed vocabulary of a field DOES bump the
  version — old records of the previous shape remain verifiable as
  immutable evidence whenever the parser keeps accepting them, and the
  registry records the supersession.
- The identity preimage domain tag (`FRF/…/vN`) is part of the identity
  function, not the schema: a schema bump may reuse the same preimage tag
  when the identity function itself is unchanged.

## 2. Supersession rules

- A schema is superseded ONLY by a newer schema of the same object family
  (receipt → receipt, series → series), and the registry states it.
- A superseded schema's records remain what they were: content-addressed
  evidence does not stop verifying because a newer shape exists. The
  conformance corpus and the checked-in evidence trees are the executable
  form of this rule — every committed document must parse, canonicalize,
  and rederive with the CURRENT implementation, whatever schema version it
  carries (the corpus pins both the current receipts and the
  pre-generalization shapes such as the one-minimal reduction record).
- When a record's shape makes it unparseable by a newer implementation
  (removed field with no default, closed vocabulary that no longer admits
  it), the record is REFUSED explicitly — never silently reinterpreted —
  and the refusal names the schema version.

## 3. Old-evidence compatibility tests

The executable guarantees:

- `cargo test --test conformance` — the corpus pins current canonical
  bytes + digests for every family, and refuses structural/semantic
  violations;
- `cargo test --test verify_tree` — the checked-in evidence tree
  rederives with the current implementation (including records whose
  shapes predate later generalizations);
- `cargo test --test consistency` — the closed enumerations (policy names,
  execution profiles, capability vocabulary, publication policies,
  minimality kinds) equal the documented vocabulary exactly, and the
  registry's active/superseded statuses are coherent;
- `cargo test --test protocol_registry` — every schema id the code uses is
  registered, and every registry id is either active or superseded.

## 4. Freeze cadence

The 0.2 draft freezes the current active schema set as the interop target:
new protocol surface lands only with (a) a registry entry, (b) conformance
pins, (c) a spec section, and (d) a consistency-test entry — the four
gates a schema change must pass. Rapid uncoordinated schema evolution is
itself a semantic hazard, which is why the four gates are mandatory.
