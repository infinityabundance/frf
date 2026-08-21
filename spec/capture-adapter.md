# The capture-adapter extension protocol

*Version: `frf-capture-request-v1` / `frf-capture-response-v1`
(`frf-capture-invocation-v1` / `frf-capture-result-v1` for the preserved
invocation evidence).*

A capture adapter captures the OBSERVATION for one externally served
observable axis: one side's raw outcome in, the ADAPTED observation out. It
is how the core observes surfaces it has no built-in capture for —
`dns.wire`, `sql.schema`, `terminal.frame`, `packet.sequence` — without
learning what they are. The adapted observation is what the axis's external
comparator receives; the raw outcome survives as the request evidence.

The two identities are always separate:

- **Semantic identity** — what the capture *is*: a canonical specification
  document `{id (the axis), relation, relation_version}` whose SHA-256
  (`FRF/CAPTURE-ADAPTER-SPEC/v2`) is the adapter's `specification_hash`.
  The adapter's extraction scheme is part of the court's QUESTION: it enters
  the court semantic identity (FRF/COURT/v2), so two courts that differ
  only in how an axis was captured ask different questions.
- **Implementation identity** — what *captured* it: the SHA-256 of the
  program bytes (sealed BEFORE it runs) plus its ARTIFACT identity,
  recorded in the capture's `provenance.adapter_implementations`.

## 1. Declaring an adapter

```yaml
court:
  ...
  admissibility_envelope:
    observables: [dns.wire]
    ...
comparators:
  - axis: dns.wire
    relation: eq
    extractor: dns-wire-payload
    residual_classifier: wire
    relation_version: "v1"
    program: golden/comparators/wire-compare.py
capture_adapters:
  - axis: dns.wire
    relation: dns-wire-dump
    relation_version: "v1"
    program: golden/adapters/wire-dump.py
```

Rules (fail closed):

- `axis` MUST be declared in the envelope's observables;
- an adapted axis MUST be served by an EXTERNAL comparator — the adapter
  defines an observation format only its comparator knows, so a built-in
  axis (exit/stderr/stdout) can never be adapted;
- at most one adapter per axis; adapter ids (axes) are unique.

## 2. The request

```json
{
  "schema_version": "frf-capture-request-v1",
  "adapter": {
    "id": "dns.wire",
    "relation_id": "dns-wire-dump",
    "relation_version": "v1",
    "specification_hash": "<64-hex>"
  },
  "side": "reference",
  "outcome": {
    "exit": "0",
    "stdout_base64": "<the side's raw stdout, base64>",
    "stderr_base64": "<the side's raw stderr, base64>"
  },
  "context": {
    "fixture_sha256": "<64-hex>",
    "arguments": ["..."],
    "environment_digest": "<64-hex>"
  }
}
```

The adapter receives the TRULY RAW outcome (before any normalizer) — the
same bytes that survive in the normalizer's first request, so the evidence
cross-checks.

## 3. The response

```json
{
  "schema_version": "frf-capture-response-v1",
  "request_id": "<SHA-256 of the exact request bytes received>",
  "observation": {
    "format": "dns-wire",
    "payload_base64": "<the ADAPTED observation payload, base64>",
    "content_sha256": "<SHA-256 of the payload bytes>"
  },
  "indeterminate": false,
  "failure": null
}
```

`observation` may be `null` when the adapter declines — but a declined
capture is a refusal (an adapted axis with no observation cannot be
compared).

## 4. Fail-closed interpretation

- wrong schema version, unparseable JSON, non-zero exit, timeout → refusal;
- `request_id` MUST equal the request's content address;
- `indeterminate` / `failure` / a missing observation → refusal;
- the declared `content_sha256` MUST be the SHA-256 of the payload bytes
  (verified by the loader, and by replay's re-invocation).

## 5. Evidence and verification

The court preserves four files per side under
`captures/<run>/capture-adapter/<axis>/<side>/` (request, response,
content-addressed invocation + result). The side capture records the
ADAPTED observation (`SideCapture.adapted`), which enters the run identity.
Verification rehashes without executing: the adapted payload decodes to its
recorded content hash and matches the adapter's recorded result; the
adapter's request carried the truly raw outcome (the side files when no
normalizers applied, else the first normalizer's request streams).

Replay re-invokes the exact snapshotted adapter (exact replay: the rebuilt
request must rederive to the recorded `request_cid`; semantic: the adapted
payload must reproduce) and the axis's external comparator receives the
reproduced adapted payloads.
