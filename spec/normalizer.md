# The normalizer extension protocol

*Version: `frf-normalizer-request-v1` / `frf-normalizer-response-v1`
(`frf-normalizer-invocation-v1` / `frf-normalizer-result-v1` for the
preserved invocation evidence).*

A normalizer maps one side's RAW streams to the streams the court COMPARES.
A normalizer is a *protocol participant*, not Rust code: any program that
speaks this protocol can build the comparison surface, so a Python
whitespace trimmer, a Go log-line joiner, or a domain tool can participate
without changing the core.

The FRF rule is absolute: **an observation is never rewritten, the
comparison surface is.** The raw streams survive as each invocation's
request evidence — an immutable, content-addressed record of exactly what
the normalizer received — and the capture's compared hashes derive from the
recorded normalizer chain end to end (verification rehashes the chain
without executing anything).

The two identities are always separate:

- **Semantic identity** — what the mapping *is*: a canonical specification
  document `{id, relation, applies_to, relation_version}` whose SHA-256
  (`FRF/NORMALIZER-SPEC/v2`) is the normalizer's `specification_hash`.
  `applies_to` is `stdout`, `stderr`, or `both` — the streams the normalizer
  is DECLARED to move. The relation's version is part of the specification
  document itself, as in every protocol.
- **Implementation identity** — what *implemented* the mapping: the SHA-256
  of its program bytes (read + hashed + sealed BEFORE anything executes,
  re-hashed on every use, exactly like the artifacts) plus its full ARTIFACT
  identity (snapshot path + interpreter chain), recorded in the capture's
  `provenance.normalizer_implementations` in application order.

## 1. Declaring and applying a normalizer

A court manifest declares normalizers and the envelope names exactly which
are APPLIED, in order:

```yaml
court:
  ...
  admissibility_envelope:
    ...
    observables: [stderr]
    normalizers: [trim-trailing-ws]
    replay_scope: single-run
normalizers:
  - id: trim-trailing-ws
    relation: trim-trailing-whitespace
    applies_to: stderr
    relation_version: "v1"
    program: golden/normalizers/trim-trailing-ws.py
```

Rules (fail closed both ways):

- The envelope's `normalizers` list MUST contain only declared ids; an
  applied normalizer that is not declared would run unverifiable code and
  refuses the court.
- Every declared normalizer MUST be applied by the envelope; a declaration
  that is not applied would falsify the evidence and refuses the court.
- Ids are unique and valid protocol identifiers; `applies_to` is closed to
  `stdout | stderr | both`.

Normalizers compose: they apply to BOTH sides, in envelope order, each
normalizer's output feeding the next. The COMPARED streams — the final
normalized streams — are what the capture records, what the residuals
derive from, and what the external comparator requests carry. The truly raw
streams live only in the first normalizer's request document.

## 2. The request

The court writes ONE canonical JSON document to the normalizer's stdin for
each side:

```json
{
  "schema_version": "frf-normalizer-request-v1",
  "normalizer": {
    "id": "trim-trailing-ws",
    "relation_id": "trim-trailing-whitespace",
    "applies_to": "stderr",
    "relation_version": "v1",
    "specification_hash": "<64-hex>"
  },
  "side": "reference",
  "stdout_base64": "<the side's raw stdout, base64>",
  "stderr_base64": "<the side's raw stderr, base64>",
  "context": {
    "fixture_sha256": "<64-hex>",
    "arguments": ["--strict", "<fixture path>"],
    "environment_digest": "<64-hex>"
  }
}
```

The request's identity (`request_cid`) is the SHA-256 of its exact canonical
bytes (RFC 8785) — the same bytes the normalizer receives.

## 3. The response

The normalizer writes ONE canonical JSON document to stdout:

```json
{
  "schema_version": "frf-normalizer-response-v1",
  "request_id": "<SHA-256 of the exact request bytes received>",
  "stdout_base64": "<the NORMALIZED stdout, base64>",
  "stderr_base64": "<the NORMALIZED stderr, base64>",
  "indeterminate": false,
  "failure": null
}
```

## 4. Fail-closed interpretation

- wrong schema version, unparseable JSON, non-zero exit, or timeout →
  refusal (the run never happens);
- `request_id` MUST equal the `request_cid` of the exact request the court
  sent — a response must cryptographically name the request it answers;
- `indeterminate: true` or a `failure` string → refusal;
- a normalizer declared `applies_to: stdout` that changes stderr (or vice
  versa) → refusal: it moved what it was not declared to move. Only
  `applies_to: both` may change both streams.

## 5. Evidence

For every side, the court preserves four files under
`captures/<run>/normalizer/<id>/<side>/`:

- `request.json` — the canonical request (the RAW streams, base64);
- `response.json` — the canonical response (the NORMALIZED streams);
- `invocation.json` — the content-addressed `NormalizerInvocation`
  (`FRF/NORMALIZER-INVOCATION/v1` over its own fields): which normalizer,
  which request, which snapshotted implementation artifact, which runner;
- `result.json` — the content-addressed `NormalizerResult`
  (`FRF/NORMALIZER-RESULT/v1`): the request/response cids and the hashes of
  the normalized streams.

Verification rehashes the chain end to end without executing: the first
request's carried streams are the raw record; each result's normalized
hashes MUST be the next request's carried streams; the LAST result's hashes
MUST be the capture's compared hashes. A broken link or a hand-edited
document refuses, never silently consumes.

### 5.1 The raw-vs-compared model is semantic, not a filename convention

A capture's `{side}.stdout` / `{side}.stderr` files are the COMPARED
observation, and an external tool MUST NOT read them as raw process output
when normalizers applied:

```text
process output (raw bytes)
        |
        v  normalizer request evidence — the RAW stream survives here,
        |  byte-for-byte, content-addressed (request.json + invocation +
        |  result: the normalizer chain is a verified hash chain)
        v
compared observation — captures/{run}/{side}.stdout / .stderr, what the
        comparators mean, and what `capture.json` hashes
```

- the RAW stream is preserved as the normalizer request evidence (the first
  request carries the raw record; every link is verified on read);
- the COMPARED stream is what the capture's `{side}.stdout` / `{side}.stderr`
  files and the `capture.json` hashes bind, and what replay/semantic
  reproduction must reproduce;
- verification consistency is preserved by construction (the last result's
  hashes MUST be the capture's compared hashes), so nothing is lost — but
  the two are different objects and must be read as such.

## 6. Replay and minimization

Replay re-invokes the EXACT snapshotted implementations in application
order. Under exact replay each rebuilt request must rederive to the recorded
`request_cid` — the raw streams reproduced byte-for-byte. Semantic replay
admits raw-stream drift the normalizer absorbs and requires the NORMALIZED
surface to reproduce (the side-capture equality). Minimization re-applies
the normalizers on every executable attempt, so preservation is decided on
the same surface the court compared.
