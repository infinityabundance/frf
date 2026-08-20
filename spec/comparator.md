# The comparator extension protocol

*Version: `frf-comparator-request-v1` / `frf-comparator-response-v1`.*

An observable axis is served by a comparator RELATION. The reference
implementation ships three in-binary comparators (`exit`, `stderr`,
`stdout` — see `src/comparators.rs`), but a comparator is a *protocol
participant*, not Rust code: any program that speaks this protocol can serve
an axis, so a Python packet comparator, a Go filesystem comparator, or a
domain tool can emit the same FRF residual structure without changing the
core.

The two identities are always separate (the FRF rule):

- **Semantic identity** — what the relation *is*: a canonical specification
  document `{id, relation, extractor}` whose SHA-256 (`FRF/COMPARATOR-SPEC/v1`)
  is the comparator's `specification_hash`. This hash enters the court's
  semantic identity. A program that declares the same specification asks the
  same question, whatever language it is written in.
- **Implementation identity** — what *implemented* the relation: for an
  external comparator, the SHA-256 of its program bytes (snapshotted,
  sealed, re-hashed on use, exactly like the artifacts it helps compare);
  for an in-binary comparator, the frf executable's hash. Both are recorded
  in the capture's `provenance.comparator_implementations`, with
  `runner_hash` naming the harness that orchestrated the comparison.

## 1. Declaring a comparator

A court manifest may add a `comparators:` section (see
`frf/courts/cli-malformed-input/manifest-candidate-fixed.yaml` for the plain
shape; the comparator tests in `tests/comparator.rs` build comparator
manifests):

```yaml
comparators:
  - axis: stderr
    relation: eq
    extractor: stderr-first-line
    relation_version: "v1"
    program: golden/comparators/stderr-first-line.py
```

Rules:

- `axis` MUST be declared in the envelope's `observables`; a comparator for
  an undeclared axis refuses the court.
- The declaration's `relation`/`extractor`/`relation_version` define the
  SEMANTIC identity via the same formula as the in-binary registry — a
  declaration matching a built-in row asks the same question, a different
  extractor is a different question.
- The comparator program is read and hashed BEFORE any execution, executed
  through a content-addressed snapshot, and the snapshot is re-hashed on
  every use: the bytes that ran are the bytes that were hashed.

## 2. The request (court → comparator, stdin, canonical JSON)

```json
{
  "schema_version": "frf-comparator-request-v1",
  "comparator": {
    "id": "stderr",
    "relation_id": "eq",
    "relation_version": "v1",
    "specification_hash": "<64 hex>"
  },
  "axis": "stderr",
  "reference": { "exit": "2", "stdout_base64": "...", "stderr_base64": "..." },
  "candidate": { "exit": "1", "stdout_base64": "...", "stderr_base64": "..." },
  "context": {
    "fixture_sha256": "<64 hex>",
    "arguments": ["--strict", "frf/objects/sha256/..."],
    "environment_digest": "<64 hex>"
  }
}
```

The raw side streams are delivered base64 so the protocol is byte-exact. The
comparator MUST verify `comparator.specification_hash` against the spec it
implements before comparing — the request names the question, and a
mismatch is a harness error.

## 3. The response (comparator → court, stdout, canonical JSON)

```json
{
  "schema_version": "frf-comparator-response-v1",
  "equivalent": false,
  "residuals": [
    {
      "surface": "first-diagnostic-line",
      "raw_reference": "tool: ...:4: unknown directive 'servre'",
      "raw_candidate": "error: unknown directive servre at line 4"
    }
  ],
  "indeterminate": false,
  "failure": null
}
```

`residuals[]` carries the raw projections the court preserves verbatim; the
residual KIND is derived by the court from the axis (exit ↔ `exit`,
stderr/stdout ↔ `text`), and the SURFACE + raw values follow the declared
extractor — a compliant implementation MUST honor its extractor, because the
residual fingerprints (and therefore trajectories) follow it.

## 4. Interpretation — fail closed

A response is never silently defaulted:

| response state | court action |
|---|---|
| non-zero exit, timeout, unparseable JSON | refuse the run (a malfunctioning instrument records nothing) |
| `indeterminate: true` | refuse the run (inconclusive evidence must not be recorded as conclusive) |
| `failure: "msg"` | refuse the run |
| `equivalent: true` with residuals | refuse (the response contradicts itself) |
| `equivalent: false` with no residuals | refuse (a divergence must name itself) |
| a residual whose raw values are equal | refuse (a divergence must diverge) |
| `equivalent: true`, no residuals | no residual on the axis |
| `equivalent: false`, residuals | preserve the residuals verbatim |

The court never records evidence from a comparator that failed, and never
records a conclusive verdict from one that was indeterminate. That is the
extension protocol's half of the harness discipline.

## 5. Replay

Replay re-executes the captured SIDES and rederives fingerprints; it does
not re-invoke comparators. The comparator's implementation hash is recorded
in the capture's provenance, and its snapshotted bytes live under
`objects/` — the instrument is evidence of how the observation was made,
even though replay does not need it.
