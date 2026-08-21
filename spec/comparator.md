# The comparator extension protocol

*Version: `frf-comparator-request-v3` / `frf-comparator-response-v2`
(`frf-comparator-invocation-v1` / `frf-comparator-result-v1` for the
preserved invocation evidence).*

An observable axis is served by a comparator RELATION. The reference
implementation ships six in-binary comparators (`exit`, `stderr`, `stdout`,
`filesystem.tree`, `bytes.wire`, `structured.state` — see
`src/comparators.rs`), but a comparator is a *protocol participant*, not
Rust code: any program that speaks this protocol can serve an axis, so a
Python packet comparator, a Go filesystem comparator, or a domain tool can
emit the same FRF residual structure without changing the core.

**Observable axes are protocol identifiers, not a closed enum.** Any valid
lowercase identifier (`dns.wire`, `filesystem.tree`, `tzif.bytes`,
`sql.schema`, …) may be declared in the envelope's `observables` and served
by an external comparator; the evidence core runs observables without
knowing what stdout, packets, or filesystem trees are.

The two identities are always separate (the FRF rule):

- **Semantic identity** — what the relation *is*: a canonical specification
  document `{id, relation, extractor, residual_classifier,
  relation_version}` whose SHA-256 (`FRF/COMPARATOR-SPEC/v2`) is the
  comparator's `specification_hash`. The relation's VERSION is part of the
  specification document itself — the one rule: a relation's version is
  part of its semantic identity, in every protocol, so two relations with
  the same fields under different versions are two relations. This hash
  enters the court's semantic identity. A program that declares the same
  specification asks the same question, whatever language it is written
  in. The `residual_classifier` names the KIND every divergence on the
  axis is recorded as (`exit` for the exit axis, `text` for
  stderr/stdout, an axis-specific kind like `wire` for a domain
  comparator); it is part of the question.
- **Implementation identity** — what *implemented* the relation: for an
  external comparator, the SHA-256 of its program bytes (snapshotted,
  sealed, re-hashed on use, exactly like the artifacts it helps compare)
  plus its full ARTIFACT identity (snapshot path + interpreter chain); for
  an in-binary comparator, the frf executable's hash. Both are recorded in
  the capture's `provenance.comparator_implementations`, with `runner_hash`
  naming the harness that orchestrated the comparison.

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
    residual_classifier: text
    relation_version: "v2"
    program: golden/comparators/stderr-first-line.py
```

Rules:

- `axis` MUST be declared in the envelope's `observables`; a comparator for
  an undeclared axis refuses the court. Conversely, every declared
  observable MUST be served — by a declaration or by the in-binary
  registry — or the court refuses (an observable with no comparator cannot
  be compared).
- The declaration's `relation`/`extractor`/`residual_classifier`/
  `relation_version` define the SEMANTIC identity via the same formula as
  the in-binary registry — a declaration matching a built-in row asks the
  same question, a different extractor, classifier, or version is a
  different question.
- The comparator program is read and hashed BEFORE any execution, executed
  through a content-addressed snapshot, and the snapshot is re-hashed on
  every use: the bytes that ran are the bytes that were hashed.

## 2. The request (court → comparator, stdin, canonical JSON)

```json
{
  "schema_version": "frf-comparator-request-v3",
  "comparator": {
    "id": "stderr",
    "relation_id": "eq",
    "extractor": "stderr-first-line",
    "residual_classifier": "text",
    "relation_version": "v2",
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

v3 adds an optional `context.produced` block (present only when the court
declares `produce` — see `spec/produced-artifacts.md`): each side's
produced-file manifest (paths + content hashes), so a comparator can compare
what the sides BUILT, not only what they printed. v2 requests (without the
block) remain the same bytes.

The raw side streams are delivered base64 so the protocol is byte-exact. The
comparator MUST verify `comparator.specification_hash` against the spec it
implements before comparing — the request names the question, and a
mismatch is a harness error.

## 3. The response (comparator → court, stdout, canonical JSON)

```json
{
  "schema_version": "frf-comparator-response-v2",
  "request_id": "<64 hex>",
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

`request_id` is MANDATORY: the SHA-256 of the exact canonical request bytes
the comparator received (the comparator hashes its own stdin). A response
that does not name the request it answers is refused — the court will not
accept evidence "from whatever subprocess happened to be launched".

`residuals[]` carries the raw projections the court preserves verbatim; the
residual KIND is the axis's declared `residual_classifier`, and the SURFACE
+ raw values follow the declared extractor — a compliant implementation
MUST honor its extractor, because the residual fingerprints (and therefore
trajectories) follow it.

## 4. Interpretation — fail closed

A response is never silently defaulted:

| response state | court action |
|---|---|
| non-zero exit, timeout, unparseable JSON | refuse the run (a malfunctioning instrument records nothing) |
| `request_id` != the request the court sent | refuse (the response must cryptographically name its request) |
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

## 5. The invocation is evidence

An externally served axis's comparison is itself preserved under the run,
as canonical JSON:

```
captures/<run>/comparator/<axis>/request.json     the exact request bytes
captures/<run>/comparator/<axis>/response.json    the exact response bytes
captures/<run>/comparator/<axis>/invocation.json  the invocation record
captures/<run>/comparator/<axis>/result.json      the result record
```

- `invocation.json` — `ComparatorInvocation`: content-addressed
  (`FRF/COMPARATOR-INVOCATION/v1`), carrying `request_cid` (SHA-256 of the
  exact request bytes), `comparator_semantic_cid` (the specification hash),
  the comparator's `comparator_implementation_artifact` (snapshot path +
  sha256 + interpreter chain), and the `execution_provenance` (the runner).
- `result.json` — `ComparatorResult`: content-addressed
  (`FRF/COMPARATOR-RESULT/v1`), carrying `request_cid`, `response_cid`
  (SHA-256 of the exact response bytes), the interpreted `outcome`
  (`equivalent` | `divergent`), and the residual observation ids it
  produced.

Both are verified on every read: identities rederive from the records' own
fields, the preserved documents hash to their cids, the response names its
request, and the result answers its invocation's exact request. The bundle
closure carries the invocation evidence and the instrument bytes (via the
capture's typed `evidence_refs`), so a portable bundle never omits the
instrumentation that produced its observation.

## 6. Replay re-invokes the comparator

Replay is a re-observation with the SAME instrument. For each externally
served axis it:

1. re-executes the captured sides;
2. rebuilds the request from the reproduced sides — the rebuilt request
   must rederive to the recorded `request_cid` (the sides reproduced
   byte-for-byte, so this is a real check);
3. re-invokes the exact snapshotted comparator implementation;
4. requires the response to name its request and the outcome to match the
   recorded result, and the fresh residual fingerprints to equal the
   recorded ones as sets (no new residuals, no missing residuals).

Replay writes nothing. A comparator whose outcome drifts — or whose
instrument bytes were lost — is a failed replay, not a silent re-derivation
with the built-in logic.
