# The minimizer extension protocol

*Version: `frf-minimizer-request-v1` / `frf-minimizer-response-v1`
(`frf-minimizer-invocation-v1` / `frf-minimizer-result-v1` for the preserved
invocation evidence).*

`frf court minimize` routes a residual to the reducer that may serve it:
the residual's κ token's `next_court` (e.g. `cli-exit-minimize`). Without a
declaration the reference engine's built-in ddmin reducer runs. When the
residual's capture binds a minimizer for that route, the minimizer is a
*protocol participant*, not Rust code: it PROPOSES a reduced fixture, and
the core COURT-VERIFIES the proposal with the one comparison operation.

The decisive rule: **the minimizer has no oracle.** It cannot execute; it
proposes. The core re-runs the court on the proposal — the exact authority
and candidate artifacts, the same comparator semantic + implementation, the
same environment, the normalizers re-applied — and the residual's lineage
must survive. A proposal that does not survive is RECORDED-BUT-NOT-ACCEPTED
(the refusal is itself evidence, content-addressed under the residual); a
proposal that cannot be evaluated aborts as a harness failure. No
unverified reduction is ever accepted.

The two identities are always separate:

- **Semantic identity** — what the reduction strategy *is*: a canonical
  specification document `{id (the κ route), relation, relation_version}`
  whose SHA-256 (`FRF/MINIMIZER-SPEC/v2`) is the minimizer's
  `specification_hash`. The relation's version is part of the specification
  document itself, as in every protocol.
- **Implementation identity** — what *proposed* it: the SHA-256 of the
  program bytes, sealed at OBSERVATION time (the court binds the reducer for
  each declared route), plus its ARTIFACT identity, recorded in the
  capture's `provenance.minimizer_implementations`.

## 1. Declaring a minimizer

```yaml
court:
  ...
  admissibility_envelope:
    ...
    observables: [exit, stderr]
minimizers:
  - id: cli-exit-minimize
    relation: drop-comment-blank-lines
    relation_version: "v1"
    program: golden/minimizers/ddmin-lines.py
```

The `id` is the κ route it serves (`cli-exit-minimize`,
`cli-diagnostic-minimize`, `cli-stdout-minimize`, or a future domain route).
Ids are unique valid identifiers. At observation time the court reads +
hashes + seals each declared minimizer BEFORE anything could execute it, so
`court minimize` works without the original manifest and the bundle closure
carries the exact reducer.

## 2. The request

```json
{
  "schema_version": "frf-minimizer-request-v1",
  "minimizer": {
    "id": "cli-exit-minimize",
    "relation_id": "drop-comment-blank-lines",
    "relation_version": "v1",
    "specification_hash": "<64-hex>"
  },
  "residual": {
    "id": "cli-exit-0003",
    "axis": "exit",
    "kind": "exit",
    "authority": "ref-cli-1.8.2",
    "candidate_sha256": "<64-hex>"
  },
  "fixture": {
    "sha256": "<64-hex>",
    "raw_base64": "<the ORIGINAL fixture, base64>"
  },
  "budget": "256",
  "context": {
    "court_semantic_identity": "<64-hex>",
    "environment_digest": "<64-hex>"
  }
}
```

## 3. The response

```json
{
  "schema_version": "frf-minimizer-response-v1",
  "request_id": "<SHA-256 of the exact request bytes received>",
  "fixture_sha256": "<SHA-256 of the proposed bytes>",
  "fixture_base64": "<the proposed reduced fixture, base64>",
  "minimal": true,
  "minimality": {
    "kind": "boundary",
    "domain": "heartbeat.claimed_payload_length",
    "ordering": "integer-ascending",
    "passing_point": "4073",
    "adjacent_nonpassing_point": "4072",
    "adjacent_fixture_sha256": "<SHA-256 of the adjacent non-passing fixture>",
    "adjacent_fixture_base64": "<the adjacent non-passing fixture, base64>"
  },
  "attempts": [
    {"attempt": "1", "fixture_sha256": "...", "kept": false},
    {"attempt": "2", "fixture_sha256": "...", "kept": true}
  ],
  "indeterminate": false,
  "failure": null
}
```

`attempts` is the minimizer's OWN log (the core records which proposal
survived; the response document preserves the log verbatim). The attempt
index is a STRING: the canonical JSON value domain is
strings/arrays/booleans/null, so a response cannot carry a JSON number
(RFC 8785 number serialization is out of scope for the protocol value
domain). `minimal` is the minimizer's own claim, recorded as claimed — the
final proposal's survival is independently court-verified. In the reduction
record (`frf-reduction-v4`) the claim lands in
`derivation.minimality.proposal_minimality_claimed` and is NEVER relayed
into `derivation.minimality.proven`: `proven` is the core's own statement
(a completed search or a core-executed boundary), and an external proposal
alone never proves anything — the record says `proven: false` and carries
the claim.

`minimality` is an optional DOMAIN-AWARE boundary DECLARATION: the proposal
claims to sit at an observation boundary of a numeric parameter. The
coordinates (`domain`, `ordering`, `passing_point`,
`adjacent_nonpassing_point` — all strings) are the minimizer's domain
interpretation, and `adjacent_fixture_*` names the EXACT bytes of the
adjacent non-passing point. The declaration is a claim, never proof: the
core validates the adjacent fixture hashes to its declared sha256 and
differs from the proposal, then EXECUTES it as a `boundary_control` attempt
recorded in the reduction. The boundary is proven ONLY when the core itself
observed both sides — the adjacent control LOST and the final verification
preserved. A preserved control is a REFUTATION: the record keeps it as
evidence and `proven` stays false. An unsupported `kind` is refused.

## 4. Fail-closed interpretation and court verification

- wrong schema version, unparseable JSON, non-zero exit, timeout → refusal;
- `request_id` MUST equal the request's content address;
- `indeterminate` / `failure` → refusal;
- the declared `fixture_sha256` MUST be the SHA-256 of the proposed bytes;
- the proposal MUST differ from the original fixture (nothing to reduce);
- the ORIGINAL fixture must first reproduce the lineage (the baseline, as in
  the built-in reducer);
- the proposal is then COURT-VERIFIED: both sides execute on the proposed
  bytes, the normalizers re-apply, and the residual's axis is evaluated
  through the ONE comparison operation. The lineage surviving = accepted;
  lost = recorded-but-not-accepted; unevaluable = harness failure (abort).

## 5. Evidence

A successful reduction preserves four files under
`reductions/<id>/minimizer/` (request, response, content-addressed
invocation + result) and the reduction record (`frf-reduction-v4`) binds the
minimizer's semantic id, specification hash, implementation hash, exact
artifact identity, and the invocation/result ids — the record proves WHO
reduced, not merely that a reduction happened. A REFUSED proposal preserves
the same four files under `residuals/<id>.minimizer/<request_cid>/`
(content-addressed by the request) with `court_verified: false` — the
refusal is itself evidence.
