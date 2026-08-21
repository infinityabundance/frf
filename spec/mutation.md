# Mutation providers — the mutation extension protocol

A court challenge seeds a defect and requires the court to see it. The
built-in mutation operators (`src/mutation.rs`) cover the built-in surfaces
only: `exit-class`, `stderr-first-line`, `stdout-first-line`. Domain surfaces —
`dns.wire`, `filesystem.tree`, `sql.schema`, `elf.abi`, `terminal.frame`,
`packet.sequence`, … — need domain-specific negative controls, and those
must not live in FRF core.

The mutation extension protocol makes them external, with the same
architectural rule as the minimizer protocol:

> **The extension proposes; the court decides.**

A mutation provider is a program that receives the court's question and the
exact reference + fixture artifacts and PROPOSES one mutant candidate. The
court then runs the proposal as an ordinary content-addressed court run and
independently derives the verdicts (`saw_defect` on the targeted axis,
`specificity_clean` on the rest) from the run's residuals — the provider's
`expected_affected_surfaces` are recorded as its declared expectation, never
trusted as the verdict.

## Declaration

```yaml
mutations:
  - id: treegen-content-swap        # the operator id `--operators` names
    relation: produced-content-swap # the mutation family (semantic identity)
    relation_version: "1"
    target_axes: [filesystem.tree]  # every axis must be a declared observable
    program: treegen-mutate.py      # sealed + hashed before it runs
```

Ids must be unique and must not collide with the built-in operators. The
challenge runs the provider once per declared target axis.

## The canonical request

The court writes the canonical `MutationRequest` document (schema
`frf-mutation-request-v1`, strict canonical JSON) to the provider's stdin.
The request's `request_cid` is the SHA-256 of those raw canonical bytes (the
extension-protocol identity rule: a request is identified by its exact
canonical bytes, never by a re-serialization):

```text
MutationRequest {
    schema_version     frf-mutation-request-v1
    mutation           { id, relation_id, relation_version, specification_hash }
                       — the SEMANTIC identity (FRF/MUTATION-SPEC/v1 over
                       id + relation + relation_version): what kind of
                       mutant is asked for
    court              { id, question, falsifier, observables, fixture_family }
                       — the question the mutant will be run against
    target_axis        the observable axis to seed a defect on
    reference_artifact { sha256, contents_base64 } — the admitted reference
                       artifact the mutant wraps (the exact bytes the court
                       executes as its authority side)
    fixture            { sha256, contents_base64 } — the fixture the court
                       runs the mutant against
}
```

## The canonical response

The provider answers with `frf-mutation-response-v1` on stdout:

```text
MutationResponse {
    schema_version           frf-mutation-response-v1
    request_id               MUST equal the SHA-256 of the exact request
                             bytes received (the response cryptographically
                             names the request it answers)
    mutant_base64            the proposed mutant candidate artifact, base64
                             (absent = declined, a refusal)
    expected_affected_surfaces   the axes the provider EXPECTS to move
                             (informational; the court decides)
    failure                  provider-side failure/refusal message
}
```

Fail-closed rules, mirroring the other extension protocols: non-zero exit,
unparseable JSON, a non-canonical response (the protocol says canonical), a
response that does not name its request, an explicit `failure`, a decline
(no mutant), or an EMPTY mutant are all refusals — the challenge records the
refusal as evidence and fails.

## The court decides

The proposed mutant is written to a transient path and the court runs it as
the candidate (same question, same envelope, same fixture — a normal,
content-addressed run). The verdicts derive from the run's residuals exactly
as for a built-in operator:

- `saw_defect` — a residual appeared on the targeted axis;
- `specificity_clean` — no residual appeared on the unaffected axes.

A court that is blind to the proposed defect (no divergence on the target)
or conflates axes is refused; the challenge record remains as evidence.

## Evidence

The proposal is instrumentation, so it is evidence: the canonical request +
response and the content-addressed `FRF/MUTATION-INVOCATION/v1` +
`FRF/MUTATION-RESULT/v1` records are preserved under
`challenges/<id>/mutation/`, and the `CourtChallenge` binds the invocation
and result ids. `load_mutation_evidence` cross-verifies on read: identities
rederive from the records' own fields, the preserved documents hash to their
cids, the response names its request, and the proposed mutant rehashes to
the recorded `mutant_sha256` — which the challenge identity
(`FRF/CHALLENGE/v1`) itself commits as `mutant_candidate_sha256`. A
verifier regenerates the mutant bytes from the preserved response and
reproves the whole chain.

## Schema versions

```text
frf-mutation-request-v1    the canonical request
frf-mutation-response-v1   the canonical response
frf-mutation-invocation-v1 the invocation evidence record
frf-mutation-result-v1     the result evidence record
FRF/MUTATION-SPEC/v1       the mutation semantic identity preimage
FRF/MUTATION-INVOCATION/v1 the invocation evidence identity preimage
FRF/MUTATION-RESULT/v1     the result evidence identity preimage
```
