# Reduction — the minimization protocol

`frf court minimize RESIDUAL_ID` is the routed minimizer: the residual's κ
token carries the route (`cli-exit-minimize`, `cli-diagnostic-minimize`,
`cli-stdout-minimize`), and the reducer turns a large failure into a small
forensic object.

The reduction is an evidence TRANSFORM with declared invariants:

```text
fixture           MAY change        (the only dimension that changes)
candidate         MUST remain       (the exact artifact the residual was
                                     observed against)
authority         MUST remain
comparator        MUST remain
environment       MUST remain
residual lineage  MUST survive      (the preservation predicate)
```

The preservation predicate is the residual's LINEAGE
(`FRF/RESIDUAL-LINEAGE/v1`): a candidate fixture is kept only when the same
kind/axis/surface divergence is still observed when both sides are
re-executed from their content-addressed snapshots with the reduced fixture
in the recorded argv.

## The record

Every minimization is a content-addressed protocol object
(`reductions/<id>.json`, `frf-reduction-v4`):

```text
ReductionRecord {
    id                                FRF/REDUCTION/v2 over the record's own
                                      fields
    residual_id                       the residual being minimized
    source_run                        the run that observed the residual
    axis / kind
    court_semantic_identity           the question (held fixed)
    authority_artifact_sha256         the authority artifact (held fixed)
    candidate_artifact_sha256         the exact candidate artifact (held fixed)
    environment_digest                the environment (held fixed)
    comparator_semantic_id            the comparator RELATION that governs the
    comparator_semantic_hash          preservation predicate (held fixed)
    comparator_implementation_hash    the comparator IMPLEMENTATION that
                                      observed the residual (held fixed)
    argv_template                     the resolved argv the sides executed
                                      under (the fixture slot varies)
    original_fixture_sha256
    final_fixture_sha256              the reproducer (court-verified)
    attempts[]                        { attempt, role, fixture_sha256,
                                      outcome, accepted } — every EXECUTABLE
                                      step, in order
    derivation                        { strategy, original_lines,
                                      final_lines, minimality }
    transform                         the evidence-transform declaration
                                      (kind=reduction, fixture varies,
                                      candidate/authority/comparator/
                                      environment stay, predicate=
                                      lineage-survives)
}
```

Every recorded attempt carries its ROLE (`baseline` — the original fixture
checked before the search; `candidate` — a ddmin step; `final_verification`
— the reproducer's last court run), its OUTCOME (`preserved` / `lost` /
`harness_failure` — an unevaluable attempt ABORTS the minimization, never
silently skipped), and whether it was ACCEPTED (preserved AND the fixture
shrank; a baseline is never accepted). The attempt budget is a HARD gate
around every executable attempt: neither the outer nor the inner ddmin loop
can exceed it, and the final verification is executed under the same gate.

`minimality` is stated precisely — `{kind: one-minimal, granularity: line,
proven}`: classic ddmin establishes that no single line can be removed while
preserving the lineage, not global cardinality minimality — and `proven` is
only true when the deterministic search completed within the attempt budget;
a budget-cut search says so honestly. The reproducer object lives under
`objects/sha256/` like every other content-addressed artifact.

The preservation predicate is decided by the SAME evaluation plan that
observed the residual (`spec/evaluation.md`): the built-in implementation
in-process, or the exact snapshotted external comparator re-invoked — never a
re-derived built-in projection. The bound identities prove the record held
what the transform declares it held.

The record is immutable: tampering breaks the content address and is refused
on read.
