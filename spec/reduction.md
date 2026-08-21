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
(`reductions/<id>.yaml`, `frf-reduction-v1`):

```text
ReductionRecord {
    id                        FRF/REDUCTION/v1 over the record's own fields
    residual_id               the residual being minimized
    axis / kind
    authority                 the admitted authority id
    candidate_sha256          the exact candidate artifact (held fixed)
    original_fixture_sha256
    final_fixture_sha256      the reproducer (court-verified)
    attempts[]                { attempt, fixture_sha256, preserved, kept } —
                              every reduction step, in order
    derivation                { strategy, original_lines, final_lines,
                                minimal }
}
```

`minimal` is only claimed when the deterministic ddmin search completed
within the attempt budget; a budget-cut search says so honestly (the last
attempt is still the court verification of the reproducer). The reproducer
object lives under `objects/sha256/` like every other content-addressed
artifact.

The record is immutable: tampering breaks the content address and is refused
on read.
