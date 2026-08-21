# The evaluation plan — one relation governing observation, replay, resolution, and reduction

*Version: the reference execution profile `frf-exec-linux-v1`; the comparator
extension protocol (`spec/comparator.md`).*

FRF's core invariant is that ONE comparator semantics governs every operation
that decides "does this axis differ?". There is exactly one comparison
operation — the **evaluation plan** — and nothing outside it may decide
parity:

```text
                 Court Semantic Identity
                          │
                          ▼
                   Evaluation Plan
                          │
             ┌────────────┼─────────────┐
             │            │             │
         Authority     Candidate      Fixture
             │            │             │
             └────────────┼─────────────┘
                          ▼
                      Execute
                          │
                          ▼
                     Observe
                          │
                          ▼
                     Compare
                          │
                ┌─────────┴─────────┐
                │                   │
              Pass               Residual
                                    │
                  ┌─────────────────┼────────────────┐
                  │                 │                │
              Trajectory         Reduce          Resolve
                  │                 │                │
                  └─────────────────┼────────────────┘
                                    ▼
                              Evidence Graph
                                    │
                              Claim Compiler
```

## The evaluation plan

An **EvaluationPlan** binds, for one observable axis:

- the **semantic identity** — what the relation IS (the comparator's
  specification hash, derived from the declared relation/extractor/residual
  classifier);
- the **implementation identity** — who runs it (an in-binary comparator is
  implemented by the frf executable itself; an external comparator is the
  snapshotted, re-hashed program whose bytes the capture binds).

Every operation derives its plan from the SAME capture-bound fields
(`EvaluationPlan::from_capture`) and evaluates through the ONE function
(`evaluate`). The four operations differ only in what they permit to move:

| Operation   | Varies            | Must stay (invariant)                     | Success predicate       |
| ----------- | ----------------- | ----------------------------------------- | ----------------------- |
| observation | nothing           | nothing (the observation IS the evidence) | divergence-observed     |
| replay      | nothing           | the whole observation                     | observation-reproduces  |
| resolution  | candidate artifact| question, authority, fixture, environment, comparator | axis-closes  |
| reduction   | fixture           | candidate, authority, comparator, environment | lineage-survives   |
| trajectory  | the declared coordinate | the question, the artifacts, the relation | observed/absent per point |

This is the **evidence-transform** frame: every operation that produces new
evidence from old evidence declares what it permits to change and what it
requires to stay, and records that declaration in the evidence it produces
(the reduction record carries its transform; the disposition event binds the
resolution run). The relations and the success predicates are the same
protocol objects the rest of the evidence graph uses — never a re-derived
built-in projection.

## Why one relation

A comparator's EXTRACTOR defines what the relation sees. The built-in `stderr`
comparator extracts the first diagnostic line; an external comparator may
declare any extractor (`stderr-bytes`, `diagnostic-error-code`, …). If
observation used the comparator but replay, resolution, and minimization
re-derived the built-in projection, you would have four definitions of one
evidentiary relation: a candidate whose full stderr changed while the first
line stayed identical would be divergent at court time (the comparator says
so) yet "reproduced", "preserved", and "closed" by the built-in projection.
That is not evidence; that is four programs disagreeing about what the
evidence means.

The rule, enforced by construction:

> **Nothing outside `evaluate()` may decide whether an axis differs.**

- **court run** evaluates every declared axis through its plan; the request,
  response, invocation, and result of an externally served axis are preserved
  as evidence.
- **replay** re-invokes the exact snapshotted implementation against the
  reproduced sides, requires the request to rederive and the outcome to
  reproduce, and compares the FRESH residual fingerprint SET against the
  recorded one (every divergence, not "the first one").
- **resolution** requires the recorded result of the resolution run's own
  evaluation to be `equivalent` for an externally served axis (verification
  never re-executes: the resolution court already executed the comparator and
  preserved the evidence), and evaluates the built-in axis in-process against
  the resolution run's verified captures.
- **minimization** decides preservation by evaluating the reduced fixture
  through the residual's plan — the comparator that generated the original
  evidence defines what "the lineage survives" means — and binds the
  comparator semantic + implementation identities in the reduction record, so
  the record itself proves what it held fixed.

Two implementations of the same specification are the same question; two
specifications are two questions. The plan is the protocol object that keeps
that distinction across every operation.
