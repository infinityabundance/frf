# The EvidenceTransform protocol

An **evidence transform** is the general derived-evidence primitive of FRF:
a declared, typed relation from *source evidence* to *derived evidence*,
naming what may vary, what must stay, the relation that governs the
comparison, and how success is decided.

Every protocol object that is DERIVED from other evidence — not observed
directly — declares the transform it is, and the object's content identity
COMMITS the declaration: the transform is part of the identity preimage
(same rule as the reduction). Verification rederives the transform's shape
from the producing record and checks it against the object's declared
dimensions, so a derived document can never be relabeled as a different
kind of evidence without changing its identity.

## 1. The declaration

```text
EvidenceTransform {
    kind                  observation | resolution | replay | reduction |
                          trajectory | claim
    source                the content address / id of the evidence consumed
                          (run id, residual id, series id, premise receipt id)
    varying_dimensions    what MAY change under this transform
                          (e.g. fixture for a reduction, coordinate for a
                          trajectory, candidate for a resolution)
    invariant_dimensions  what MUST NOT change, each bound by identity in
                          the producing record
    observation_relation  the evaluation relation governing the comparison:
                          the observable axis + its specification — the same
                          identity the court bound (or "parity" for a claim)
    success_predicate     how success is decided
}
```

The six instances:

| kind | source | varying | invariant | relation | success |
|---|---|---|---|---|---|
| `observation` | run | — | — | the court's relation | `divergence-observed` |
| `resolution` | run | `candidate` | question, authority, fixture, environment, comparator | the court's relation | `axis-closes` |
| `replay` | run | — | — | the court's relation | `observation-reproduces` |
| `reduction` | residual | `fixture` | candidate, authority, comparator, environment | the court's relation | `lineage-survives` |
| `trajectory` | series | `coordinate` | lineage, axis, question, authority, comparator | the axis's relation | `movement-classified` |
| `claim` | premise receipt | — | candidate, authority | `parity` | `scope-admitted` |

## 2. The commitment rule

A derived object's content address is computed over its canonical document
INCLUDING the transform declaration:

- `FRF/REDUCTION/v3` hashes the reduction's fields + `transform`;
- `FRF/TRAJECTORY/v1` hashes the trajectory's fields + `transform`;
- `FRF/CLAIM/v1` hashes the claim's fields + `transform`.

Relabeling a document (changing its `kind`, source, dimensions, or
predicate) changes its content address, so no derived document can be
passed off as a different transform.

## 3. Verification

Each derived object verifies as EVIDENCE only after:

1. canonical parsing (bytes == RFC 8785 canonical, strict I-JSON);
2. the content address rederives from the record's own fields (including the
   transform declaration);
3. the transform's `kind` is the object's kind, and the declaration is the
   one the producing context requires — a reduction must declare the
   fixture-varying transform, a trajectory the coordinate-varying transform
   of its series, a claim the parity transform of its premises;
4. the derived content re-derives from the source (the minimizer attempts,
   the trajectory classification over the pinned series' observations, the
   claim's scope algebra over the committed universe).

The reference engine enforces this in `load_*` verified paths and the
whole-store walk; the independent verifiers (xtask, Go) rederive the same
identities and shapes from bundles and the corpus.

## 4. The instances

### 4.1 observation
The court runs a question and observes a divergence. Nothing may vary:
the run IS the observation.

### 4.2 resolution
A later run reruns the SAME question under a CHANGED candidate artifact and
observes the axis close. Only the candidate varies; the question,
authority, fixture, environment, and comparator must stay (each bound by
identity in the resolution's evidence edge).

### 4.3 replay
An independent re-execution of the same observation. Nothing may vary; the
observation must reproduce byte-for-byte.

### 4.4 reduction
The minimization: the fixture shrinks while the candidate, authority,
comparator, and environment stay. The final fixture is court-verified to
preserve the lineage (`lineage-survives`), and minimality is the record's
own statement (one-minimal at line granularity, or the typed
adjacent-boundary domain with the identity-bound domain projection).

### 4.5 trajectory
The movement of one lineage across an ordered coordinate system (repetition
index, candidate revision, authority version, environment, time). The source
is the ExecutionSeries; the coordinate varies; the lineage, axis, question,
authority, and comparator stay. The derivation (drift/slew/localization/
bands/trend) is the deterministic classification of the series'
observations — never read from the file. The trajectory record is
content-addressed (`FRF/TRAJECTORY/v1`) and declares its transform, making
it a first-class derived protocol object like the reduction.

### 4.6 claim
The compilation of premise receipts against the committed knowledge
universe under an admission policy. The source is the first premise
receipt; nothing varies — the claim is the scope algebra over exactly the
premises, the universe, and the policy. Success is `scope-admitted`:
`Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)`, the absence scan over U is empty, and the
policy evidence (challenge coverage, witness statements, independence,
replay profile) re-verifies. The claim record declares its transform and is
content-addressed (`FRF/CLAIM/v1`).

## 5. Protocol status

- Schema: the transform is a structural declaration inside the producing
  records (`frf-reduction-v5`, `frf-trajectory-v6`, `frf-claim-v10`); it has
  no standalone schema version.
- Identity domain: `FRF/TRAJECTORY/v1` (trajectory content address).
- The transform declaration is rederived by all three implementations
  (reference engine, xtask, Go verifier) from the document's own fields.
