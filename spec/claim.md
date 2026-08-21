# Claims — the Claim IR and the scope algebra

Claims are not produced by humans or by evidence producers. They are COMPILED
by `frf claim compile` from a verified receipt (`ReceiptVerified`) — the only
code path that can emit a positive claim sentence — and written to
`claims/<receipt-id>.json` (or rendered canonically with `--json`).

The claim schema is `frf-claim-v5`. The core of the protocol is the paper's
admission rule, made RELATIVE to an explicitly committed state of knowledge:

```text
Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)     and     no unresolved residual in U intersects K
```

A claim K is licensed by its premises P₁..Pₙ (the receipts it `requires`)
only when every dimension of K's scope was actually observed by the union of
the premises — and it is blocked by exactly the residuals whose surface
intersects K's scope. The absence of blockers is established by a scan over
U, the EVIDENCE UNIVERSE committed at compile time, and the compiled claim
CARRIES U: the negative search is as portable as the premises.

## 0. Admission policies — the assurance grades

The claim is compiled under a declared POLICY (`--policy`), and the compiled
claim carries the capability evidence that satisfied it:

| policy | requires | carried in the claim |
|---|---|---|
| `baseline` | observation evidence only (the verified receipt + the absence scan over U) | — |
| `sensitivity-backed` | EVERY claimed observable axis has CHALLENGE coverage: a content-addressed challenge record for the same court semantic identity, wrapping the same reference artifact, targeting exactly that axis, with `saw_defect` and `specificity_clean` RECOMPUTED from the mutant run | `capability` (per-axis challenge ids) |
| `independently-witnessed` | sensitivity coverage PLUS a verified witness statement attesting THIS receipt (`subject kind=receipt`, `outcome: affirm` — the statement's identity, preserved request/response, and request binding all verify on read) | `witness_statements` |
| `high-assurance` | independently witnessed PLUS the observation was made under the reference execution profile (`frf-exec-linux-v1`) with the reference capture bounds (the exact-replay contract) | `replay_profile` |

The tiers are strict supersets: the evidence is named by content address in
the claim, never reduced to a boolean, so any implementation can re-derive
the admission from the claim alone (the independent verifiers do).

## 1. The Claim IR

```text
ClaimRecord {
    schema_version     frf-claim-v5
    receipt            the premise receipt (v0: exactly one premise)
    authority          prose id of the admitted reference
    candidate          { name, version_or_commit, identity_hash } — the
                       EXACT artifact the run executed
    court              the executed court id
    fixture_family
    environment        prose label (arch-os + digest prefix)
    relation           the comparators asserted (the clean axes', e.g.
                       eq(exit-code))
    proposition        the machine-readable proposition
    scope              K — the structured scope (below)
    observable_scope   projection of scope.observables
    blockers           residuals that refuse this claim
    excluded_evidence  observed divergences outside K's surface
    requires           premise receipt ids
    knowledge_snapshot U — the evidence universe the absence search ran over
    policy             the admission policy (Section 0)
    capability         per-claimed-axis challenge evidence: { axis,
                       challenge_ids } — the content-addressed challenges
                       that demonstrated sensitivity on that axis
    witness_statements the verified witness statements attesting the receipt
                       (independently-witnessed and above)
    replay_profile     the execution contract the evidence was observed under
                       (high-assurance requires the reference profile)
    positive           prose renderer output
    non_claims         the non-claim renderer output
}

KnowledgeSnapshot {
    schema_version     frf-claim-v5
    cid                SHA-256 of FRF/KNOWLEDGE/v2 over the snapshot's fields
    residual_heads     every residual present in U, committed as an exact
                       immutable observation: (id, record_cid — the content
                       address of the record's own fields, fingerprint,
                       disposition, and the disposition event that supplied
                       it). The blocker scan reads those records, so the
                       universe commits their bytes, not their labels.
    objects            every other member of U as a typed content reference:
                       (kind, id, cid) for receipts, runs, authorities,
                       series, and reductions
}
```

ClaimScope {
    authority        admitted authority ids
    candidate        exact candidate artifact hashes
    fixtures         fixture ids actually executed
    fixture_family
    observables      axes
    environments     environment digests
    versions         authority versions (the envelope's)
    temporal         run ids (where the evidence lives)
}
```

## 2. Scope semantics

- **Intersection** is product-wise: two scopes overlap iff they share a
  point in EVERY dimension — {authority, candidate, fixtures,
  fixture_family, observables, environments, versions}. `temporal` is
  deliberately excluded: an open divergence recorded by an earlier run about
  the same surface is still an unexplained divergence about that surface,
  and must still block.
- **Containment** is dimension-wise subset: `Scope(P) ⊇ Scope(K)` when every
  point of K is a point of P.
- **Union is a union of scope CELLS, never a merge of dimension sets.** A
  union of Cartesian products is not generally the product of dimension-wise
  unions — merging dimension sets would INVENT unsupported evidence points
  (evidence-space inflation). The premise union `P₁ ∪ … ∪ Pₙ` is therefore
  an [`EvidenceRegion`]: a list of cells, and the admission rule is
  existential containment — every point of K must lie in SOME cell. The
  single-premise compiler produces a one-cell region; the multi-premise
  compiler appends one cell per premise receipt without ever merging
  dimensions.

## 3. Blocking

- `harness` invalidates the EVIDENCE of a premise run: no claim whose
  `requires` includes a harness run, whatever the axes.
- `open` / `unknown` residuals block exactly the claims whose scope
  intersects their surface — WHEREVER the divergence was recorded. The
  compiler scans the EVIDENCE UNIVERSE U (committed before the scan): an
  unexplained divergence about the claimed candidate artifact, axis,
  fixture, environment, authority, and version blocks the claim even when a
  later run passed (a later observation never rewrites an earlier one; only
  evidence-backed closure does).
- A residual about a different candidate, axis, fixture, or environment does
  not block — the claim about the passing surface compiles.
- An axis THIS receipt's run observed diverging is never parity from this
  receipt, whatever its disposition: a disposition links history, it never
  rewrites an observation. Compile from the resolution run instead (the
  refusal names it).

## 4. Admission

`frf claim compile` verifies the receipt (identity over the raw document —
strict I-JSON, duplicate property names and unknown properties refused —
then structural, semantic, and evidentiary conformance), derives K from the
clean axes, checks `Scope(K) ⊆ Scope(P)` literally (existential containment
over the premise region), commits the evidence universe U (every residual
head with its disposition, every receipt, run, authority, series snapshot,
and reduction present), scans U for intersecting `open`/`unknown` residuals,
and refuses on any blocker. The compiled claim CARRIES U (content-addressed):

- a store mutation after compile time is a NEW universe — it does not
  silently change what the claim means (re-compiling under the new universe
  produces a new claim with a new snapshot cid);
- the negative search is portable: any implementation can re-run the scan
  over the claim's own snapshot — which is why an OpenReceipt bundle
  carrying a claim also carries the snapshot's residual heads, their events
  and runs, and the referenced reductions (the verifier rehashes every
  object the absence search depended on).

Prose is ONE renderer of the IR; `--json` emits the same IR canonically
(RFC 8785).

A multi-premise compiler (admission against the UNION of several receipts'
scopes) is future work; the cell-region algebra above already defines it
without inflation.
