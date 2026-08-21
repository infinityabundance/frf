# Claims — the Claim IR and the scope algebra

Claims are not produced by humans or by evidence producers. They are COMPILED
by `frf claim compile` from a verified receipt (`ReceiptVerified`) — the only
code path that can emit a positive claim sentence — and written to
`claims/<receipt-id>.yaml` (or rendered canonically with `--json`).

The claim schema is `frf-claim-v2`. The core of the protocol is the paper's
admission rule:

```text
Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)
```

A claim K is licensed by its premises P₁..Pₙ (the receipts it `requires`)
only when every dimension of K's scope was actually observed by the union of
the premises — and it is blocked by exactly the residuals whose surface
intersects K's scope.

## 1. The Claim IR

```text
ClaimRecord {
    schema_version    frf-claim-v2
    receipt           the premise receipt (v0: exactly one premise)
    authority         prose id of the admitted reference
    candidate         { name, version_or_commit, identity_hash } — the
                      EXACT artifact the run executed
    court             the executed court id
    fixture_family
    environment       prose label (arch-os + digest prefix)
    relation          the comparators asserted (the clean axes', e.g.
                      eq(exit-code))
    proposition       the machine-readable proposition
    scope             K — the structured scope (below)
    observable_scope  projection of scope.observables
    blockers          residuals that refuse this claim
    excluded_evidence observed divergences outside K's surface
    requires          premise receipt ids
    positive          prose renderer output
    non_claims        the non-claim renderer output
}

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
- **Union** merges dimension sets (the P₁ ∪ … ∪ Pₙ of the admission rule).

## 3. Blocking

- `harness` invalidates the EVIDENCE of a premise run: no claim whose
  `requires` includes a harness run, whatever the axes.
- `open` / `unknown` residuals block exactly the claims whose scope
  intersects their surface — WHEREVER the divergence was recorded. The
  compiler scans the whole store: an unexplained divergence about the
  claimed candidate artifact, axis, fixture, environment, authority, and
  version blocks the claim even when a later run passed (a later observation
  never rewrites an earlier one; only evidence-backed closure does).
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
clean axes, checks `Scope(K) ⊆ Scope(P)` literally, scans the store for
intersecting `open`/`unknown` residuals, and refuses on any blocker. Prose is
ONE renderer of the IR; `--json` emits the same IR canonically (RFC 8785).

A multi-premise compiler (admission against the UNION of several receipts'
scopes) is future work; the algebra above already defines it.
