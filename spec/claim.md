# Claims — the Claim IR and the scope algebra

Claims are not produced by humans or by evidence producers. They are COMPILED
by `frf claim compile` from one or more verified premise receipts
(`ReceiptVerified`) — the only code path that can emit a positive claim
sentence — and written to `claims/<claim-id>.json` with a by-receipt index at
`claims/by-receipt/<first-premise-receipt>/<claim-id>` (or rendered canonically
with `--json`).

The claim schema is `frf-claim-v12` (v9 added the sensitivity mutation
profile; v10 declared the claim's EVIDENCE TRANSFORM — nothing varies,
parity over the premises, `scope-admitted` — committed by the content
address, spec/transform.md; v11 admits TRAJECTORY PREMISES: verified
movements of lineages over coordinate systems, so "onset in the vulnerable
release, cessation in the fixed release" is a COMPILED claim under the
scope algebra, not prose; v12 BINDS every trajectory premise to its
SUBJECT). The core of the protocol is the paper's
admission rule, made RELATIVE to an explicitly committed state of
knowledge:

```text
Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)     and     no unresolved residual in U intersects K
```

A claim K is licensed by its premises P₁..Pₙ (the receipts it `requires`)
only when every point of K was actually observed by the union of the
premises — and it is blocked by exactly the residuals whose surface
intersects any of K's cells. The absence of blockers is established by a scan
over U, the EVIDENCE UNIVERSE committed at compile time, and the compiled
claim CARRIES U: the negative search is as portable as the premises.

## 0. Identity and immutability

A claim is a content-addressed IMMUTABLE protocol object:

```text
claim_id = SHA-256("FRF/CLAIM/v1\n" ‖ JCS(claim document minus the id field))
```

The same receipt compiled under a different evidence universe U or a
different admission policy is a DIFFERENT claim with a different id, and they
coexist forever — a claim is never a slot on a receipt, and `claims/<id>.json`
is never overwritten (re-compiling an identical claim is a verified no-op;
re-compiling anything else is a new claim). The `claims/by-receipt/` index is
NON-NORMATIVE: it maps a receipt to its projections; the claims themselves
are the evidence.

Prose is NOT stored as authoritative Claim IR: `positive`/`non_claims` are
renderer outputs, deterministically derived from the verified premises. The
stored IR is the proposition + the evidence graph; the identity
cryptographically binds the exact proposition — not a sentence someone
happened to write.

`frf claim render` accepts ONLY a `ClaimVerified`: the target is a claim id
or a receipt (resolved through the index; several claims for one receipt
must be rendered by id), and the claim is RE-VERIFIED against the evidence
tree before a single field is rendered — identity rederives, every premise
is a `ReceiptVerified`, subject coherence holds, K rederives and is contained
in P, the universe rederives and the blocker search over the COMMITTED U is
empty, the policy evidence (capability / witness / independence / replay
contract) re-verifies, and the IR fields (proposition, relation, environment
label, court, fixture family, observable scope, excluded evidence) all
rederive. A hand-written canonical file at `claims/<id>.json` — even one
whose id rederives — is REFUSED, never rendered: data becomes evidence only
after verification.

## 0. Admission policies — the assurance grades

The claim is compiled under a declared POLICY (`--policy`), and the compiled
claim carries the capability evidence that satisfied it. Every tier above
`baseline` holds PER PREMISE: each premise receipt must satisfy the tier on
its own claimable axes, and the compiled claim binds the evidence to the
premise it belongs to.

| policy | requires (per premise) | carried in the claim |
|---|---|---|
| `baseline` | observation evidence only (the verified receipts + the absence scan over U) | — |
| `sensitivity-backed` | EVERY claimed observable axis of EVERY premise has CHALLENGE coverage: a content-addressed challenge record for THAT premise's court semantic identity, wrapping the same reference artifact, targeting exactly that axis, with `saw_defect` and `specificity_clean` RECOMPUTED from the mutant run. The REQUIRED SENSITIVITY MUTATION PROFILE (`--mutation-profile AXIS:FAMILY,…`) may additionally declare WHICH mutation families must be demonstrated on each claimed surface: every required pair must name a CLAIMED axis (a claim cannot require sensitivity on a surface it does not assert — the profile stays bounded, never a correctness claim) whose DEMONSTRATED operators include that family | `capability` (per-premise, per-axis `{ receipt, axis, mutation_profile, challenge_ids }` — the demonstrated operators plus the challenge ids) + `mutation_profile` (the required pairs) |
| `independently-witnessed` | sensitivity coverage PLUS a verified witness statement attesting EACH premise receipt (`subject kind=receipt`, `outcome: affirm` — the statement's identity, preserved request/response, and request binding all verify on read) PLUS at least one admissible INDEPENDENCE relation per premise: a content-addressed `IndependenceEvidence` record (`frf-independence-v1`) bound to an attestation of THAT premise (identity rederives, the relation is closed, the spec hash rederives). An affirming witness with zero declared independence is WITNESSED, not independently witnessed — the tier's name is its semantics | `witness_statements` (the union across premises) + `independence_evidence` (the records backing them) |
| `high-assurance` | independently witnessed PLUS EVERY premise's observation was made under a profile providing the REQUIRED CAPABILITY SET — the reference contract (`exact_capture_contract`, `sealed_executable_image`, `native_runtime_closure_bound`), the protocol constants no `FRF_EXEC_*` override can redefine (the exact-replay contract). Every admitted profile provides it (v1 exactly; v2/v3/OCI as supersets), so an observation under a stronger harness qualifies exactly like a v1 one — assurance is orthogonal capabilities, never a profile-name equality | `replay_profile` (the least qualifying profile) + `required_capabilities` (the set the policy demanded) |

The tiers are strict supersets: the evidence is named by content address in
the claim, never reduced to a boolean, so any implementation can re-derive
the admission from the claim alone (the independent verifiers do).

## 1. The Claim IR

```text
ClaimRecord {
    id                 content address: FRF/CLAIM/v1 over the canonical
                       document minus the id (Section 0)
    schema_version     frf-claim-v12
    receipt            the FIRST premise receipt (the claim's root into the
                       evidence graph; the by-receipt index maps it)
    authority          prose id of the admitted reference (all premises bind
                       the SAME authority and the SAME candidate artifact —
                       a claim asserts parity of one candidate against one
                       reference)
    candidate          { name, version_or_commit, identity_hash } — the
                       EXACT artifact the runs executed
    court              the first premise's executed court id
    fixture_family
    environment        prose label (arch-os + digest prefix) of the first
                       premise
    relation           the comparators asserted (the clean axes', e.g.
                       eq(exit-code))
    proposition        the machine-readable proposition: parity(cells=[…]),
                       one cell per premise's clean surface
    scope              K — the structured scope as an EvidenceRegion (below)
    observable_scope   flat projection of the region's observables
    blockers           residuals that refuse this claim
    excluded_evidence  observed divergences outside K's cells
    requires           ALL premise receipt ids
    trajectory_premises (v12) each is a verified MOVEMENT bound to its
                       SUBJECT: { lineage, receipt (the anchored premise
                       receipt, ∈ requires), anchor_run (== receipt.run, a
                       point of the series), axis, coordinate_system,
                       series, trajectory (the content address), drift,
                       slew, localization, bands, onset, cessation } — the
                       trajectory document rederives from its pinned series
                       on read, the anchored receipt's run is a point of the
                       series, the axis is a clean declared observable of
                       that receipt, the lineage REDERIVES from the anchored
                       receipt's authority/fixture-family/fixture semantics
                       (an unrelated same-axis trajectory is never a
                       movement premise), and the endpoints derive from the
                       document's observations. On `candidate_revision` the
                       anchored point is proven to be the point of the
                       trajectory that corresponds to the candidate the
                       parity claim is about. The proposition renders the
                       movement ("onset in …, cessation in …")
    transform          the EVIDENCE TRANSFORM declaration (v10): kind=claim,
                       source=the first premise receipt, nothing varies,
                       invariant={candidate, authority}, relation=parity,
                       success=scope-admitted — committed by the claim's
                       content address (spec/transform.md)
    knowledge_snapshot U — the evidence universe the absence search ran over
    policy             the admission policy (Section 0)
    mutation_profile   the REQUIRED sensitivity mutation profile: the
                       AXIS:FAMILY pairs the claim was compiled under (v9;
                       empty = any demonstrated sensitivity on each claimed
                       axis suffices)
    capability         per-premise, per-claimed-axis challenge evidence:
                       { receipt, axis, mutation_profile, challenge_ids } —
                       the DEMONSTRATED operators (the distinct operators of
                       the covering challenges, sorted — re-derived by every
                       verifier) plus the content-addressed challenges that
                       demonstrated sensitivity on that axis for that
                       premise's court
    witness_statements the verified witness statements attesting the premise
                       receipts (independently-witnessed and above)
    independence_evidence
                       the content-addressed IndependenceEvidence records
                       backing those attestations (independently-witnessed
                       and above): every premise must have at least one
                       admissible independence relation bound to an
                       attestation of itself — an attestation alone is
                       witnessed, not independently witnessed
    replay_profile     the least execution profile providing the claim's
                       required capabilities (the replay contract;
                       high-assurance records the reference profile)
    required_capabilities
                       the capability set the policy REQUIRED (the
                       orthogonal assurance model; non-empty for
                       high-assurance — the reference contract — so the
                       requirement rederives from the claim alone)
    positive           NOT STORED — derived by the renderers from the
                       verified premises (one sentence per premise cell)
    non_claims         NOT STORED — derived by the renderers from the
                       premise fixture family
}

KnowledgeSnapshot {
    schema_version     frf-claim-v12
    cid                SHA-256 of FRF/KNOWLEDGE/v2 over the snapshot's fields
    residual_heads     every residual present in U, committed as an exact
                       immutable observation: (id, record_cid — the content
                       address of the record's own fields, fingerprint,
                       disposition, and the disposition event that supplied
                       it). The blocker scan reads those records, so the
                       universe commits their bytes, not their labels.
    objects            every other member of U as a typed content reference:
                       (kind, id, cid) for receipts, runs, authorities,
                       series, and reductions — the cid commits the EXACT
                       bytes the absence search's scope computation read
}
```

The universe is CONTAINED in the evidence that carries it. The reference
loader re-derives every committed object's content address from the store
before consuming a claim (`verify_knowledge_universe`); the independent
verifiers re-derive the same objects FROM THE BUNDLE — a bundle that cannot
reproduce a committed receipt/run/authority/series/reduction is refused, so
"no unresolved residual in U intersects K" means the same thing to the
compiler, the store re-verifier, and every portable verifier. The bundle
export therefore carries the ENTIRE committed universe generically (not
only the objects a run walk happens to cite): every committed authority
(including one only a witness's admission cites), series, reduction,
receipt, and run.

```text
ClaimScope {           one cell: a single Cartesian product
    authority        admitted authority ids
    candidate        exact candidate artifact hashes
    fixtures         EXACT fixture input identities (FRF/FIXTURE/v1 over
                     semantic id + content SHA-256 + declared arguments) —
                     never the human label alone: two different files that
                     share a fixture id are different inputs, and the named
                     role stays the separate fixture_family dimension
    fixture_family
    observables      axes
    environments     environment digests
    versions         authority versions (the envelope's)
    temporal         run ids (where the evidence lives)
}

EvidenceRegion {       the claim's scope K, and the premise union P
    cells            a LIST of ClaimScope cells — the region is the union
                     of its cells, in disjunctive normal form
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
  existential containment — every point of K must lie in SOME cell.
- **K is itself a region**: one cell per premise's clean surface. A claim
  cell is never merged with another premise's cell, so a multi-premise claim
  never asserts parity over a surface no single premise observed (the
  compiler checks the containment literally and refuses a K cell that
  exceeds the premises' observed surface).

## 3. Blocking

- `harness` invalidates the EVIDENCE of a premise run: no claim whose
  `requires` includes a harness run, whatever the axes.
- `open` / `unknown` residuals block exactly the claims whose scope region
  intersects their surface — an unexplained divergence about ANY claimed
  cell's surface blocks, WHEREVER the divergence was recorded. The compiler
  scans the EVIDENCE UNIVERSE U (committed before the scan): an unexplained
  divergence about the claimed candidate artifact, axis, fixture,
  environment, authority, and version blocks the claim even when a later run
  passed (a later observation never rewrites an earlier one; only
  evidence-backed closure does).
- A residual about a different candidate, axis, fixture, or environment does
  not block — the claim about the passing surface compiles.
- An axis A premise receipt's run observed diverging is never parity from
  that receipt, whatever its disposition: a disposition links history, it
  never rewrites an observation. Compile from the resolution run instead
  (the refusal names it) — that axis remains claimable from another premise
  that observed it passing, unless an unexplained divergence on the surface
  blocks.

## 4. Admission

`frf claim compile R1 [R2 …]` verifies every premise receipt (identity over
the raw document — strict I-JSON, duplicate property names and unknown
properties refused — then structural, semantic, and evidentiary
conformance), enforces subject coherence (all premises bind the same
authority and the same candidate artifact), derives K as the region of
per-premise clean surfaces, checks `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)` literally
(existential containment over the premise region cells), commits the
evidence universe U (every residual head with its disposition, every receipt,
run, authority, series snapshot, and reduction present), scans U for
intersecting `open`/`unknown` residuals, and refuses on any blocker. The
compiled claim CARRIES U (content-addressed):

- a store mutation after compile time is a NEW universe — it does not
  silently change what the claim means (re-compiling under the new universe
  produces a new claim with a new snapshot cid);
- the negative search is portable: any implementation can re-run the scan
  over the claim's own snapshot — which is why an OpenReceipt bundle
  carrying a claim also carries the snapshot's residual heads, their events
  and runs, the referenced reductions, and EVERY premise receipt and its
  run (the verifier rehashes every object the absence search depended on).

Prose is ONE renderer of the IR; `--json` emits the same IR canonically
(RFC 8785). `frf claim render RECEIPT --format prose|json|sarif|ci|badge`
presents a COMPILED claim in other voices — a SARIF 2.1.0 document (the
admissible claim as a `none`-level result, each carried residual as
`note`/`error`), a CI gate document, or a badge — all pure, deterministic
functions of the IR, never a new source of epistemic meaning.
