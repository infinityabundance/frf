# FRF Quick Reference

Two documents in one file: a vocabulary Rosetta table (for orienting a reader who
already knows adjacent practices), and the operating core (kernel + rules +
worked example) — everything a developer needs to run FRF today without reading
the full paper. The full paper (*The Forensic Residual Framework*, de Beer, 2026)
remains the source of truth for provenance, DSFB lineage, the Taste Codex layer,
and formal treatment; this document exists so no one has to read that first.

---

## Part 1 — Rosetta Table

If you already know these practices, here's what FRF term maps to what you know,
and — more importantly — what it adds on top.

| FRF term | Closest known practice | What FRF adds |
|---|---|---|
| **Authority** | Test oracle; source of truth in golden-master testing | Requires *admission* — a versioned, hashed identity record — before the oracle can be cited, preventing silent oracle drift |
| **Admission** | Pinning a dependency version / lockfile | Applied to *evidence sources*, not just build dependencies — the reference binary itself gets a lockfile entry |
| **Court** | A single contract test (Pact) or a differential-testing harness (McKeeman) run | Must declare its admissibility envelope up front; a court that runs outside its declared conditions returns UNKNOWN, not PASS |
| **Admissibility envelope** | Test scope / preconditions in a test plan | Made a first-class, checked object rather than a comment or a doc string |
| **Observable** | Assertion target / comparison surface in a differential test | Enumerated explicitly per court so "we tested it" always answers "tested *what*, exactly" |
| **Raw capture** | Golden file / cassette (VCR-style recorded interaction) | Immutable by rule — normalization always produces a *new* derived artifact, never overwrites the raw one |
| **Residual** | A failing diff in golden-master or snapshot testing | Not auto-accepted or auto-updated on mismatch — it gets identity, a lifecycle, and a required disposition before it can close |
| **Structured Unknown** | "Flaky test" or "test skipped" | Explicit third state distinct from pass/fail, carrying full residual metadata — flaky isn't a shrug, it's a typed, routable object |
| **Disposition** | Triage label on a bug ticket (wontfix, duplicate, fixed) | Required reason string enforced at the tool level; no silent default disposition |
| **Residual token / endoduction** | Bug classification / defect taxonomy tagging | Deterministic function, not human judgment call — same residual always coarsens to the same token |
| **Receipt** | SLSA-style provenance attestation / build attestation | Applied to *behavioral test outcomes*, not just supply-chain artifacts |
| **Claim compiler** | Nothing standard has this | The actual novel piece: prose claims are *generated from* receipts and mechanically refused if evidence doesn't cover them — most projects hand-write "production ready" with no such gate |
| **Non-claim / negative capability** | "Known limitations" section in a README | Made structurally paired with each positive claim rather than optional prose at the bottom |
| **Invariant bank** | Regression test suite | Explicitly linked back to the residual that motivated it, with a required negative control |
| **Minimization** | Test-case reduction (C-Reduce lineage) | Same idea, explicitly required as a step before a residual can be marked resolved |
| **Negative control / mutation operator** | Mutation testing (kill rate) | Applied to *invariants specifically*, not code coverage generally — "does this court reject the seeded failure" |
| **Normalization (governed)** | Ignoring timestamps/UUIDs in a snapshot diff | Requires the normalizer itself to be versioned evidence, and the resulting claim explicitly excludes the normalized field |
| **Authority separation** | Multiple sources of truth in a data-consistency system | Applied to test oracles — an RFC and a legacy binary can disagree, and FRF requires that conflict stay visible rather than picking a winner silently |
| **Semantic non-bypass rule** | Nothing standard has this | The hard version of "don't let the README outrun the tests" — enforced as a code-path constraint, not a review habit |

**The one-line summary for a skeptical senior engineer:** this is differential
testing plus golden-master discipline plus SLSA-style provenance, with one truly
new piece — a claim compiler that refuses to let documentation say more than the
receipts prove.

---

## Part 2 — The Operating Core

Everything below is the entire practical payload of FRF. If you internalize this
page, you can run the framework without the rest of the paper.

### The central rule

> A mismatch is not noise until evidence establishes why it is noise.

### The kernel — ten steps, in order

1. Admit the authority.
2. Declare the claim you're trying to earn.
3. Name the court (one narrow question).
4. Capture raw observations from both sides.
5. Preserve residuals — don't interpret yet.
6. Coarsen residuals into typed tokens.
7. Route tokens to the next court or blocker.
8. Add negative controls.
9. Emit receipts.
10. Compile claims and non-claims — never hand-write either.

### The canonical loop

```
Authority → Court → Capture → Residual → Endoduction
→ Route → Disposition → Receipt → Claim
```

### The twelve operating rules

1. A green test without a bounded claim is a local signal, not an argument.
2. Compatibility is a property of code *observed against an admitted authority*, not of code alone.
3. The authority is not sacred. The observation is.
4. Preserve raw residuals before interpreting, normalizing, filtering, or fixing them.
5. Treat every normalizer as claim-weakening machinery until proven otherwise.
6. Never call an unmeasured surface compatible.
7. Never let a fixture count substitute for surface coverage.
8. Never delete a residual without a disposition.
9. Never convert an intentional divergence into a parity claim.
10. Never let the README outrun the receipts.
11. If a statement can be generated from evidence, generate it.
12. A receipt is the build artifact of a claim.

### Residual states (use all of them — not just pass/fail)

`admissible | boundary | violation | recovery | unknown | intentional_divergence`

### Minimal residual token

```yaml
kind: text | exit | wire | state | timing | filesystem | security | platform | performance | harness | unknown
surface: string
authority: string
disposition: open | fixed | intentional | environmental | oracle_version | harness | unknown
next_court: string
```

A disposition is not valid without a one-line reason attached to it.

### Worked example (condensed from the full paper's Section 12)

**Question:** for malformed input, does the candidate preserve the reference's exit
class and first diagnostic line?

**Raw capture:**
```
reference.exit: 2      reference.stderr[0]: "tool: file:4: unknown directive 'servre'"
candidate.exit: 1      candidate.stderr[0]: "error: unknown directive servre at line 4"
```

**Two residuals, both `open`.** Don't decide who's "right" yet.

**Endoduction:** exit residual routes to exit-class minimization; text residual
routes to diagnostic-wording minimization. Both currently block any compatibility
claim.

**Minimization:** reduces to a single misspelled directive — that alone is
sufficient to reproduce both residuals.

**Resolution:** candidate is patched to match the exit class. Diagnostic wording
is kept different on purpose, for clarity.

**Dispositions:** `exit → fixed` · `text → intentional-divergence (reason: clearer wording, documented)`

**What the claim compiler is allowed to say:**
> For reference `ref-cli-1.8.2`, fixture family X, and environment E, the candidate
> preserves malformed-input exit class for the minimized directive-error cases.

**What it must refuse to say:**
> The candidate is byte-identical on stderr, fully CLI-compatible, or a drop-in
> replacement for all malformed-input behavior.

That refusal — not the pass — is the artifact FRF exists to produce.

### When *not* to use this

Not every project needs byte-exact historical compatibility. If there's no
meaningful external authority to admit against — no reference implementation,
contract, protocol, or prior release — conventional spec-driven development is
probably the better tool. FRF earns its cost specifically where a claim depends
on an admitted authority.

---

*This cheat sheet is deliberately small enough to act as a Claude skill
(`SKILL.md`) as-is — the frontmatter a skill needs (name, description, trigger
conditions) is the only thing missing; the body above is already skill-shaped.
Say the word if you want it converted.*
