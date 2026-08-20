# Build Prompt: `frf` — Minimal Reference Implementation of the Forensic Residual Framework

## Mission

Implement the smallest possible tool that makes the FRF kernel *executable* rather than
just *described*. The test of success is not feature count. It is this: a developer with
no prior exposure to FRF should be able to install the tool, run it against two CLI
programs, and watch an authority get admitted, a court run, raw output captured, a
residual preserved, an endoduction token emitted, a disposition recorded, a receipt
written, and a claim compiled — end to end, on one real example — inside five minutes.

Everything in this brief exists to protect that five-minute experience. Cut anything
that threatens it. Do not build the platform. Build the kernel.

## Source of truth

The canonical object model, field names, and schema are defined in *The Forensic
Residual Framework* (R. de Beer, v1.0, 2026), specifically:
- Section 2 (Developer Operating Kernel)
- Section 10 (Formal Model)
- Section 12 (Worked Court: From Mismatch to Claim) — this is your golden-path test case
- Appendix A (Minimal Receipt Schema)
- Appendix B (Developer Checklist)

Do not invent new terminology. Do not add fields the paper doesn't define. If a
schema field in Appendix A isn't needed to make the worked example in Section 12
run end to end, leave it out of v0 and note it as a documented gap — that omission
is itself a residual, and FRF's own discipline says to be honest about it rather
than build ahead of the evidence.

## Scope: what v0 must do

Implement exactly the canonical loop, nothing upstream or downstream of it:

```
Authority → Court → Capture → Residual → Endoduction
→ Route → Disposition → Receipt → Claim
```

Concretely, as a CLI:

1. **`frf authority admit`** — records an authority: name, kind (start with
   `executable_reference` only), version, path, computed SHA-256, platform.
   Writes `authorities/<id>.yaml`.

2. **`frf court run`** — takes a court manifest (question, admitted authority id,
   candidate path, fixture, declared observable axes — start with `exit` and
   `stderr` only), executes both authority and candidate against the fixture,
   captures raw stdout/stderr/exit code with hashes, and diffs the declared axes.

3. **Residual creation** — for every axis where authority and candidate disagree,
   write a residual record: id, kind, raw authority value, raw candidate value,
   disposition `open`. No interpretation yet. No repair yet.

4. **Endoduction** — a small, honest, deterministic function `κ(residual) → token`
   that coarsens each residual into `{kind, surface, authority, magnitude, scope,
   disposition, next_court}` per the token grammar in Section 6. Keep this function
   dumb on purpose in v0 — a lookup/classification table, not a model, not a
   heuristic engine. It should be auditable in under a minute of reading.

5. **`frf residual dispose`** — lets a developer mark a residual's disposition
   (`fixed | intentional | environmental | oracle_version | harness | unknown`)
   with a required one-line reason. Refuse to let a disposition be set without
   a reason string — that refusal *is* the misuse-resistance gate from the Taste
   Codex layer, implemented, not just described.

6. **`frf receipt emit`** — binds court + authority + candidate + fixture +
   captures + residuals + dispositions into a receipt (trimmed Appendix A schema:
   drop `verdict_case_file`, `taste_gates`, and `invariants` for v0 — those are
   real but not needed to prove the kernel works).

7. **`frf claim compile`** — the semantic non-bypass rule, implemented literally.
   Reads a receipt. If any residual in it has disposition `open`, `unknown`, or
   `harness`, it **refuses** to emit a positive claim and instead prints the
   non-claim boundary explicitly ("cannot claim X because residual Y is open").
   If all residuals are `fixed`, `intentional`, `environmental`, or
   `oracle_version`, it emits a single conservative sentence scoped exactly to
   the court's declared observable axes — never more.

This is the whole v0. Seven verbs. If you find yourself wanting an eighth before
these seven are rock solid, that's scope creep — write it down and don't build it.

## The golden-path acceptance test

Implement Section 12 of the paper as your integration test, verbatim in spirit:
two small CLI programs (a fake "reference" and a fake "candidate," maybe 20 lines
of shell or Rust each) that agree on everything except exit code (2 vs 1) and
first stderr line wording, for a malformed-input fixture. Running the full
pipeline against them must:

- produce two residuals (`cli-exit-*`, `cli-text-*`) with disposition `open`
- refuse a positive compatibility claim while they're open
- accept manual disposition of the exit residual as `fixed` (after you patch the
  candidate) and the text residual as `intentional` (documented rationale: clearer
  wording)
- then compile the exact bounded-claim shape from Section 12: scoped to the
  named authority version, fixture family, and court — and explicitly print the
  non-claim ("does not establish byte-identical stderr, full CLI compatibility,
  or a drop-in replacement claim")

If this test doesn't pass byte-for-byte in spirit, the tool doesn't ship.

## Non-goals for v0 — explicitly out of scope

State these in the README as deliberate exclusions, not gaps you forgot:

- Densors, densorial inference, tekmeric-inference framing — not needed for the
  mechanism to work; leave the philosophy in the paper, not the code.
- Taste Codex gates (representation, boundary quarantine, misuse resistance,
  performance grounding) — real and valuable, but a second milestone, not v0.
- Corpus admission, version ladders, environment matrices, independent-witness
  maps — scale features. v0 proves the kernel on one authority, one candidate,
  one fixture.
- Wire/timing/filesystem/state courts — v0 supports `exit` and `stderr` axes
  only. Adding axes should be a matter of writing a new comparator, not
  restructuring the core.
- Any GUI, dashboard, or metrics rollup — CLI and YAML files on disk only.
- Networked or remote authority admission — local executables only.

## Implementation constraints (quality bar)

You are Riaan's systems-programming background is Rust; build this as a Rust
crate/CLI (`frf` binary, e.g. `frf-rs`) unless there's a concrete reason not to.
Hold it to the standard of `programming-taste`: invariants stated before code,
no representable-but-forbidden states, no boolean-parameter APIs, the unsafe/
host-mutation surface (subprocess execution, file hashing) kept in a small
quarantined module, and the correct way to use the CLI shorter than the wrong way.

Specific rules:

- **Raw captures are immutable.** Once written to `captures/`, nothing rewrites
  them. Normalization, if you add it later, produces a new derived file next to
  the raw one — never in place.
- **No claim path may originate anywhere except `frf claim compile` reading a
  receipt.** There should be no code path, no flag, no shortcut that lets a
  human hand-author a positive claim string. Enforce the semantic non-bypass
  rule structurally, not by convention.
- **Every write is content-addressed or timestamped-and-hashed.** Authorities,
  fixtures, captures, and receipts all carry SHA-256 hashes of their content,
  because replayability is the entire point.
- **Disposition without reason is a compile error, not a lint.** Reject it at
  the type/API level if you can, at minimum at the CLI-argument level — never
  silently default to a disposition.
- **The tool's own claims about itself must obey its own rules.** The README
  may not say "compatible," "correct," or "production-ready" about the tool
  unless a receipt in the repo's own `frf/` self-application actually
  establishes it. Dogfood it on day one: run `frf` against its own test fixture
  and check the receipt in.

## Deliverables

1. A working `frf` CLI implementing the seven verbs above.
2. The golden-path fixture pair (reference + candidate scripts) and the
   resulting `authorities/`, `courts/`, `captures/`, `residuals/`, `receipts/`,
   `claims/` directory tree, checked into the repo as the canonical example —
   mirroring the layout in Section 19.3 of the paper.
3. A README that is *shorter* than this prompt: install, the one command that
   runs the golden path, and a link back to the paper for the theory. Do not
   re-explain FRF in the README — point to the source document.
4. An honest "Known Limitations" section listing every Non-Goal above plus
   anything else you cut, so the tool's own documentation practices what the
   framework preaches.

## Definition of done

A stranger clones the repo, runs one command, and within five minutes has
watched a real residual get created, refused a claim while it was open,
disposed it, and watched a bounded claim get compiled — with the exact
non-claim language from Section 12 printed alongside it. If that experience
isn't tight, nothing else in this brief matters yet.
