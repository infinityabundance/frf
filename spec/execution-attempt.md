# Execution attempts — the refusal is itself evidence

Status: normative (0.1.64). Object `execution-attempt`, schema
`frf-execution-attempt-v1`, identity `FRF/EXECUTION-ATTEMPT/v1`.

## The missing object

A court observation attempt ends in one of two ways:

- **completed** — a run exists: a content-addressed capture is the durable
  graph root of everything the observation produced (residuals, receipts,
  claims);
- **refused** — the harness enforced a declared bound (stream overflow,
  timeout, produced-tree overflow) and, fail-closed, no capture is written.
  Until now the only durable trace of such an attempt was the content-
  addressed **harness event** (`harness/<id>.json`), named by the error
  message that surfaced the refusal.

That left a hole in the evidence graph: a failed observation attempt had no
root object. The harness event recorded *that a bound fired*, but nothing
bound together *which court*, *which exact artifacts*, *under what
execution contract*, *which side refused*, and *why* — the things that make
the refusal a portable, re-derivable observation rather than an incident in
an error message.

`ExecutionAttempt` is that object:

```
ExecutionAttempt
    ├── completed → Run            (a run IS the completed-attempt record;
    │                               no separate object exists for this arm)
    └── refused
          ├── harness_events       (content-addressed bound-firing records)
          ├── declared court       (id + semantic identity)
          ├── bound artifacts      (authority + candidate SHA-256)
          ├── fixture + argv       (exact inputs of the attempted observation)
          ├── execution contract   (profile + capture bounds AS ENFORCED)
          ├── side                 (reference | candidate)
          └── refusal_reason       (kind + detail)
```

Because the completed arm *is* a run (the capture), the record exists
exactly where the run cannot. Its `kind` is always `"refused"` in this
schema version.

## The record

Stored content-addressed under `attempts/<id>.json`, canonical JSON (like
receipts — strict, duplicates refused, bytes == JCS):

```json
{
  "schema_version": "frf-execution-attempt-v1",
  "id": "<FRF/EXECUTION-ATTEMPT/v1 digest>",
  "kind": "refused",
  "court": "<court id>",
  "court_semantic_identity": "<FRF/COURT/v2 digest>",
  "authority_sha256": "<hex>",
  "candidate_sha256": "<hex>",
  "fixture_sha256": "<hex>",
  "arguments": ["...", "..."],
  "environment_digest": "<FRF/ENVIRONMENT/v2 digest>",
  "execution_profile": "frf-exec-linux-v1",
  "capture_bounds": { "...": "as enforced ..." },
  "side": "reference",
  "harness_events": ["<harness event id>"],
  "refusal_reason": {
    "kind": "timeout",
    "detail": "<the refusing error>"
  }
}
```

### Identity

`FRF/EXECUTION-ATTEMPT/v1` over the canonical document of the record's own
fields minus the `id`:

```
court, court_semantic_identity, authority_sha256, candidate_sha256,
fixture_sha256, arguments, environment_digest, execution_profile,
capture_bounds, side, harness_events (SORTED), refusal_reason
```

The cited harness events enter **sorted**: the identity is a deterministic
function of the cited *set*, so two attempts that recorded the same bound
firings in a different order are the same attempt. The `capture_bounds` are
the **effective** bounds as enforced (including any `FRF_EXEC_*` overrides
in force) — the same discipline as the run identity: an observation is made
under a declared harness contract, and the identity commits that contract.
Two executions that differ only in the enforced bounds are different
attempts even when their outputs would have been identical.

### When it is written

`court run` writes the attempt record at each harness-refusal exit point —
after the harness event is recorded, before the refusal is propagated:

- the reference side's execution refuses (stream overflow / timeout);
- the reference side's produced-tree capture refuses;
- the candidate side's execution refuses;
- the candidate side's produced-tree capture refuses.

A refusal **without** an enforced bound (a missing OCI runtime, an exec
failure) is an environmental/local failure of the harness itself, not a
bounded observation attempt: no harness event exists, and no attempt record
is written. The record's scope is exactly the scope of the harness events
it binds.

### Verification

`load_execution_attempt_verified` (engine) and the independent verifiers
(xtask, Go) prove, before the record may be consumed:

1. the document is canonical evidence (strict JSON, duplicates refused,
   bytes == JCS);
2. the `id` rederives from the record's own fields;
3. `kind == "refused"` (a completed attempt IS a run);
4. every cited harness event exists, is canonical and self-authenticating
   (its own id rederives), and belongs to the **same court** — an attempt
   citing missing, corrupt, or foreign enforcement evidence is not
   self-consistent.

## Portability

A refusal is as portable as the observation that would have been captured:

- the record and its harness events are **immutable** (write-once, identity
  rederives on every read — a re-run of the same refused observation
  reproduces the same attempt id and the write is idempotent);
- a receipt-rooted bundle additionally carries **every refused attempt
  recorded for the root receipt's court**, with its harness events — the
  court's refusal history travels with its positive evidence;
- every verifier in the conformance triangle (Rust engine, Rust xtask, Go)
  verifies attempts byte-for-byte against the same identity rule.

This makes the reviewer's requirement mechanical: failure to obtain an
observation is a first-class portable observation about the attempt, not an
event id surfaced primarily through an error message.
