# The detached-object declaration — `frf-detached-objects-v1`

A publication may deliberately withhold the BYTES of some content addresses
(security-sensitive executables, export-controlled or confidential
artifacts, huge payloads) while publishing the evidence graph that
references them. This declaration makes that choice explicit and mechanical:
every withheld CID is attested as intentionally unavailable, with its role,
publication status, size, and the reconstruction recipe that reproduces the
exact bytes.

The declaration lives at the evidence root as `detached-objects.json`:

```json
{
  "schema_version": "frf-detached-objects-v1",
  "policy": "detached",
  "objects": [
    {
      "cid": "1fa728ceb86abab91de36f044e798e8631fbd672676c0cce8992889ef3bbeb77",
      "role": "authority-artifact",
      "publication": "external-security-sensitive",
      "size": "1911808",
      "reconstruction": {
        "recipe": "external-corpus/v3/build/build-all.sh: the pinned-NEVRA container builds the probe against the official OpenSSL 1.0.1g tarball (SHA-256-pinned in build-manifest.json)",
        "source_path": "heartbleed/builds/hb-1.0.1g"
      }
    }
  ]
}
```

Canonical-JSON rules apply like every evidence document (RFC 8785; the value
domain is strings/arrays/booleans/null only — `size` is therefore a decimal
STRING, never a JSON number).

## Verification: four states, mechanically distinguished

| state | meaning |
|---|---|
| `graph_verified` | EVERY protocol-object namespace parses and verifies through its verified loader: every canonical document parses, every identity rederives, and every referenced content address RESOLVES — its bytes are present AND verified, OR it is declared detached here with a reconstruction recipe |
| `object_closure_complete` | every referenced CID's bytes are present in the store |
| `replay_ready` | the object AND stream closures are complete: the bytes a replay would execute are materialized and verified |
| `replay_verified` | an ACTUAL replay operation has re-executed the observation and reproduced it. A complete object store does NOT prove the current machine can satisfy the execution profile, OCI runtime, interpreter/native-runtime closure, kernel facilities, cgroup requirements, or Landlock requirements — `evidence status` therefore reports `not-performed` until `frf replay` succeeds |

A declared-detached CID is NEVER treated as corruption: the graph verifies,
the closure reports exactly what is withheld and how to rebuild it, and
replay refuses until the bytes are materialized locally and verified against
the declared CID. `frf evidence status` reports all four states; a detached
study prints "graph_verified: yes / object_closure: incomplete-by-policy (N
declared-detached payloads) / replay_ready: no / replay_verified:
not-performed".

## Hydration

A reviewer who needs the full closure:

1. runs each declared `reconstruction.recipe` (or fetches the bytes from a
   trusted source named by `source_path`);
2. hashes the materialized bytes; they MUST equal the declared `cid` (a
   mismatch is refused — the object would not be the same evidence);
3. places them at the content-addressed path (`objects/sha256/<cid>`, or the
   declared record `path`).

After hydration the closure is complete and replay is available. The
declaration itself never changes: hydrated bytes join the store; the
publication's declaration remains the record of what was withheld.

## Roles

`role` matches the evidence references the payload served:
`authority-artifact`, `candidate-artifact`, `fixture-object`,
`comparator-implementation`, `normalizer-implementation`,
`adapter-implementation`, `minimizer-implementation`, `mutation-request`,
`execution-context`, …

## Refusals

- a malformed declaration (bad schema version, duplicate cid, non-64-hex
  cid, empty role/publication/recipe) is refused — the publication cannot
  silently hide a payload;
- a missing object that is NOT declared detached is an incomplete or corrupt
  publication and is refused at verification;
- a declared-detached payload that must actually EXECUTE (replay,
  comparator invocation) is refused with "hydrate first" — a detached
  closure is never silently executed.
