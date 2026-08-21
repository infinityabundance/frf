# Produced artifacts — the filesystem-tree surface

A CLI court observes what its sides PRINT. A produced-artifact court
observes what its sides BUILD. When a court declares `produce`, each side
writes its output tree to the declared path and the harness captures it
immutably: every produced file is copied under the run directory, hashed,
and recorded in the side capture as a canonical manifest. The
`filesystem.tree` axis is the built-in comparator over that surface.

## The clause

```yaml
court:
  ...
  fixture:
    id: tree-spec.conf
    path: frf/courts/fs-tree-build/fixtures/tree-spec.conf
    arguments: ["--spec", "{fixture}", "--out", "{output}"]
  admissibility_envelope:
    observables: [filesystem.tree]
  produce:
    path: golden/work/tree-out/
```

- `produce.path` is the output root each side writes — working-directory
  relative (under replay: relative to the reconstructed invocation root),
  contained (no absolute path, no `..`).
- `{output}` in the fixture arguments substitutes to that path; both sides
  receive the same argv. The sides run SEQUENTIALLY: the harness clears the
  transient path before each side, walks it after, and clears it again, so
  the produce path is never evidence — the captured copies under the run
  are.
- A side that produces nothing (absent output) is an empty observation, not
  an error.
- The walk refuses symlinks (a side cannot smuggle a link outside its
  output), non-regular files, and escaped paths. Directories are not
  recorded: a tree with the same files is the same tree.

## The observation

The capture records, per side, a `produced` block (`frf-produced-v1`):

```yaml
produced:
  schema_version: frf-produced-v1
  manifest_sha256: <sha256 of the canonical manifest>
  files:                    # sorted by path
    - path: src/main.c
      sha256: <64 hex>
      executable: false
```

The manifest is ONE canonical formula (RFC 8785 JSON over
`{schema_version, files: [{path, sha256, executable}]}`), shared by the
reference engine and the independent verifier, so the tree observation
rederives cross-language from the captured files alone. The raw files are
copied under `captures/<run>/produced/<side>/` and rehashed by
verification.

The produced trees enter the RUN IDENTITY (the side capture is part of the
`FRF/RUN/v1` preimage): a run binds what its sides BUILT.

## The comparator

The built-in `filesystem.tree` comparator (registry: `{relation: eq,
extractor: produced-tree, residual_classifier: text}`) diffs the produced
manifests and yields ONE residual per differing file, surfaced by path:

| Divergence                     | surface          | raw projections           |
| ------------------------------ | ---------------- | ------------------------- |
| content differs                | `path:<rel>`     | the two content hashes    |
| exists on the reference only   | `path:<rel>`     | reference hash, `<absent>`|
| exists on the candidate only   | `path:<rel>`     | `<absent>`, candidate hash|

A court declaring the `filesystem.tree` axis MUST declare `produce` (else it
would compare two empty trees — refused, never pretended). External
comparators on a produced court receive the manifests in the request's
`context.produced` block (raw-file access is a future extension).

## The pipeline

Everything downstream is the ordinary pipeline: the residuals get κ tokens,
receipts emit, open residuals block claims, replay re-executes the sides
(which re-write their trees) and re-captures them byte-for-byte, and the
bundle closure carries the produced files so verification rehashes the
trees without executing anything.
