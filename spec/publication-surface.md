# Publication-safe capture — the capture surface

FRF distinguishes **observation bytes retained locally** from **observation
bytes publishable**. Every observed stream has a publication disposition —
its **capture-surface policy** — declared by the court at OBSERVATION time
and recorded in the capture. The publication transform honors the declared
policies; the verifier reports the resulting stream closure. This is a
GENERAL capability (not a Heartbleed special case): it is what lets FRF
publish an evidence graph and content identities for proprietary binaries,
confidential test data, malware samples, private customer inputs, medical
datasets, and huge artifacts — without redistributing the observation bytes
themselves.

## 1. The policy vocabulary

A court manifest may declare a `capture_surface:` list; each entry names one
observed stream and its policy:

```yaml
capture_surface:
  - side: candidate
    stream: stdout
    policy: synthetic-publication
  - side: reference
    stream: stdout
    policy: inline
```

The vocabulary is CLOSED (an unknown policy is a refused manifest, never a
silently mislabeled publication):

- `inline` — the bytes are publishable as-is (safe text). The default for
  every stream with no declaration.
- `hash-only` — only the SHA-256 is publishable; the bytes stay local. The
  publication transform WITHHOLDS the bytes and writes a disposition record
  (`captures/<run>/<side>.<stream>.pub.json`,
  `frf-stream-publication-v1`) naming the withheld bytes' identity and the
  policy. A verifier finding a declared non-publishable stream ABSENT must
  find exactly that record; missing or mismatched, the tree is refused — a
  withheld stream cannot silently disappear.
- `redacted-with-commitment` — the published bytes are a REDACTED
  representative carrying a commitment (e.g. a redaction that preserves a
  deterministic marker). The policy declares the redaction contract; the
  bytes publish as-is.
- `detached` — the bytes are external, reconstructable from a recipe. The
  transform withholds them like `hash-only`.
- `synthetic-publication` — the published bytes are a SAFE SYNTHETIC
  representative (e.g. a projection line), never the raw observation. The
  Heartbleed probe's `hb-leak-projection` line is exactly this: length +
  SHA-256 commitment + planted-canary observation, printed instead of the
  echoed process memory.

## 2. The observation contract

The declarations are part of the OBSERVATION: they are recorded in the
capture (`capture.json`, `publication_surface`) and entered into the
observation identity (`FRF/OBSERVATION/v1`) when present. A tampered
surface — e.g. flipping `hash-only` to `inline` so bytes can be republished
— breaks the identity rederivation and refuses the capture. Captures from
before the capability (no declaration) rederive identically: absent means
every stream is `inline`.

## 3. The publication transform

`publish-detached` is a pure function of (complete local tree, policy). It
copies the tree, withholds the declared objects, and then applies the
capture surfaces:

- `hash-only` / `detached` streams are withheld — the copied bytes are
  removed and a `frf-stream-publication-v1` disposition record is written
  where they used to live;
- every stream of every run is recorded in `publication-manifest.json`
  (`frf-publication-manifest-v1`, sorted, deterministic): side, stream,
  effective policy, SHA-256, and whether the bytes traveled. The manifest is
  the EXPLICIT record of the transform — nothing is silently altered.

## 3.1 The manifest is a proof-derived transform record

The publication manifest is not merely valid — it is the transform's
PROOF-DERIVED RECORD. Verification (`load_publication_manifest_verified`,
run by `evidence status` and the whole-store walk) rederives the expected
manifest as a pure function of

1. every VERIFIED capture in the publication (the run's streams and their
   recorded SHA-256s);
2. every capture-surface declaration (each stream's effective policy, or
   `inline` when none is declared);
3. the ACTUAL publication tree (a stream's `published` flag is the tree's
   own state: its bytes exist, or a withholding disposition record took
   their place — the verified capture loader has already proved that
   combination is exactly the declared policy's),

and requires EXACT EQUALITY with the recorded manifest, reporting the
first differing stream. A manifest entry whose policy, hash, or
publication state lies — or that invents or drops a stream — is refused:
the manifest is a projection of the evidence, not a document that may say
whatever its writer wished.

## 4. Verification

`evidence status` reports the whole-store graph verdict (every protocol-object
namespace, not just the receipt/capture roots) plus the stream closure:
`stream_closure: complete` when every observed stream is published as-is, or
`incomplete-by-policy (N withheld stream(s); identities + dispositions
published, bytes local)` when the surface withheld streams. `replay_ready`
requires the stream closure complete alongside the object closure;
`replay_verified` stays `not-performed` until an actual replay succeeds.
`load_capture_verified` is surface-aware: present bytes must derive the
recorded hashes; withheld bytes are authenticated by their disposition
record. Replay of a withheld stream is only possible after hydrating the
bytes (the disposition record names what must be rebuilt), mirroring the
detached-object model.
