# Heartbleed (CVE-2014-0160) — the information-leak trajectory and the comparative claim

*Generated from the executed study — every number below is measured evidence,
not prose. Run `./reproduce.sh run` to regenerate the tree under
`evidence/`; run `./reproduce.sh verify` to re-derive it.*

## The semantic axis

The study does not compare bytes. The `memory.leak.sensitive` axis is served
by an external comparator (`comparators/heartbleed-leak.py`) that asks the
actual vulnerability question: *did the candidate's linked TLS library leak
process memory in response to the malformed heartbeat?* Three independent
signals are recognized (any one flags the leak):

1. the probe's verdict — exit 1 + `HEARTBLEED` on stderr;
2. a well-formed leak projection — `len>0` + a 64-hex SHA-256 commitment
   (the probe observed the echoed window and committed to it);
3. a known sensitive marker in the echoed content (`-----BEGIN RSA PRIVATE
   KEY-----`, `SECRET_KEY=`, …) — the seeded-leak challenge mutant's shape.

**RAW-MEMORY PUBLICATION BOUNDARY**: the probe (`src/hb.c`) NEVER writes the
echoed process memory to any observed stream. It plants a deterministic
synthetic canary in its own heap before the handshake, and on the leak path
hashes the exact echoed window (SHA-256) and reports ONE projection line:

```text
hb-leak-projection len=16384 sha256=<hex> canary=present fraction=0.99
```

The published evidence records "N bytes were returned, SHA-256 X, the
planted synthetic canary was [not] observed" — never arbitrary process
memory. The raw bytes exist transiently in the probe for the hash/scan and
are discarded. (The `strip-heap-noise` normalizer was retired with the raw
dump: the projection is pure text, so there are no address runs to mask.)

## The version lifecycle — one lineage, onset to cessation

The full CVE-2014-0160 series was built from the official OpenSSL tarballs
(1.0.1a through 1.0.1g; hashes pinned in `../build/build-manifest.json`) and
run as a candidate-revision series against the fixed reference authority
`ref-hb-1.0.1g`:

| revision | exit | observable surface on `memory.leak.sensitive` |
|---|---|---|
| 1.0.1a | 1 | `hb-leak-projection len=16384 sha256=… canary=present fraction=0.99` + `HEARTBLEED: …` |
| 1.0.1b | 1 | identical |
| 1.0.1c | 1 | identical |
| 1.0.1d | 1 | identical |
| 1.0.1e | 1 | identical |
| 1.0.1f | 1 | identical |
| 1.0.1g | 0 | `hb: no leak (malformed heartbeat silently discarded)` |

The engine's own classification over the 7-point series
(`evidence/trajectories/1e5f93cb…json`):

```text
axis memory.leak.sensitive, coordinate_system candidate_revision (x7)
drift = boundary-localized   slew = abrupt
localization = start         bands = 1
```

The vulnerability appears with the heartbeat feature (1.0.1a) and ceases
exactly at the fix release (1.0.1g): one band, abrupt boundary, no
recurrence — the historical lifecycle, measured, not asserted.

## The minimized trigger

`frf court minimize` routed the leak residual to the external minimizer
`leak-minimize` (`minimizers/heartbeat-length.py`), which reduced the
fixture's claimed payload length and the court verified the proposal with
the one comparison operation. The court-verified reproducer
(`evidence/objects/sha256/39c4402e…`) is:

```text
malformed 0x0FE9
```

**4073 bytes is the empirically minimal claimed payload length that yields
the observable leak on 1.0.1f.** Below it the vulnerable library constructs
the heartbeat response but never flushes it to the wire (the response-write
path re-enters the handshake state machine and abandons the small write), so
the probe observes "silently discarded". The boundary is deterministic
(swept 0x0FE1..0x0FF0: 0x0FE8 → no leak, 0x0FE9 → leak). The reduction
record `evidence/reductions/e23099d0…` binds the minimizer's semantic +
implementation identities and the content-addressed invocation evidence.

## The sensitivity proof (challenge before claim)

Before any "non-vulnerable" claim, the court was challenged with a seeded
leak: the mutation provider `seed-leak` (`mutations/seed-leak.py`) proposed
a mutant candidate dumping a PEM private-key header + `SECRET_KEY=12345`.
The challenge (`evidence/challenges/9ef00147…`) passed:

```text
operator seed-leak saw the seeded defect on memory.leak.sensitive and
nothing else — the court can see this defect class
```

The comparator is therefore not blind: a leak-shaped divergence is seen on
the axis it is claimed on, and only there.

## The claim

The claim compiled from the fixed release's receipt
(`evidence/claims/8b2fc1c4…json`), under the `sensitivity-backed` policy
(the challenge above is its backing):

> For reference `ref-hb-1.0.1g`, fixture family `heartbeat`, and environment
> x86_64-linux, candidate `cand-hb 1.0.1x` (sha256 65686b8a) **preserves
> memory.leak.sensitive behavior** for the heartbeat cases in court
> `heartbeat-leak-check`.

The claim is deliberately narrow: it asserts the semantic leak axis only,
with the Section-12 non-claims printed beside it ("This receipt does not
establish byte-identical stderr, full CLI compatibility, or a drop-in
replacement claim.").

## Reproducing

```sh
./reproduce.sh build   # hermetically rebuilds the 7 probe binaries (pinned container + official tarballs)
./reproduce.sh run     # regenerates evidence/ (admit -> courts -> series -> challenge -> minimize -> claim)
./reproduce.sh verify  # re-derives the evidence and checks every committed artifact hash
```

## The comparative statement

**1.0.1f**: a malformed heartbeat with a claimed 0x4000-byte payload drew a
16384-byte echo of process memory as a heartbeat response; the leak survived
every run of the series. The published evidence carries each echo as a
projection — length, SHA-256 commitment of the exact echoed window, and the
planted-canary observation (present, 0.99 of the window canary-consistent) —
never the raw process-memory bytes. **1.0.1g**: the same trigger was silently
discarded (RFC 6520 §4) — no response, no leak, exit 0. The divergence
between the two releases on the `memory.leak.sensitive` axis is the patch's
effect: 1.0.1g bounds the `memcpy` in the heartbeat handler against the
record length, so the claimed length can no longer reach past the record
into adjacent memory. The trajectory above maps exactly where that bound
appeared in the release history.
