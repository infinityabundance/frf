# Execution profiles and reproduction policy

An observation is made under a **declared harness contract**, never under an
implicit one. The reference engine executes every side — authority,
candidate, external comparator — under the same reference execution profile,
and the exact parameters that applied are recorded at observation time
(`execution_profile` + `capture_bounds` in the capture and in every receipt
derived from it). A receipt therefore never guesses what the harness
enforced, and replay can require the same contract instead of hoping for it.

This document separates two questions that must not be conflated:

- **The harness contract**: what the engine promises to do while executing
  a side (bounds, termination policy, capture semantics).
- **The reproduction policy**: what a replay is allowed to require of the
  current host (same machinery, or merely the same bounded observation).

## Execution profiles

A profile names a normative execution contract. The reference engine
implements one profile today:

| Profile            | Meaning                                                    |
| ------------------ | ---------------------------------------------------------- |
| `frf-exec-linux-v1`| Direct-exec Linux process capture (the reference profile)  |
| `frf-exec-linux-v2`| The cgroup v2 per-side AGGREGATE envelope on top of v1     |

A profile defines exactly what its engine records and enforces:
argv, stdin policy, working directory, environment, locale, timezone,
umask, timeout semantics, stream capture semantics, resource limits,
process topology, and termination policy. Profiles are protocol
identifiers (`ObservableId` grammar); an engine that implements a different
profile declares it, and exact replay across profiles is refused.

A court DECLARES its profile in the manifest (`court.execution_profile`;
absent = the reference profile). Everything the run executes — the sides
AND every extension program (comparator, normalizer, capture adapter,
minimizer, mutation provider) — runs under the declared profile, and the
capture records it. A declared profile is ENFORCED, never approximated.

## `frf-exec-linux-v1` — the reference profile

Every side runs as a direct child of the harness: **no shell** is involved
in execution (the captured argv is passed to `execve(2)` on the sealed
image). Each side lives in its own process group; when the direct process
exits, times out, or overflows a stream cap, the **entire group** is
terminated, so a descendant cannot hold the capture pipes open past the
direct process.

### Sealed-image execution (the verify→execute race is closed)

An executable image is bound to its verified bytes **at execution time**:

```text
read artifact bytes → verify CID → memfd_create → copy →
F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL →
execute /proc/self/fd/<n>
```

No pathname whose contents were verified earlier is ever re-opened for
execution — the bytes that were hashed are the bytes that exec. After
sealing, **no process, not even the same OS user**, can alter the image;
the seals are read back (`F_GET_SEALS`) before the image may be executed.
This closes the same-OS-user verify→execute race for the executed image.

Two declared properties follow from the mechanism:

- **Native (ELF) images keep their `argv[0]`**: the harness sets argv[0]
  to the materialized snapshot path, so a binary observes the same
  program name as a path-based execution.
- **Scripts observe their image path as `$0`**: the kernel executes a
  shebang script via its exec path, so a script's `$0` is
  `/proc/self/fd/<n>` (the sealed image), never an `objects/sha256/`
  path. The captured argv (the arguments after the program name) is
  unchanged, and the interpreter chain is bound from the artifact bytes.
  A script whose behavior depends on `$0` is therefore observed under
  the profile's declared mechanism, and FRF's own generated
  instrumentation never depends on `$0` (the court-challenge mutant
  wrapper resolves the reference from the fixture argument).

Data files (fixtures) remain path-based: the recorded argv is part of the
run identity, and the content-addressed object CAS plus `0444`/`0555`
permissions plus re-hashing on every use are the data discipline. Sealing
is for the executed **image**.

## `frf-exec-linux-v2` — the cgroup v2 per-side aggregate envelope

The setrlimit layer bounds ONE process each (`RLIMIT_AS`, `RLIMIT_CPU`) and
`RLIMIT_NPROC` bounds the processes of the side's real USER ID — a hostile
tree distributes memory or CPU over descendants, and the per-UID process
cap is shared with every other process of the same user. The v2 profile
bounds the side's WHOLE descendant tree in its own cgroup:

```text
pids.max    the per-side, per-tree process-count envelope
memory.max  the per-side, per-tree memory envelope (aggregate)
cpu.max     the per-side, per-tree CPU quota (aggregate)
```

- Each side (and each extension program) gets its own group under a
  writable cgroup v2 root, created BEFORE the spawn.
- The side moves ITSELF into its group in `pre_exec` (before `execve(2)`),
  writing its own pid to the inherited `cgroup.procs` — race-free:
  descendants inherit the cgroup at fork, so the envelope covers the whole
  tree, not just the direct process. A failed move refuses the exec.
- The setrlimit layer remains in force underneath the envelope (a second
  layer, per the design).
- The group is removed when the side is reaped; nothing lingers.
- The capture records the envelope under `capture_bounds` (`cgroup_pids_max`
  / `cgroup_memory_max` / `cgroup_cpu_max`, receipt schema v16), so exact
  replay requires the same envelope and the receipt never guesses it.

**Delegation is required.** cgroupfs is only writable where the manager
delegated it: a systemd user session with `Delegate=`, a container with a
writable `/sys/fs/cgroup`, or a delegated subtree. The harness locates a
writable cgroup v2 root (`/sys/fs/cgroup` itself, or the deepest writable
ancestor of the process's own cgroup path) and **REFUSES** the profile when
none exists — a declared profile is enforced, never approximated, so a
silent downgrade can never record a contract the harness did not enforce.
The reference profile remains `frf-exec-linux-v1`; `high-assurance` claim
admission requires it.

### Capture bounds (the parameters that actually applied)

| Parameter            | Default      | Meaning                                             |
| -------------------- | ------------ | --------------------------------------------------- |
| `timeout_ms`         | `60000`      | Wall-clock budget per side; expiry kills the group  |
| `max_stream_bytes`   | `16777216`   | Per-stream (stdout/stderr) capture cap in bytes     |
| `rlimit_as_mb`       | `2048`       | Address-space limit per side (`RLIMIT_AS`)          |
| `rlimit_cpu_s`       | `30`         | CPU-time limit per side (`RLIMIT_CPU`)              |
| `rlimit_nofile`      | `1024`       | Open-file limit per side (`RLIMIT_NOFILE`)          |
| `rlimit_nproc`       | `4096`       | Process-count limit per side (`RLIMIT_NPROC`, v15)  |

The defaults are overridable through test hooks (`FRF_EXEC_TIMEOUT_MS`,
`FRF_EXEC_MAX_BYTES`, `FRF_EXEC_RLIMIT_AS_MB`, `FRF_EXEC_RLIMIT_CPU_S`,
`FRF_EXEC_RLIMIT_NOFILE`, `FRF_EXEC_RLIMIT_NPROC`) used by the regression
suite; whatever bounds applied are what the capture records.

### Overflow is refusal, never truncation

A side that exceeds `max_stream_bytes` on either stream is killed and the
run is **REFUSED**: the truncated bytes are never recorded, hashed, or
turned into evidence. An evidentiary `overflow` result is the honest outcome
of a hostile or pathological side; a silently truncated stream would be a
forged observation.

### Resource limits

On Linux, the child applies its resource limits in `pre_exec` (after
`fork(2)`, before `execve(2)`): `RLIMIT_AS`, `RLIMIT_CPU`, and
`RLIMIT_NOFILE` are set to the profile's values. A side that hits a limit
dies by the kernel's signal outcome — the capture records the signal. The
exact signal is kernel-dependent (`SIGXCPU` while a soft limit is in force,
`SIGKILL` once it is crossed with hard == soft); the property is that the
resource bound terminates the side before the wall-clock timeout.

### Process topology

- one process group per side (its leader is the side itself)
- group termination on exit, timeout, or overflow
- concurrent pipe draining with a bounded spawn-retry budget
  (`ETXTBSY` retries never hang the court)
- stdin: piped when a fixture provides bytes, else `/dev/null`

### What the engine records

Per side: exit status (or terminating signal), full stdout and stderr
bytes, SHA-256 of each stream, and the first line of each stream (the
built-in `stderr`/`stdout` comparators' surface). The interpreter chain
(kernel interpreter, shebang argument bytes, env resolver with PATH digest,
downstream interpreter) is recorded for every script artifact, so a changed
`/usr/bin/env` or downstream interpreter is visible to exact replay even
when the kernel is unchanged.

## The reproduction policies

`frf replay RUN_ID | RECEIPT_ID --policy exact|semantic`:

### exact (default)

> Did essentially the same execution reproduce?

Exact replay requires:

- the same execution profile and the same applied capture bounds;
- the same environment digest (os, arch, kernel, locale, timezone, umask);
- the same working directory;
- every artifact's interpreter chain re-resolving to the recorded
  identities (kernel interpreter, downstream interpreter, shebang
  arguments, env resolver, PATH digest);
- the same observations, byte for byte.

Any provenance drift **REFUSES** the replay. An exact reproduction under
changed machinery is never silently called "the same execution".

### semantic

> Did independent or changed machinery reproduce the same bounded
> observation?

Semantic replay requires:

- the same court question (the semantic identity is recomputed and must
  match);
- the same authority and candidate artifacts (verified snapshots);
- the same observations, byte for byte;

while provenance differences — environment, interpreter chains, profile,
bounds — are **admitted but always reported** to stderr, and the final
reproduction line counts them, so a semantic reproduction is never
confusable with an exact one.

The policies are declared, never implicit: the receipt records the profile
and bounds it was observed under, replay defaults to the strictest policy,
and the looser policy is opt-in and self-reporting.
