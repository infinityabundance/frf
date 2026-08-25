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
implements these profiles:

| Profile            | Meaning                                                    |
| ------------------ | ---------------------------------------------------------- |
| `frf-exec-linux-v1`| Direct-exec Linux process capture (the reference profile)  |
| `frf-exec-linux-v2`| The cgroup v2 per-side AGGREGATE envelope on top of v1     |
| `frf-exec-linux-v3`| The filesystem/ambient-channel CLOSURE envelope on top of v2 (§ `frf-exec-linux-v3`) |
| `frf-exec-oci`     | The side runs inside a digest-pinned OCI container (a complete root filesystem) (§ `frf-exec-oci`) |

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

### Streaming stream capture

Capture is STREAMING: stdout/stderr are drained incrementally (concurrently
with the wait loop), with the stream length, the first line, and the
SHA-256 computed on the fly. A stream at or below the in-memory threshold
is kept inline; a larger stream SPILLS to a temp file as it is read, so
harness memory is bounded to the threshold + one read chunk regardless of
the stream's size — a very large output (a raised capture cap) does not
buffer the whole stream in RAM, and the evidence files are written by
streaming from the same source. The evidence invariants are unchanged:
overflow still kills the group and REFUSES the run (truncated output is
never evidence), and the recorded digest + first line derive from the exact
bytes.

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
- **The group is KILLED, not merely bounded** — the v2 termination policy.
  The side's direct process is reaped; then the harness writes `1` to
  `cgroup.kill` (kernel >= 5.14), terminating every remaining member of the
  side's tree — including a descendant that escaped the process group via
  `setsid()` (the v1 group-kill cannot reach it, but it is still IN the
  side's cgroup). The harness then waits for `cgroup.events` to report
  `populated 0` (bounded); on a kernel without `cgroup.kill` it enumerates
  `cgroup.procs` and SIGKILLs each member until the group is empty. The
  harness is a child subreaper (`PR_SET_CHILD_SUBREAPER`), so the side's
  orphaned descendants reparent to it and are reaped in the wait loop — a
  container whose pid 1 never reaps cannot leave a zombie holding the group
  populated forever.
- **A group that cannot be emptied within the budget is a run REFUSAL**, not
  ignored cleanup (an uninterruptible D-state member that survives SIGKILL
  is the honest failure mode). The v2 property is therefore mechanical:
  **no descendant of the observed side remains alive after the observation
  is finalized** — the cgroup is removed only after it reports empty, and
  only then is the evidence emitted.
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

## Assurance capabilities — the orthogonal model

Execution profiles do NOT form a simple "v1 < v2 < v3 < OCI" ladder: each
adds materially different machinery. What an observation actually
guarantees is a set of orthogonal CAPABILITIES, and admission policies
reason over CAPABILITY SETS, never over a profile-name equality:

| Capability | Meaning |
|---|---|
| `exact_capture_contract` | The observation was made under the EXACT capture contract (reference capture bounds, byte-exact streams, exact-replay semantics); an `FRF_EXEC_*` override can never redefine the reference bounds |
| `sealed_executable_image` | The side executed the SEALED verified bytes (memfd sealed F_SEAL_WRITE\|GROW\|SHRINK\|SEAL) — verify→execute race closed |
| `descendant_resource_envelope` | The side's whole descendant tree ran inside a per-side aggregate resource envelope (cgroup v2 pids/memory/cpu) |
| `io_world_closed` | The side's world was closed before it ran a single instruction (filesystem closure + ambient-channel closure: no network, no Unix sockets, no shared memory, no ptrace) |
| `rootfs_content_bound` | The side ran inside a complete root filesystem bound by content (the digest-pinned OCI image) |
| `native_runtime_closure_bound` | The side's native runtime closure was bound at observation time (dynamic loader + resolved dependency hashes) |

Every profile provides the REFERENCE contract
(`exact_capture_contract`, `sealed_executable_image`,
`native_runtime_closure_bound`); the later profiles ADD mechanisms. The
`high-assurance` claim policy requires exactly the reference set — an
observation made under v2/v3/OCI (a superset provider) qualifies exactly
like a v1 one. A claim records its `required_capabilities`, so the
requirement rederives from the claim alone.

## `frf-exec-oci` — the containerized side (0.1.62)

Where the declared execution-context closure (frf-execution-context-v1)
binds the runtime machinery artifact by artifact, the OCI profile binds the
WHOLE root filesystem: each side runs inside a container spawned from a
digest-pinned OCI image. The image is the complete execution machinery —
the interpreter, the shared libraries, the loader configuration, the
certificates — bound by its manifest digest in the execution identity. A
court declares:

```yaml
court:
  execution_profile: frf-exec-oci
  # The image reference MUST carry its manifest digest — the image is
  # content-addressed machinery; a mutable tag is refused.
  execution_image: docker.io/library/busybox@sha256:73aaf090…
```

- The runtime (`podman` or `docker`) must be present AND must resolve the
exact image: `image inspect <reference-with-digest>` must succeed. A missing
runtime or a missing image **REFUSES** the run — the image is never
silently substituted (this is the same enforced-never-approximated rule as
the v2 cgroup delegation).
- The side runs as the container command: the container executes the
MATERIALIZED snapshot path (argv[0] — the path the observation sees), never
the sealed memfd path (`/proc/self/fd/<n>` is a host descriptor, invisible
inside the container). The working directory is bind-mounted at its own
absolute path, so the side's recorded root-relative argv (the materialized
object path, the fixture, the produce path) resolves inside the container
exactly as it does on the host; produced trees are captured from the mount
after the container exits.
- The container runs with no network, the DECLARED environment, and is
removed on exit (`--rm`). The capture discipline — drain, timeout, stream
overflow refusal — is identical to the reference profile; the harness
event records apply unchanged.
- The capture records the image identity (`container_image`: reference,
digest, runtime + version at observation time), and the execution identity
commits it: an observation inside the image is NOT the same execution as
the same sides on the host, and exact replay re-runs inside the same image.
- EXTENSIONS are harness-side instrumentation, not the observed software:
under the OCI profile they run on the HOST under the reference capture
discipline (their invocation evidence records the host execution honestly).
- An OCI observation is a different execution contract from a v1 one; both
qualify for `high-assurance` claim admission when they provide the required
capability set (the reference contract — see § assurance capabilities).

### Capture bounds (the parameters that actually applied)

| Parameter            | Default      | Meaning                                             |
| -------------------- | ------------ | --------------------------------------------------- |
| `timeout_ms`         | `60000`      | Wall-clock budget per side; expiry kills the group  |
| `max_stream_bytes`   | `16777216`   | Per-stream (stdout/stderr) capture cap in bytes     |
| `produced_max_files` | `4096`       | Max files in a side's produced tree (v19)           |
| `produced_max_bytes` | `268435456`  | Max TOTAL bytes of a side's produced tree (v19)     |
| `produced_max_file_bytes` | `16777216` | Max bytes of any ONE produced file (v19)       |
| `rlimit_as_mb`       | `2048`       | Address-space limit per side (`RLIMIT_AS`)          |
| `rlimit_cpu_s`       | `30`         | CPU-time limit per side (`RLIMIT_CPU`)              |
| `rlimit_nofile`      | `1024`       | Open-file limit per side (`RLIMIT_NOFILE`)          |
| `rlimit_nproc`       | `4096`       | Process-count limit per side (`RLIMIT_NPROC`, v15)  |

The defaults are overridable through test hooks (`FRF_EXEC_TIMEOUT_MS`,
`FRF_EXEC_MAX_BYTES`, `FRF_EXEC_PRODUCED_MAX_FILES`,
`FRF_EXEC_PRODUCED_MAX_BYTES`, `FRF_EXEC_PRODUCED_MAX_FILE_BYTES`,
`FRF_EXEC_RLIMIT_AS_MB`, `FRF_EXEC_RLIMIT_CPU_S`,
`FRF_EXEC_RLIMIT_NOFILE`, `FRF_EXEC_RLIMIT_NPROC`) used by the regression
suite; whatever bounds applied are what the capture records.

### Overflow is refusal, never truncation

A side that exceeds `max_stream_bytes` on either stream is killed and the
run is **REFUSED**: the truncated bytes are never recorded, hashed, or
turned into evidence. An evidentiary `overflow` result is the honest outcome
of a hostile or pathological side; a silently truncated stream would be a
forged observation.

The **produced-tree caps** (v19) extend the same rule to the
filesystem-tree surface: a side whose produced tree exceeds
`produced_max_files`, `produced_max_bytes`, or `produced_max_file_bytes`
is refused exactly like a stream overflow — never truncated, never
partially recorded — and the enforced caps are part of the recorded harness
contract, so replay enforces the same bounds.

### Harness events — the refusal is itself evidence

When a declared bound fires, the harness writes a **content-addressed
harness event** (`harness/<id>.json`, `frf-harness-event-v1`, identity
`FRF/HARNESS-EVENT/v1` over the event's own fields plus the enforcing
runner hash) recording the side, the bound that fired (`stdout` | `stderr`
| `wall` | `cpu` | `produced-files` | `produced-bytes` |
`produced-file-bytes`), the declared cap as enforced, the observed value,
the court, the execution profile, and the runner. The run is still refused
where the rule says refuse — but the refusal is now provable, immutable
(identity rederives on every read), and citable.

- A bound that **refuses** the run (stream overflow, timeout, produced
  overflow) leaves no run to bind to: the event is **court-scoped refusal
  evidence**, named by the refusal message.
- A bound that **completes as a valid side outcome** (the CPU limit's
  SIGXCPU) is recorded ALONGSIDE the observation, cited by the run's
  capture (`harness_events`, capture schema v15), verified with the
  capture, and carried by the run's bundle.

### Resource limits

On Linux, the child applies its resource limits in `pre_exec` (after
`fork(2)`, before `execve(2)`): `RLIMIT_AS`, `RLIMIT_CPU`, and
`RLIMIT_NOFILE` are set to the profile's values, and `RLIMIT_NPROC` to the
profile's process-count cap. The CPU limit is applied as soft = the declared
cap and hard = cap + a bounded escalation window (v19): the profile's
deterministic outcome — `SIGXCPU`, whose default disposition terminates the
side — is the signal the kernel actually delivers, and a side that catches
or blocks SIGXCPU is still SIGKILLed once it burns the escalation window.
The capture records the terminating signal, and a resource-limit signal
completes as a valid observation whose harness event accompanies it.

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

## `frf-exec-linux-v3` — the I/O-closed side (0.1.65)

On top of the reference setrlimit layer, the side's WORLD is closed before
it runs a single instruction. Two kernel mechanisms, both installed in the
child before exec (fail-closed: a side that could not be closed never runs):

- **the filesystem closure — Landlock** (Linux ≥ 5.13, unprivileged with
  `no_new_privs`). The side may read/execute ONLY:
  - the content-addressed objects directory (`objects/sha256/`) — every
    object there is a DECLARED, verified artifact: the side's own snapshot,
    the fixture, the context artifacts;
  - the execution machinery: the interpreter chain (and the interpreter's
    OWN native closure — a script's machinery is its interpreter PLUS
    bash→libc, libdl, …), the artifact's native runtime closure (the
    dynamic loader + the resolved `DT_NEEDED` closure), and the declared
    execution-context artifacts;
  - the declared randomness channel (`/dev/urandom`) and the null device;
  - the produced-output staging directory — the ONLY writable surface
    (a court with no `produce` clause grants NO writable surface at all).
  Everything else on the host — `/etc/passwd`, `/proc`, the court
  manifests, other users' files — is `EACCES`.
- **the ambient-channel closure — seccomp** (BPF). `socket` (every address
  family, including `AF_UNIX`), `connect`, `bind`, `listen`, `accept`,
  `accept4`, SysV shared memory (`shmget`/`shmctl`/`shmat`/`shmdt`),
  `ptrace`, and `process_vm_readv`/`process_vm_writev` return `EPERM`: no
  network, no Unix sockets, no shared memory, no cross-process inspection.

A side that violates a closure does not crash the harness: the access is
denied and the court OBSERVES the denial like any other output divergence
(the candidate's exit/stderr carry the failed access and the run records
residuals against the reference — never a silent pass).

### The execution-mechanism tradeoff (empirically established)

The reference profile executes the side from a SEALED MEMFD
(`/proc/self/fd/<n>`) to close the same-UID verify→execute race. Under a
Landlock filesystem closure that is impossible: the kernel refuses to bind
an access rule to an anonymous-inode memfd (`landlock_add_rule` →
EBADF/EBADFD), and both path-based exec (`/proc/self/fd/<n>`) and
`execveat(AT_EMPTY_PATH)` of an inherited memfd are denied (`EACCES`) even
when the memfd predates the restriction. This was proven empirically, not
assumed: any implementation of an I/O-closed profile on Linux must make
the same choice unless the kernel grows anon-inode Landlock rules.

Therefore `frf-exec-linux-v3` executes the VERIFIED SNAPSHOT PATH —
content-addressed under `objects/sha256/`, sealed read-only, and itself
inside the closure — and documents the residual same-UID window exactly as
the normal operating model does (permissions plus rehashing; the OCI
profile remains the mechanism that closes both the path race and the
ambient-environment race).

### Refusal semantics and replay

A profile is ENFORCED, never approximated: if Landlock is unavailable
(kernel < 5.13, disabled at boot, syscall absent) the run REFUSES with a
message naming the missing mechanism — never a silent fallback to an
unclosed profile. **Replay rebuilds the closure from the capture's recorded
machinery** (the interpreter chains, the native closures, the declared
execution context, the objects directory) — a v3 observation is replayed
under the SAME closed contract, never unclosed. Extensions (comparators,
normalizers, adapters, minimizers, mutation providers, witnesses) are
harness-side instrumentation and run on the host under the reference
profile, exactly as under `frf-exec-oci`.

## Native runtime closure — `executable hash` is not `executable semantics`

For a native (ELF) executable, the artifact's behavior depends on more than
its own bytes. The kernel invokes the dynamic loader named by `PT_INTERP`;
the loader then resolves the executable's `DT_NEEDED` dependencies,
transitively, under the loader's search configuration (its cache, its
default directories, and the effective `LD_LIBRARY_PATH` of the
observation). Two artifacts with identical hashes can behave differently
under different loaders or libraries, and one artifact can behave
differently on two machines that load different components.

The engine therefore binds the **native runtime closure AT OBSERVATION
TIME** (receipt schema v17):

```text
FRF/RUNTIME-CLOSURE/v1 {
    schema_version: frf-runtime-closure-v1
    cid
    interp:   { path, sha256 }   // the dynamic loader (PT_INTERP)
    components: [ { path, sha256 }, … ]  // the resolved closure
}
```

- The executable's ELF program headers are parsed (self-contained, no
  external parser) to find `PT_INTERP`; a malformed ELF is a REFUSAL — an
  artifact that is not what it claims is not evidence. A statically linked
  binary (no `PT_INTERP`) has no dynamic loader to bind; the closure is
  refused honestly rather than silently omitted.
- The loader named by `PT_INTERP` is an UNTRUSTED-INPUT boundary: the
  artifact does not choose what the harness executes. It must pass the
  ADMITTED-LOADER policy — an absolute path whose canonical form sits
  under an admitted system loader root (`/lib`, `/lib64`, `/usr/lib`,
  `/usr/lib64`, the multiarch triples) with a basename in the loader
  family (`ld-*.so*`, `ld.so*`, `ld-linux*.so*`, `ld64.so*`, `ld-musl-*`)
  — and its bytes are read + hashed + SEALED BEFORE anything executes. The
  executed bytes are therefore exactly the bytes the closure records; an
  artifact that names `/bin/sh`, a relative path, a nonexistent loader, or
  a loader-like file outside the admitted roots is REFUSED at the policy,
  never executed.
- The resolved dependency closure is produced by invoking the ADMITTED,
  SEALED loader read-only (`ld.so --list <executable>`) — the same
  resolution the side's own exec would perform, with the observation's
  cache, default directories, and `LD_LIBRARY_PATH` applying. Only the
  loader executes, never the artifact's code. The `<executable>` is the
  SEALED EXEC PATH the side actually runs from (`/proc/self/fd/<n>` — the
  memfd fd the loader child inherits), NEVER the materialized snapshot
  path: `$ORIGIN`-relative `DT_RUNPATH`/`RPATH` resolution therefore sees
  the same origin the real execution sees. An unresolvable dependency
  (`not found`), a loader that refuses to resolve, or an `$ORIGIN`
  dependency the sealed mechanism cannot find is a REFUSAL: a closure that
  cannot be bound is an honest outcome, never a silent gap — and a closure
  resolved from a path the side never runs from would describe an
  execution that never happened.
- The closure-resolution execution is HARNESS-SIDE instrumentation under
  an EXPLICIT profile: the loader's `--list` invocation follows the same
  rule as every extension program (`host::extension_profile`) — under the
  OCI and I/O-closed profiles the instrumentation runs on the host under
  the reference profile (the loader cannot be I/O-closed before its own
  closure is known, and `--list` never runs the artifact's code), and
  under the reference/cgroup profiles it runs under the side's own
  profile. It is never the hardcoded weaker host profile: the executed
  loader is always the admitted + sealed bytes, and the resolution profile
  is part of the documented contract, not an accident.
- Every resolved component (loader + libraries) is hashed; components are
  sorted by path, so the identity is a deterministic SET identity. The
  closure's `cid` rederives in any implementation:
  `SHA-256("FRF/RUNTIME-CLOSURE/v1\n" ‖ JCS(document minus the cid))`.
- The closure lives on the artifact identity (`ArtifactIdentity.native_runtime`,
  in the capture and copied verbatim into the receipt). An artifact is a
  script OR a native ELF, never both: the interpreter chain and the closure
  are mutually exclusive, and verification REFUSES an artifact carrying
  both.
- Verification rederives the closure's `cid` from its own fields before the
  artifact is consumed, and the receipt's copy must EQUAL the capture's — a
  receipt never invents the machinery its run loaded.
- The resolved paths and hashes are evidence recorded at observation time;
  like interpreter hashes they are machine-specific and not re-derivable
  cross-machine. The closure's CID rederives from its own fields in any
  implementation.
- High-assurance claim admission requires the runtime closure for every
  native premise artifact: under that policy, a native artifact without its
  bound closure is refused, exactly as a script without its interpreter
  chain is refused.

## Execution-context closure — the DECLARED runtime dependencies (v18)

The native runtime closure binds the STARTUP LINK closure of the artifact
itself; it does not bind what the side subsequently SPAWNS or LOADS. The
engine therefore also records the court's **DECLARED execution-context
closure** (receipt + capture schema v18): the child executables, runtime
libraries, and data dependencies the side's behavior depends on beyond its
own bytes.

```text
FRF/EXECUTION-CONTEXT/v1 {
    schema_version: frf-execution-context-v1
    cid
    artifacts: [
        { path, role: child-executable | runtime-library | data, sha256 }, …
    ]
}
```

- The court author DECLARES the artifacts in the manifest
  (`court.execution_context.artifacts`), each a working-directory-relative or
  absolute path plus a protocol role; a role outside the protocol set is a
  REFUSAL at observation time.
- At observation time the engine resolves every declared path, snapshots
  the exact bytes as content-addressed objects, and records the closure in
  the capture — a declared dependency is bound to the exact bytes, never
  assumed. Relative paths resolve against the working directory, absolute
  paths against the host.
- The identity is a deterministic function of the declared SET: artifacts
  are sorted by path, and the `cid` rederives in any implementation:
  `SHA-256("FRF/EXECUTION-CONTEXT/v1\n" ‖ JCS(document minus the cid))`.
- Verification rederives the closure's `cid` from its own fields, requires
  the protocol roles and the strictly-sorted order, verifies each snapshot
  object is content-addressed, and requires the receipt's copy to EQUAL the
  capture's.
- **This is a DECLARED closure, never a measured file-access trace.** It
  binds what the court author declares the side needs — for JVM evidence,
  `java` + its native startup closure + the classpath artifacts; for
  Python, the interpreter + the module tree; for a service, the binary +
  shared libs + config. A high-assurance claim therefore means "the
  declared execution context is bound", never "every file the side read was
  captured". A launcher's classpath is bound because the court declared it;
  the artifact's own closure remains its native startup-link closure (v17),
  not a runtime trace.
- High-assurance claim admission states each premise's declared closure
  (when present) and never implies transitive runtime closure beyond it.

## The reproduction policies

`frf replay RUN_ID | RECEIPT_ID --policy exact|semantic`:

### exact (default)

> Did essentially the same execution reproduce?

Exact replay requires:

- the same execution profile and the same applied capture bounds;
- the same environment digest — the FRF/ENVIRONMENT/v2 formula over the
  host strata (os, arch, kernel, umask) AND the DECLARED execution
  environment the sides ran under (the exact map the harness spawned them
  with; replay re-spawns with that map, so the declared environment is
  reproduced byte-for-byte from the evidence — the ambient host
  environment is never inherited and never part of the observation);
- the same working directory;
- every artifact's interpreter chain re-resolving to the recorded
  identities (kernel interpreter, downstream interpreter, shebang
  arguments, env resolver, PATH digest); a native artifact's runtime
  closure re-resolving to the recorded loader + component hashes;
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
