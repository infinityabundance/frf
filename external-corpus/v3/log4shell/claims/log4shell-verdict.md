# Log4Shell — CVE-2021-44228, judged semantically

## The measured story

Apache Log4j's "Log4Shell" defect (CVE-2021-44228) was a JNDI lookup
expression resolved at log time: a message containing
`${jndi:ldap://...}` made the vulnerable stack contact an
attacker-controlled endpoint. This study judges the defect's OBSERVABLE —
did the logging stack perform the lookup? — on the semantic `jndi.lookup`
domain: the THIRD semantic axis of the v3 corpus, a structured-runtime
observable, proving the leak study's recipe (semantic comparator + minimizer
κ-route + mutation challenge + version-series trajectory) is a general
protocol facility and not a one-off construction.

* the **vulnerable 2.14.1 stack** performs the lookup at log time — the
  court observes the `jndi.lookup` divergence against the fixed reference
  (the lookup error path fires against the loopback, connection-refused
  endpoint; no exfiltration is possible);
* the **fixed 2.17.1 stack** logs the message literally — the verdict court
  is clean, and the **clean control** (both launchers on a message with no
  lookup expression) is clean on both sides: without the malicious message,
  the vulnerable and fixed stacks are observably identical;
* the **version series 2.14.1 → 2.15.0 → 2.16.0 → 2.17.1** measures the
  real CVE-2021-44228 lifecycle: onset in 2.14.1, cessation exactly at
  2.15.0 (message lookups disabled by default — the mitigation point),
  clean through 2.16.0 (JNDI removed) and 2.17.1 (final). The movement is
  compiled as a trajectory premise bound to its subject;
* the **jndi-inject challenge** passes: the seeded mutant is the REAL
  vulnerable 2.14.1 stack run against the court's fixture — the lookup is
  genuinely performed through the historical defect, and the court sees the
  seeded signal and nothing else;
* the **court-verified minimal trigger** is the BARE lookup token — the
  `jndi.lookup.message_suffix_length` boundary: at suffix length 28 the
  message is exactly `${jndi:ldap://127.0.0.1:1/a}` and the divergence
  survives; at length 27 the token loses its opening `${` and is left
  literal by the substitutor — no lookup on either side. The typed
  adjacent-boundary is proven by the core's own two observations, with the
  domain projection (`len=`, embedded-integer) deriving both coordinates
  from the executed fixtures;
* the **fixed stack's claim** compiles under the `sensitivity-backed`
  policy, backed by that challenge: it asserts parity on the `jndi.lookup`
  surface — never byte-identical stderr, never a drop-in claim.

## What is here

| path | what |
|---|---|
| `src/Log4ShellProbe.java` | the probe: logs the fixture message through the Log4j release under test and reports the lookup verdict as a deterministic first stdout line (`JNDI_LOOKUP_ATTEMPTED` / `JNDI_LOOKUP_NOT_ATTEMPTED`), followed by the captured lookup diagnostic. Honors the fixture's `len=N ` directive — the ordered-integer domain projection the minimizer reduces (the message is the last N characters of the line) |
| `builds/` | the probe, the eight pinned log4j jars (2.14.1 / 2.15.0 / 2.16.0 / 2.17.1 × api/core) and the four launchers, pinned by SHA-256 in `../build/build-manifest.json`. NOT committed (v3 discipline): `./reproduce.sh build` materializes them |
| `fixtures/` | `defect.conf` (the message containing the lookup expression) and `clean.conf` (no lookup expression — the clean control) |
| `comparators/jndi-lookup.py` | the semantic comparator: the `jndi.lookup` axis under `eq(jndi-scan)` — did the side PERFORM the lookup? A verdict is a semantic observable, never a byte diff |
| `minimizers/jndi-message.py` | the κ-route minimizer (`jndi-message-minimize`): reduces the declared message-suffix length to the empirical floor 28 (the bare lookup token), declaring the typed adjacent-boundary the core proves |
| `mutations/jndi-inject.py` | the challenge operator: proposes the REAL vulnerable 2.14.1 stack as the mutant — the lookup is genuinely performed through the historical defect |
| `evidence/` | the committed, deterministic evidence tree: the 4-point version series + boundary-localized trajectory, the receipts, the jndi-inject challenge, the court-verified reduction, and the sensitivity-backed claim |
| `claims/log4shell-verdict.md` | this comparative claim |
| `study.sh` | the full FRF flow driver (regenerates the evidence under `golden/work`) |
| `reproduce.sh` | `build` / `run` / `publish` / `verify` — the reproducibility kit |

## Reproduce

```sh
./reproduce.sh build    # BYTE-REPRODUCIBLE: pinned builder image + pinned Maven Central jars (needs podman/docker + network)
./reproduce.sh run      # regenerate evidence/ under golden/work (never the public tree)
./reproduce.sh publish  # full local evidence -> publish-detached -> evidence/
./reproduce.sh verify   # re-derive + publish + byte-compare the committed publication
```

HOSTILE-CODE WARNING: this kit deliberately constructs and executes the
CVE-2021-44228-vulnerable Log4j 2.14.1 stack (loopback, connection-refused
endpoint only). Execution stages require `FRF_L4S_ACK=yes`.
