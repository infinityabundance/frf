# Log4Shell — CVE-2021-44228, the `jndi.lookup` semantic domain

The third semantic-domain axis of the v3 corpus. Apache Log4j's "Log4Shell"
defect (CVE-2021-44228) resolved a JNDI lookup expression in a log message
at log time, contacting an attacker-controlled endpoint. This case judges
the defect's OBSERVABLE — did the logging stack perform the lookup? — on
the `jndi.lookup` axis, a structured-runtime observable, distinct from the
memory-leak (Heartbleed) and TLS-verdict (Goto Fail) domains. The recipe
generalizes: external semantic comparator + minimizer κ-route + mutation
challenge + version-series trajectory + sensitivity-backed claim.

See `claims/log4shell-verdict.md` for the measured story, and
`../build/build-manifest.json` for the artifact pins.

## Reproduce

```sh
./reproduce.sh build    # BYTE-REPRODUCIBLE: pinned builder image + pinned Maven Central jars (needs podman/docker + network)
./reproduce.sh run      # regenerate evidence/ under golden/work (never the public tree)
./reproduce.sh publish  # full local evidence -> publish-detached -> evidence/ (+ the portable bundle)
./reproduce.sh verify   # re-derive + publish + byte-compare the committed publication (+ the portable bundle)

The PORTABLE BUNDLE (`bundle/portable.frf`, built by `publish` and
`verify`): the fixed receipt + its complete evidence closure, exported by
`frf bundle export` and verified from an EMPTY directory — no source tree,
no FRF installation — by the reference engine AND the independent
verifiers (xtask, Go), which reach the same verdict on the same bytes.
```

The probe and jars are NOT committed (they are pinned build/fetch
products): `./reproduce.sh build` materializes them once. Hosted CI does
not build or execute them — it verifies the detached publication instead.

HOSTILE-CODE WARNING: this kit deliberately constructs and executes the
CVE-2021-44228-vulnerable Log4j 2.14.1 stack (loopback, connection-refused
endpoint only — no real exfiltration is possible). Execution stages
require `FRF_L4S_ACK=yes`. Run in an ISOLATED, DISPOSABLE environment.
