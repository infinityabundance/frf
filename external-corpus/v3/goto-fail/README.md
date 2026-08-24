# Goto Fail — CVE-2014-1266, the `tls.verdict` semantic domain

The second semantic-domain axis of the v3 corpus. Apple Secure Transport's
"goto fail" defect (CVE-2014-1266) was a duplicated `goto fail;` that
skipped the signature comparison, accepting every handshake. This case
models the defect's OBSERVABLE — a verifier that accepts tampered records —
and judges it SEMANTICALLY on the `tls.verdict` axis, exactly as the
Heartbleed study judges the leak observables. The recipe generalizes:
external semantic comparator + minimizer κ-route + mutation challenge +
version-series trajectory + sensitivity-backed claim.

See `claims/goto-fail-verdict.md` for the measured story, and
`../build/build-manifest.json` for the artifact pins.

## Reproduce

```sh
./reproduce.sh build    # gcc; no container needed
./reproduce.sh run      # regenerate evidence/ under golden/work (never the public tree)
./reproduce.sh publish  # full local evidence -> publish-detached -> evidence/
./reproduce.sh verify   # re-derive + publish + byte-compare the committed publication
```

The verifier binaries are NOT committed (they are pinned build products):
`./reproduce.sh build` materializes them once. Hosted CI does not build or
execute them — it verifies the detached publication instead.
