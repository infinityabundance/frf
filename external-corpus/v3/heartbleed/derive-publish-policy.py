#!/usr/bin/env python3
"""Derive the Heartbleed publication policy (frf-detached-objects-v1) from
the regenerated COMPLETE local evidence tree + the build manifest.

The withheld set is EXACTLY the security-sensitive build products (the seven
hb probe binaries, pinned in build-manifest.json) plus the mutation-provider
request document (which embeds the reference artifact bytes). Everything else
— fixtures, comparator/minimizer implementations, the mutant wrapper — is
safe and stays in the publication. The policy is DERIVED, never hand-
maintained: the probe cids come from the manifest, the mutation request's cid
and path come from the tree (its invocation record), so a regenerated study
always produces a policy that matches the tree it was derived from.

usage: derive-publish-policy.py <full-ev-root> <build-manifest.json> <out.json>
"""
import hashlib
import json
import pathlib
import sys


def main() -> int:
    ev, manifest_path, out = (pathlib.Path(a) for a in sys.argv[1:4])
    manifest = json.loads(manifest_path.read_text())
    letters = {"a": "1.0.1a", "b": "1.0.1b", "c": "1.0.1c", "d": "1.0.1d",
               "e": "1.0.1e", "f": "1.0.1f", "g": "1.0.1g"}

    objects = []
    # The probes: from the manifest pins (role + size + recipe).
    for rel, cid in manifest["artifacts"].items():
        if not rel.startswith("heartbleed/builds/hb-1.0.1"):
            continue
        version = rel[-1]  # the release letter: hb-1.0.1a -> a
        src = (manifest_path.parent.parent / rel)
        size = str(src.stat().st_size) if src.exists() else "0"
        objects.append({
            "cid": cid,
            "role": "authority-artifact" if version == "g" else "candidate-artifact",
            "publication": "external-security-sensitive",
            "size": size,
            "reconstruction": {
                "recipe": (
                    f"external-corpus/v3/build/build-all.sh: the pinned-NEVRA "
                    f"container builds the probe against the official OpenSSL "
                    f"{letters[version]} tarball (SHA-256-pinned in "
                    f"build-manifest.json); the bytes are the same object the "
                    f"court executed"
                ),
                "source_path": f"heartbleed/builds/hb-1.0.1{version}",
            },
        })

    # The mutation-provider request (embeds the reference artifact bytes):
    # derived from the tree's invocation record, so the path always matches.
    for inv in (ev / "challenges").glob("*/mutation/invocation.json"):
        doc = json.loads(inv.read_text())
        request_cid = doc["request_cid"]
        request_path = inv.parent / "request.json"
        if request_path.exists():
            objects.append({
                "cid": request_cid,
                "role": "mutation-request",
                "publication": "external-security-sensitive",
                "size": str(request_path.stat().st_size),
                "path": str(request_path.relative_to(ev)),
                "reconstruction": {
                    "recipe": (
                        "rerun the study (sh external-corpus/v3/heartbleed/"
                        "study.sh) with the local build products: the mutation "
                        "provider's canonical request document embeds the "
                        "reference artifact bytes"
                    ),
                },
            })

    policy = {
        "schema_version": "frf-detached-objects-v1",
        "policy": "detached",
        "objects": objects,
    }
    out.write_bytes(json.dumps(
        policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode())
    print(f"derived publication policy: {len(objects)} detached payload(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
