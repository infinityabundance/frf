#!/usr/bin/env python3
"""Derive the Log4Shell publication policy (frf-detached-objects-v1) from

the regenerated COMPLETE local evidence tree + the shared build manifest.

The withheld set is EXACTLY the evidence payloads the tree references that
are security-sensitive: the four launchers (the court's side programs —
the admitted reference and the three candidate launchers, snapshotted as
content-addressed objects by the court) plus the mutation-provider request
document (which embeds the reference artifact bytes). Everything else —
fixtures, comparator/minimizer implementations, the mutant wrapper — is
safe and stays in the publication.

The pinned jars and probe.jar are NOT evidence-tree references: they are
runtime dependencies the launchers load through the JVM classpath (the
Java analogue of the native runtime closure), never snapshotted by the
court. Their SHA-256 pins + reconstruction recipes live in the shared
build manifest and in every launcher's reconstruction record — the
publication documents them; the detached declaration names only payloads
the tree actually references.

The policy is DERIVED, never hand-maintained: the payload cids come from
the manifest pins, the mutation request's cid and path come from the tree
(its invocation record), so a regenerated study always produces a policy
that matches the tree it was derived from.

usage: derive-publish-policy.py <full-ev-root> <build-manifest.json> <out.json>
"""
import json
import pathlib
import sys


def main() -> int:
    ev, manifest_path, out = (pathlib.Path(a) for a in sys.argv[1:4])
    manifest = json.loads(manifest_path.read_text())
    case_dir = manifest_path.parent.parent  # external-corpus/v3

    # The pinned launchers: run-fixed.sh is the admitted reference; the
    # vulnerable/revision launchers are candidates.
    role_by_rel = {
        "log4shell/builds/run-fixed.sh": "authority-artifact",
        "log4shell/builds/run-vuln.sh": "candidate-artifact",
        "log4shell/builds/run-v150.sh": "candidate-artifact",
        "log4shell/builds/run-v160.sh": "candidate-artifact",
    }
    recipe_launcher = (
        "external-corpus/v3/build/build-all.sh: the launcher is a committed "
        "case-kit script whose SHA-256 is pinned in build-manifest.json; the "
        "bytes are the same object the court executed. Its classpath loads "
        "the SHA-256-pinned probe and log4j jars (also in build-manifest.json)"
    )

    objects = []
    for rel, cid in manifest["artifacts"].items():
        if not rel.endswith(".sh") or not rel.startswith("log4shell/builds/"):
            continue
        role = role_by_rel.get(rel, "candidate-artifact")
        src = case_dir / rel
        size = str(src.stat().st_size) if src.exists() else "0"
        objects.append({
            "cid": cid,
            "role": role,
            "publication": "external-security-sensitive",
            "size": size,
            "reconstruction": {
                "recipe": recipe_launcher,
                "source_path": rel,
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
                        "rerun the study (sh external-corpus/v3/log4shell/"
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
