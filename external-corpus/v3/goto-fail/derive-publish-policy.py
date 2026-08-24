#!/usr/bin/env python3
"""Derive the goto-fail publication policy: the frf-detached-objects-v1
declaration naming the cids to withhold from the publication.

The v3 discipline withholds BUILD PRODUCTS (pinned in build-manifest.json;
rebuilt hermetically by build/build.sh) and the mutation REQUEST documents
(which embed the reference artifact bytes). Everything else — the canonical
documents of the evidence graph — is published.

Usage: derive-publish-policy.py <evidence-root> <build-manifest.json> <output>
"""
import hashlib
import json
import pathlib
import sys

ev = pathlib.Path(sys.argv[1])
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text())
out = sys.argv[3]
case_dir = pathlib.Path(sys.argv[2]).parent.parent
pins = manifest["artifacts"]  # e.g. builds/sslcheck-clean -> sha256

objects = []
for rel, sha in pins.items():
    role = "authority-artifact" if rel.endswith("sslcheck-clean") else "candidate-artifact"
    objects.append({
        "cid": sha,
        "role": role,
        "publication": "build-product",
        "size": str((case_dir / rel).stat().st_size),
        "reconstruction": {
            "recipe": "external-corpus/v3/goto-fail/build/build.sh: gcc -O2 builds the clean verifier and the -DGO_TO_FAIL defect build from src/sslcheck.c (SHA-256-pinned in build-manifest.json); the bytes are the same object the court executed",
            "source_path": "external-corpus/v3/goto-fail/src/sslcheck.c",
        },
    })

# The mutation-request documents embed the reference artifact bytes; they are
# withheld by the same publication policy.
for req in sorted((ev / "challenges").glob("*/mutation/request.json")):
    cid = hashlib.sha256(req.read_bytes()).hexdigest()
    objects.append({
        "cid": cid,
        "role": "mutation-request",
        "publication": "build-product",
        "size": str(req.stat().st_size),
        "path": str(req.relative_to(ev)),
        "reconstruction": {
            "recipe": "rerun the study (sh external-corpus/v3/goto-fail/study.sh) with the local build products: the mutation provider's canonical request document embeds the reference artifact bytes",
        },
    })

declaration = {
    "schema_version": "frf-detached-objects-v1",
    "policy": "detached",
    "objects": objects,
}
with open(out, "w") as f:
    json.dump(declaration, f, indent=1, sort_keys=True)
    f.write("\n")
