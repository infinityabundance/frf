#!/bin/sh
# The Goto Fail (CVE-2014-1266) semantic study — build the two verifiers
# BYTE-REPRODUCIBLY inside a digest-pinned builder image.
#
# The defect is a duplicated `goto fail;` in Apple Secure Transport that
# skips the signature comparison, so every handshake is accepted. This kit
# builds a clean verifier and the buggy verifier (-DGO_TO_FAIL) from ONE C
# source — a SYNTHETIC MODEL of the defect's observable (it executes no
# historical Apple code; see provenance_kind: synthetic-model in
# build-manifest.json) — and pins both by SHA-256 in build-manifest.json.
#
# Source reproducibility is NOT artifact reproducibility: the compiler,
# linker, and libc development environment are fixed by the builder image
# (fedora:41 pinned by OCI manifest digest + exact gcc/binutils/glibc-devel
# NEVRAs, see Containerfile). The recipe records — in build-manifest.json —
# the source SHA-256, the pinned base digest and the BUILT image id, the
# exact compiler/linker/libc versions, the target, and the flags; a reviewer
# with the same sslcheck.c bytes and the same pinned image reproduces the
# SAME executable bytes. An ambient compiler is REFUSED: it could not
# reproduce the pinned hashes, and a build that cannot be reproduced is not
# a reconstruction recipe.
#
# Usage:  sh build/build.sh        (needs podman or docker + network for dnf)
set -eu

cd "$(dirname "$0")/.."

if command -v podman >/dev/null 2>&1; then
  RUNTIME=podman
elif command -v docker >/dev/null 2>&1; then
  RUNTIME=docker
else
  echo "the goto-fail builder needs podman (or docker): the artifact hashes are pinned to a digest-pinned toolchain (build/Containerfile), and an ambient compiler cannot reproduce them" >&2
  exit 1
fi

WORK_DIR=build/work
mkdir -p "$WORK_DIR" builds
cp build/Containerfile "$WORK_DIR/Containerfile"

echo "== building the pinned builder image (fedora:41 by digest + exact NEVRAs) =="
$RUNTIME build --network=host -t frf-goto-fail-builder -f "$WORK_DIR/Containerfile" "$WORK_DIR"
IMAGE_ID=$($RUNTIME image inspect frf-goto-fail-builder --format '{{.Id}}')
echo "builder image id: $IMAGE_ID"

echo "== building the two verifiers INSIDE the pinned toolchain =="
# The compile happens inside the image; the source is mounted read-only and
# the artifacts are written to a host-mounted output dir (copied out with
# `install` so ownership is deterministic).
mkdir -p "$WORK_DIR/out"
$RUNTIME run --rm \
  -v "$PWD/src":/src:ro \
  -v "$PWD/$WORK_DIR/out":/out \
  frf-goto-fail-builder sh -c '
    gcc -O2 -o /out/sslcheck-clean /src/sslcheck.c
    gcc -O2 -DGO_TO_FAIL -o /out/sslcheck-buggy /src/sslcheck.c
  '
install -m 0755 "$WORK_DIR/out/sslcheck-clean" builds/sslcheck-clean
install -m 0755 "$WORK_DIR/out/sslcheck-buggy" builds/sslcheck-buggy

echo "== recording the exact toolchain in build-manifest.json =="
# The exact versions come from the PINNED image itself (never from the
# ambient host): gcc/ld/glibc report the versions the image was built with.
TOOLCHAIN=$($RUNTIME run --rm frf-goto-fail-builder sh -c '
  echo "gcc=$(gcc --version | head -1)"
  echo "ld=$(ld --version | head -1)"
  echo "glibc=$(rpm -q glibc)"
  echo "target=$(gcc -dumpmachine)"
')
echo "$TOOLCHAIN"

python3 - build/build-manifest.json "$IMAGE_ID" "$TOOLCHAIN" <<'PY'
import hashlib, json, pathlib, sys
manifest_path, image_id, toolchain = sys.argv[1], sys.argv[2], sys.argv[3]

# The toolchain facts, parsed from the image's own reports.
facts = {}
for line in toolchain.splitlines():
    if "=" in line:
        k, _, v = line.partition("=")
        facts[k] = v

builder = {
    "base_image": "fedora@sha256:68bb1ba893be0c05991b2df55bc6571862bab7526fd6053b1ebacd53a2a75366",
    "built_image_id": image_id,
    "containerfile": "external-corpus/v3/goto-fail/build/Containerfile (pinned base digest + exact package NEVRAs)",
    "compiler": facts.get("gcc", ""),
    "linker": facts.get("ld", ""),
    "libc": facts.get("glibc", ""),
    "target": facts.get("target", ""),
    "flags": ["-O2", "-O2 -DGO_TO_FAIL"],
}

# The artifact hashes the builder JUST produced (the ground truth a reviewer
# must reproduce).
artifacts = {}
for rel in ["builds/sslcheck-clean", "builds/sslcheck-buggy"]:
    p = pathlib.Path(rel)
    artifacts[rel] = hashlib.sha256(p.read_bytes()).hexdigest()

manifest = json.loads(pathlib.Path(manifest_path).read_text())
manifest["builder"] = builder
manifest["artifacts"] = artifacts
pathlib.Path(manifest_path).write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
print("build-manifest.json updated: builder + artifact hashes recorded")
PY

echo "== verifying the built artifacts against the pinned hashes =="
python3 - build/build-manifest.json <<'PY'
import hashlib, json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
drift = []
for rel, pinned in manifest["artifacts"].items():
    p = pathlib.Path(rel)
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != pinned:
        drift.append(f"DRIFT {rel}: got {got[:16]} pinned {pinned[:16]}")
if drift:
    print("\n".join(drift))
    sys.exit(1)
print("ok: all artifact hashes match build-manifest.json")
PY
echo "done: builds/sslcheck-clean + builds/sslcheck-buggy (pinned toolchain)"
