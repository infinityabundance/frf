# The FRF v3 empirical corpus — hermetic build.
#
# Builds the REAL vulnerable and fixed releases of the historical software
# from their pinned upstream sources:
#
#   shellshock  bash 4.3.0  (vulnerable, CVE-2014-6271)  — pristine upstream
#               bash 4.3.30 (fixed)                       — the final 4.3 patch
#   heartbleed  OpenSSL 1.0.1a..1.0.1f (vulnerable, CVE-2014-0160 — every
#               release from the heartbeat feature's introduction to the fix)
#               OpenSSL 1.0.1g (fixed)                    — the fix release
#   log4shell   log4j 2.14.1 (vulnerable, CVE-2021-44228) — Maven Central jars
#               log4j 2.17.1 (fixed)                      — pinned by SHA-256
#
# The native builds (bash, openssl) AND the Java probe run INSIDE a pinned
# container image (fedora:41 pinned by digest + exact package NEVRAs + a
# pinned JDK) so the toolchain is hermetic and recorded; the produced
# binaries and the probe.jar are NOT committed — every artifact is pinned by
# SHA-256 in build-manifest.json and materialized HERE (a fresh clone runs
# this once; CI does not build them, and the xtask empirical programs skip
# cases whose build products are absent). The probe.jar is byte-reproducible
# (pinned JDK + fixed entry timestamps).
#
# Prerequisites: podman (or docker), curl, and network access (the pinned
# source tarballs/jars and the image's package repository).
# Usage:  sh build/build-all.sh
set -eu

cd "$(dirname "$0")/.."

BUILD_DIR=build
WORK_DIR=${FRF_V3_BUILD_WORK:-"$PWD/$BUILD_DIR/work"}
mkdir -p "$WORK_DIR/src" "$WORK_DIR/out"
: > "$WORK_DIR/build.log"

log() { echo "[build] $*" | tee -a "$WORK_DIR/build.log"; }

# The pinned sources (URL + SHA-256). ftp.gnu.org no longer hosts the
# pristine 4.3.0 release; it is archived at snapshot.debian.org as the
# Debian orig tarball (identical to the upstream release).
bash_4_3_0_url="https://snapshot.debian.org/archive/debian/20140304T040604Z/pool/main/b/bash/bash_4.3.orig.tar.gz"
bash_4_3_0_sha="b2fe79ddf9e7abdb4695e3070afa866d2a94a58d1cc9d731585330c753815491"
bash_4_3_30_url="https://ftp.gnu.org/gnu/bash/bash-4.3.30.tar.gz"
bash_4_3_30_sha="317881019bbf2262fb814b7dd8e40632d13c3608d2f237800a8828fbb8a640dd"
openssl_1_0_1a_url="https://www.openssl.org/source/old/1.0.1/openssl-1.0.1a.tar.gz"
openssl_1_0_1a_sha="d3487e09d891c772cf946273a3bb0ca47479e7941be6d822274320e7cfcc361b"
openssl_1_0_1b_url="https://www.openssl.org/source/old/1.0.1/openssl-1.0.1b.tar.gz"
openssl_1_0_1b_sha="1187bf2d5cdf0b286b951bf5c777aa97855cd7db24fdb9604cb557c8b1d7364b"
openssl_1_0_1c_url="https://www.openssl.org/source/old/1.0.1/openssl-1.0.1c.tar.gz"
openssl_1_0_1c_sha="2a9eb3cd4e8b114eb9179c0d3884d61658e7d8e8bf4984798a5f5bd48e325ebe"
openssl_1_0_1d_url="https://www.openssl.org/source/old/1.0.1/openssl-1.0.1d.tar.gz"
openssl_1_0_1d_sha="88a423f9b08a994054583691b968815875580e12df754e881d7cfe9f1bd1f49d"
openssl_1_0_1e_url="https://www.openssl.org/source/old/1.0.1/openssl-1.0.1e.tar.gz"
openssl_1_0_1e_sha="f74f15e8c8ff11aa3d5bb5f276d202ec18d7246e95f961db76054199c69c1ae3"
openssl_1_0_1f_url="https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz"
openssl_1_0_1f_sha="6cc2a80b17d64de6b7bac985745fdaba971d54ffd7d38d3556f998d7c0c9cb5a"
openssl_1_0_1g_url="https://www.openssl.org/source/old/1.0.1/openssl-1.0.1g.tar.gz"
openssl_1_0_1g_sha="53cb818c3b90e507a8348f4f5eaedb05d8bfe5358aabb508b7263cc670c3e028"
log4j_api_2_14_1_sha="8caf58db006c609949a0068110395a33067a2bad707c3da35e959c0473f9a916"
log4j_core_2_14_1_sha="ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0"
log4j_api_2_17_1_sha="b0d8a4c8ab4fb8b1888d0095822703b0e6d4793c419550203da9e69196161de4"
log4j_core_2_17_1_sha="c967f223487980b9364e94a7c7f9a8a01fd3ee7c19bdbf0b0f9f8cb8511f3d41"

fetch() { # $1=url $2=dest $3=sha256
  if [ ! -f "$2" ] || ! echo "$3  $2" | sha256sum -c - >/dev/null 2>&1; then
    log "fetching $(basename "$2")"
    curl -fsSL "$1" -o "$2.tmp"
    echo "$3  $2.tmp" | sha256sum -c - >/dev/null || {
      echo "[build] SHA-256 mismatch for $(basename "$2")" >&2; exit 1; }
    mv "$2.tmp" "$2"
  fi
}

fetch "$bash_4_3_0_url"   "$WORK_DIR/src/bash_4.3.orig.tar.gz"  "$bash_4_3_0_sha"
fetch "$bash_4_3_30_url"  "$WORK_DIR/src/bash-4.3.30.tar.gz"   "$bash_4_3_30_sha"
for v in a b c d e f g; do
  eval "u=\$openssl_1_0_1${v}_url"
  eval "s=\$openssl_1_0_1${v}_sha"
  fetch "$u" "$WORK_DIR/src/openssl-1.0.1${v}.tar.gz" "$s"
done

# The log4j jars are prebuilt Maven Central artifacts, pinned by SHA-256.
for v in 2.14.1 2.17.1; do
  for a in api core; do
    f="log4j-$a-$v.jar"
    case "$a-$v" in
      api-2.14.1) sha=$log4j_api_2_14_1_sha ;;
      core-2.14.1) sha=$log4j_core_2_14_1_sha ;;
      api-2.17.1) sha=$log4j_api_2_17_1_sha ;;
      core-2.17.1) sha=$log4j_core_2_17_1_sha ;;
    esac
    fetch "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-$a/$v/$f" \
          "$WORK_DIR/src/$f" "$sha"
  done
done

# The containerized native build (bash + openssl + the Java probe). The
# image is pinned by digest and exact package NEVRAs (see Containerfile);
# the image digest is recorded in the build manifest by the recipe.
cp "$BUILD_DIR/Containerfile" "$WORK_DIR/Containerfile"
cp "$BUILD_DIR/native-build.sh" "$WORK_DIR/native-build.sh"
cp "heartbleed/src/hb.c" "$WORK_DIR/hb.c"
mkdir -p "$WORK_DIR/probe"
cp "log4shell/src/Log4ShellProbe.java" "$WORK_DIR/probe/Log4ShellProbe.java"
podman build --network=host -t frf-v3-build -f "$WORK_DIR/Containerfile" "$WORK_DIR" \
  >> "$WORK_DIR/build.log" 2>&1
IMAGE_ID=$(podman image inspect frf-v3-build --format '{{.Id}}')
log "build image: $IMAGE_ID"
podman run --rm --network=host \
  -v "$WORK_DIR":/work:Z -w /work \
  frf-v3-build:latest sh native-build.sh >> "$WORK_DIR/build.log" 2>&1

# Commit the artifacts into the corpus.
install -m 0755 "$WORK_DIR/out/bash-4.3.0" shellshock/builds/bash-4.3.0
install -m 0755 "$WORK_DIR/out/bash-4.3.30" shellshock/builds/bash-4.3.30
install -m 0755 "$WORK_DIR/out/hb-1.0.1a" heartbleed/builds/hb-1.0.1a
install -m 0755 "$WORK_DIR/out/hb-1.0.1b" heartbleed/builds/hb-1.0.1b
install -m 0755 "$WORK_DIR/out/hb-1.0.1c" heartbleed/builds/hb-1.0.1c
install -m 0755 "$WORK_DIR/out/hb-1.0.1d" heartbleed/builds/hb-1.0.1d
install -m 0755 "$WORK_DIR/out/hb-1.0.1e" heartbleed/builds/hb-1.0.1e
install -m 0755 "$WORK_DIR/out/hb-1.0.1f" heartbleed/builds/hb-1.0.1f
install -m 0755 "$WORK_DIR/out/hb-1.0.1g" heartbleed/builds/hb-1.0.1g
install -m 0644 "$WORK_DIR/out/probe.jar" log4shell/builds/probe.jar
install -m 0644 "$WORK_DIR/src/log4j-api-2.14.1.jar" log4shell/builds/lib/
install -m 0644 "$WORK_DIR/src/log4j-core-2.14.1.jar" log4shell/builds/lib/
install -m 0644 "$WORK_DIR/src/log4j-api-2.17.1.jar" log4shell/builds/lib/
install -m 0644 "$WORK_DIR/src/log4j-core-2.17.1.jar" log4shell/builds/lib/

log "done: corpus artifacts refreshed (see build/work/build.log)"
