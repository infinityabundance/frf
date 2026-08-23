#!/bin/sh
# The pinned, hermetic native build executed INSIDE the frf-v3-build image
# (fedora:41 + gcc/make/perl). Runs from /work with src/ and out/ mounted.
set -e
echo "build host: $(uname -a)"
echo "gcc: $(gcc --version | head -1)"
echo "make: $(make --version | head -1)"
echo "glibc: $(ldd --version | head -1)"
echo "perl: $(perl --version | head -2 | tail -1)"

# --- bash 4.3.0 (vulnerable; the pristine upstream release, archived at
#     snapshot.debian.org — ftp.gnu.org no longer hosts it) ---
tar xzf src/bash_4.3.orig.tar.gz
cd bash-4.3
rm -f .build   # the build-version counter: a fresh tree must start at 1
./configure --quiet --without-bash-malloc --disable-nls CFLAGS="-O2 -std=gnu89"
make -j"$(nproc)" bash
cd ..
cp bash-4.3/bash out/bash-4.3.0

# --- bash 4.3.30 (fixed) ---
tar xzf src/bash-4.3.30.tar.gz
cd bash-4.3.30
rm -f .build   # the build-version counter: a fresh tree must start at 1
./configure --quiet --without-bash-malloc --disable-nls CFLAGS="-O2 -std=gnu89"
make -j"$(nproc)" bash
cd ..
cp bash-4.3.30/bash out/bash-4.3.30

# --- openssl 1.0.1a..1.0.1g (the full CVE-2014-0160 series: every release
#     from the heartbeat feature's introduction through the fix) ---
# The TERMIO patch is the same for every 1.0.1.x: termio.h was removed from
# modern glibc; the source forces TERMIO on linux. Build-only, never linked
# into the probe.
for v in a b c d e f g; do
  tar xzf "src/openssl-1.0.1${v}.tar.gz"
  cd "openssl-1.0.1${v}"
  sed -i 's/-DTERMIO //' Configure
  sed -i 's/# define TERMIO/# define TERMIOS/' crypto/ui/ui_openssl.c
  ./config no-shared
  # -j1, deliberately: the 1.0.1 build system merges every crypto subdir
  # into ONE libcrypto.a with concurrent `ar` invocations, and on a
  # many-core host -jN races them into a truncated archive (observed:
  # "error reading x509_txt.o: file truncated"). Serial is deterministic;
  # the build is a one-time corpus cost.
  make -j1 build_crypto build_ssl
  cd ..
  cp "openssl-1.0.1${v}/libssl.a" "out/libssl-1.0.1${v}.a"
  cp "openssl-1.0.1${v}/libcrypto.a" "out/libcrypto-1.0.1${v}.a"
done

# --- the heartbleed probe, linked against each library set ---
for v in a b c d e f g; do
  gcc -O2 -no-pie -I "openssl-1.0.1${v}/include" hb.c -o "out/hb-1.0.1${v}" \
    -Wl,--start-group "openssl-1.0.1${v}/libssl.a" "openssl-1.0.1${v}/libcrypto.a" \
    -Wl,--end-group -ldl -lpthread
done

# --- the log4shell probe, compiled with the PINNED JDK inside this image ---
# (the JDK is part of the pinned toolchain — no host javac is involved; the
# source is UTF-8, declared explicitly; the jar uses FIXED entry timestamps
# so probe.jar is byte-reproducible: two builds in this image hash equal)
rm -rf probe-classes && mkdir -p probe-classes
javac -encoding UTF-8 -cp src/log4j-api-2.14.1.jar:src/log4j-core-2.14.1.jar \
  -d probe-classes probe/Log4ShellProbe.java
jar --date=2020-01-01T00:00:00Z --create --file out/probe.jar \
  -C probe-classes Log4ShellProbe.class \
  -C probe-classes 'Log4ShellProbe$CapturingListener.class'

echo "BUILD COMPLETE"
