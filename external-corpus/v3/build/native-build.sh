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

# --- openssl 1.0.1f (vulnerable) ---
tar xzf src/openssl-1.0.1f.tar.gz
cd openssl-1.0.1f
# Modern-toolchain compatibility (documented, minimal, affects only the
# terminal-UI code we never use): termio.h was removed from glibc; the
# source forces TERMIO on linux.
sed -i 's/-DTERMIO //' Configure
sed -i 's/# define TERMIO/# define TERMIOS/' crypto/ui/ui_openssl.c
./config no-shared
make -j"$(nproc)" build_crypto build_ssl
cd ..
cp openssl-1.0.1f/libssl.a out/libssl-1.0.1f.a
cp openssl-1.0.1f/libcrypto.a out/libcrypto-1.0.1f.a

# --- openssl 1.0.1g (fixed) ---
tar xzf src/openssl-1.0.1g.tar.gz
cd openssl-1.0.1g
sed -i 's/-DTERMIO //' Configure
sed -i 's/# define TERMIO/# define TERMIOS/' crypto/ui/ui_openssl.c
./config no-shared
make -j"$(nproc)" build_crypto build_ssl
cd ..
cp openssl-1.0.1g/libssl.a out/libssl-1.0.1g.a
cp openssl-1.0.1g/libcrypto.a out/libcrypto-1.0.1g.a

# --- the heartbleed probe, linked against each library set ---
gcc -O2 -no-pie -I openssl-1.0.1f/include hb.c -o out/hb-1.0.1f \
  -Wl,--start-group openssl-1.0.1f/libssl.a openssl-1.0.1f/libcrypto.a \
  -Wl,--end-group -ldl -lpthread
gcc -O2 -no-pie -I openssl-1.0.1g/include hb.c -o out/hb-1.0.1g \
  -Wl,--start-group openssl-1.0.1g/libssl.a openssl-1.0.1g/libcrypto.a \
  -Wl,--end-group -ldl -lpthread

echo "BUILD COMPLETE"
