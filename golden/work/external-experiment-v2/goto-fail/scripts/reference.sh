#!/bin/sh
# CVE-2014-1266 (Apple Secure Transport, "goto fail") — the FIXED verifier.
# A TLS handshake record carries a signature; the signature must match the
# data's checksum or the handshake is refused. (The historical defect was a
# duplicated `goto fail;` that skipped this comparison entirely.)
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || { echo "tls: no record file" >&2; exit 2; }
sig=""
data=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    sig=*) sig=${line#sig=} ;;
    data=*) data=${line#data=} ;;
  esac
done <"$file"
[ -n "$sig" ] || { echo "tls: missing signature" >&2; exit 1; }
[ -n "$data" ] || { echo "tls: missing data" >&2; exit 1; }
# The record checksum: the byte-sum of the data, mod 256, as lowercase hex.
sum=0
i=1
len=${#data}
while [ $i -le $len ]; do
  c=$(printf '%s' "$data" | cut -c$i)
  o=$(printf '%d' "'$c" 2>/dev/null || echo 0)
  sum=$(( (sum + o) % 256 ))
  i=$((i + 1))
done
expected=$(printf '%02x' $sum)
if [ "$sig" != "$expected" ]; then
  echo "tls: signature mismatch (got $sig, expected $expected)" >&2
  exit 1
fi
echo "tls: handshake accepted"
exit 0
