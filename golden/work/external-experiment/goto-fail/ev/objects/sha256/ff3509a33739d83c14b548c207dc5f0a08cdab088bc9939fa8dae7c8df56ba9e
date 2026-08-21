#!/bin/sh
# The BUGGY verifier (CVE-2014-1266): a duplicated `goto fail;` skips the
# signature comparison. Any record whose header parses is accepted; the
# signature is never checked.
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
# goto fail;   /* BUG: verification skipped */
# goto fail;
echo "tls: handshake accepted"
exit 0
