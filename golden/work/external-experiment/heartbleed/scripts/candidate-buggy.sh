#!/bin/sh
# The BUGGY responder (CVE-2014-0160): echoes `declared_length` bytes of
# payload regardless of how many were actually present — the missing bounds
# check reads past the end of the request. The disclosure is modeled
# deterministically: missing bytes are padded with 0x58 ('X').
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
type=$(cut -c1-2 "$file")
decl=$(cut -c3-6 "$file")
payload_hex=$(cut -c7- "$file" | tr -d '\n')
decl_num=$(( 0x$decl ))
out="$type$decl$payload_hex"
while [ ${#out} -lt $(( 2 + 4 + decl_num * 2 )) ]; do
  out="${out}58"
done
printf '%s' "$out"
exit 0
