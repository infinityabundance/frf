#!/bin/sh
# A clean candidate: a different implementation of the FIXED responder —
# identical wire bytes on every record.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
r=$(cat "$file")
type=$(printf '%s' "$r" | cut -c1-2)
decl=$(printf '%s' "$r" | cut -c3-6)
payload_hex=$(printf '%s' "$r" | cut -c7- | tr -d '\n')
if [ $((0x$decl)) -le $(( ${#payload_hex} / 2 )) ]; then
  printf '%s%s%s' "$type" "$decl" "$payload_hex"
else
  printf '15030000020268'
fi
exit 0
