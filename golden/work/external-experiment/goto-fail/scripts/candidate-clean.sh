#!/bin/sh
# A clean candidate: a different implementation of the FIXED verifier —
# identical verdicts on every record.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || { echo "tls: no record file" >&2; exit 2; }
sig=""
data=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in sig=*) sig=${line#sig=};; data=*) data=${line#data=};; esac
done <"$file"
sum=0
i=1
len=${#data}
while [ $i -le $len ]; do
  c=$(printf '%s' "$data" | cut -c$i)
  sum=$(( (sum + $(printf '%d' "'$c" 2>/dev/null || echo 0)) % 256 ))
  i=$((i + 1))
done
if [ "$sig" != "$(printf '%02x' $sum)" ]; then
  echo "tls: signature mismatch" >&2
  exit 1
fi
echo "tls: handshake accepted"
exit 0
