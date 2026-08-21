#!/bin/sh
# A clean candidate: a different implementation of the FIXED parser —
# identical dates on every input.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
d=$(grep -o '"date": *"[^"]*"' "$file" | cut -d'"' -f4)
mm=${d%%/*}
rest=${d#*/}
dd=${rest%%/*}
yy=${rest##*/}
if [ "$yy" -lt 70 ] 2>/dev/null; then
  yyyy="20$yy"
else
  yyyy="19$yy"
fi
printf '{"date":"%s-%s-%s"}\n' "$yyyy" "$mm" "$dd"
exit 0
