#!/bin/sh
# The classic two-digit-year parser — the FIXED version. A date like
# MM/DD/YY maps YY < 70 to 20YY (the Y2K window) and 70-99 to 19YY.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
d=$(grep -o '"date": *"[^"]*"' "$file" | cut -d'"' -f4)
mm=${d%%/*}
rest=${d#*/}
dd=${rest%%/*}
yy=${rest##*/}
case "$yy" in
  [0-6][0-9]) yyyy="20$yy" ;;
  *) yyyy="19$yy" ;;
esac
printf '{"date":"%s-%s-%s"}\n' "$yyyy" "$mm" "$dd"
exit 0
