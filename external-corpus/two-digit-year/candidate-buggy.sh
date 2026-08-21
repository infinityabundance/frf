#!/bin/sh
# The BUGGY parser: every two-digit year is 19YY — the defect that was
# endemic before Y2K remediation (a 2000-01-01 date becomes 1900-01-01).
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
d=$(grep -o '"date": *"[^"]*"' "$file" | cut -d'"' -f4)
mm=${d%%/*}
rest=${d#*/}
dd=${rest%%/*}
yy=${rest##*/}
printf '{"date":"19%s-%s-%s"}\n' "$yy" "$mm" "$dd"
exit 0
