#!/bin/sh
# A clean candidate: a different implementation of the FIXED processor —
# identical telemetry on every command.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
units=$(grep -o '"units":[^,}]*' "$file" | cut -d'"' -f4)
impulse=$(grep -o '"impulse_[a-z_]*": *[0-9.]*' "$file" | grep -o '[0-9.]*$')
if [ "$units" = "lbf-s" ]; then
  n=$(awk -v v="$impulse" 'BEGIN { printf "%.4f", v * 4.4482216152605 }')
else
  n=$impulse
fi
printf '{"impulse_n_s":%s}\n' "$n"
exit 0
