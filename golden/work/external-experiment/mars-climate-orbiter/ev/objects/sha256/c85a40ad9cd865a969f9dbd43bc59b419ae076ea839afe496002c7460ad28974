#!/bin/sh
# Mars Climate Orbiter (1999) — the FIXED thruster command processor. The
# ground system sent impulse in pound-force-seconds; the flight software
# converts lbf-s to newton-seconds (1 lbf-s = 4.4482216152605 N-s) before
# the trajectory model consumes it.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
units=$(grep -o '"units":[^,}]*' "$file" | cut -d'"' -f4)
impulse=$(grep -o '"impulse_[a-z_]*": *[0-9.]*' "$file" | grep -o '[0-9.]*$')
case "$units" in
  lbf-s)
    # Convert to newton-seconds with the trajectory model's precision.
    n=$(awk -v v="$impulse" 'BEGIN { printf "%.4f", v * 4.4482216152605 }')
    printf '{"impulse_n_s":%s}\n' "$n"
    ;;
  n-s)
    printf '{"impulse_n_s":%s}\n' "$impulse"
    ;;
  *) echo "mars: unknown units $units" >&2; exit 1 ;;
esac
exit 0
