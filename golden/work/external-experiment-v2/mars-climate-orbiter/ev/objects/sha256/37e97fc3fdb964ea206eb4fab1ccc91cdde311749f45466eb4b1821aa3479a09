#!/bin/sh
# The BUGGY flight software (1999): the ground command's lbf-s value is
# consumed AS newton-seconds — the unit mismatch that sent the orbiter off
# course.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
impulse=$(grep -o '"impulse_[a-z_]*": *[0-9.]*' "$file" | grep -o '[0-9.]*$')
printf '{"impulse_n_s":%s}\n' "$impulse"
exit 0
