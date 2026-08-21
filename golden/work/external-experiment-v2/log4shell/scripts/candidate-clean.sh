#!/bin/sh
# A clean candidate: a different implementation of the FIXED resolver —
# a direct cycle check on the top-level lookup.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
a=$(grep -o '"a": *"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
b=$(grep -o '"b": *"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
case "$a" in
  \$\{b\}) resolved="<cycle-detected>" ;;
  *) resolved=$a ;;
esac
printf '{"resolved":"%s"}\n' "$resolved"
exit 0
