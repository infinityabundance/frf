#!/bin/sh
# The BUGGY resolver (CVE-2021-44228): nested lookups expand recursively
# with NO cycle detection — a self-referential configuration expands until
# the internal depth cap instead of being refused.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
a=$(grep -o '"a": *"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
b=$(grep -o '"b": *"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
CYCLE_GUARD=off
resolve() {
  key=$1
  depth=$2
  case "$key" in a) val=$a ;; b) val=$b ;; *) val=$key ;; esac
  case "$val" in
    \$\{*\})
      inner=${val#\$\{}
      inner=${inner%\}}
      depth=$((depth + 1))
      if [ $depth -ge 8 ]; then
        echo "<depth-cap>"
        return
      fi
      resolve "$inner" "$depth"
      ;;
    *) echo "$val" ;;
  esac
}
printf '{"resolved":"%s"}\n' "$(resolve a 0)"
exit 0
