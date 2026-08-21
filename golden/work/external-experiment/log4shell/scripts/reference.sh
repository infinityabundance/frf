#!/bin/sh
# CVE-2021-44228 (Log4j "Log4Shell") — the FIXED lookup resolver. A
# configuration's `${key}` lookups expand from the lookup table; a lookup
# that would recurse into itself is detected by the cycle guard and resolves
# to a fixed marker.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || exit 2
a=$(grep -o '"a": *"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
b=$(grep -o '"b": *"[^"]*"' "$file" | head -1 | cut -d'"' -f4)
CYCLE_GUARD=on
resolve() {
  key=$1
  depth=$2
  case "$key" in a) val=$a ;; b) val=$b ;; *) val=$key ;; esac
  case "$val" in
    \$\{*\})
      if [ "$CYCLE_GUARD" = "on" ]; then
        echo "<cycle-detected>"
        return
      fi
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
