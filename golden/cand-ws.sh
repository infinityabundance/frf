#!/bin/sh
# cand-ws 0.1.0 — a candidate whose diagnostic is IDENTICAL to the
# reference's except for the trailing whitespace the reference carries. The
# normalized court must call the stderr axis EQUIVALENT once the declared
# normalizer trims it; without the normalizer the raw first lines differ.
set -u

file=""
for arg in "$@"; do
  case "$arg" in
    --strict) ;;
    *) file="$arg" ;;
  esac
done

if [ -z "$file" ]; then
  echo "tool: no input file" >&2
  exit 2
fi

line=0
while IFS= read -r entry || [ -n "$entry" ]; do
  line=$((line + 1))
  case "$entry" in
    '' | \#*) continue ;;
    server\ * | listen\ * | log\ *) echo "ok: $entry" ;;
    *)
      word=${entry%% *}
      echo "tool: $file:$line: unknown directive '$word'" >&2
      exit 2
      ;;
  esac
done <"$file"
exit 0
