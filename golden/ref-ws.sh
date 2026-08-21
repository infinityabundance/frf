#!/bin/sh
# ref-ws 1.0 — a reference whose diagnostic lines carry TRAILING WHITESPACE.
# The normalized court compares the stderr surface after the declared
# normalizer trims it; the raw streams (with the whitespace) survive as the
# normalizer request evidence.
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
      echo "tool: $file:$line: unknown directive '$word'   " >&2
      exit 2
      ;;
  esac
done <"$file"
exit 0
