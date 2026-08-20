#!/bin/sh
# ref-cli 1.8.2 — reference CLI for the golden-path court.
# Parses directive lines; on a malformed directive it prints a prefixed
# diagnostic to stderr and exits 2 (reference exit class).
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
