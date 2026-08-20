#!/bin/sh
# cand-cli 0.1.0 — candidate CLI for the golden-path court.
# Identical parsing and stdout; deliberately different diagnostic wording and
# a different malformed-input exit class (1 instead of the reference's 2).
# This divergence is the whole point of the court.
set -u

file=""
for arg in "$@"; do
  case "$arg" in
    --strict) ;;
    *) file="$arg" ;;
  esac
done

if [ -z "$file" ]; then
  echo "cand: no input file" >&2
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
      echo "error: unknown directive $word at line $line" >&2
      exit 1
      ;;
  esac
done <"$file"
exit 0
