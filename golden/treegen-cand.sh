#!/bin/sh
# treegen-cand 0.1.0 — the candidate tree generator for the fs-tree-build
# court. Identical to the reference, except it writes DIFFERENT content for
# src/main.c and DROPS build/config: the seeded filesystem-tree divergences
# the court must observe. Like the reference, it produces a tree, not text.
set -u
spec=""
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --spec) spec="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$spec" ] && [ -n "$out" ] || exit 2
rm -rf "$out"
while IFS=$'\t' read -r path content || [ -n "$path" ]; do
  [ -z "$path" ] && continue
  case "$path" in \#*) continue ;; esac
  mkdir -p "$out/$(dirname "$path")"
  if [ "$path" = "src/main.c" ]; then
    printf '%s\n' "int main(void){return 0;}" > "$out/$path"
  elif [ "$path" = "build/config" ]; then
    continue
  else
    printf '%s\n' "$content" > "$out/$path"
  fi
done < "$spec"
exit 0
