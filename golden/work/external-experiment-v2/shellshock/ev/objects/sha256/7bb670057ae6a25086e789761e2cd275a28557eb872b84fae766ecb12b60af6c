#!/bin/sh
# CVE-2014-6271 (bash "Shellshock") — the FIXED importer. An environment
# function string is imported; ONLY the function definition is honored and
# anything after the closing brace is inert. (The historical defect executed
# the trailing code.)
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || { echo "sh: no import file" >&2; exit 2; }
while IFS= read -r entry || [ -n "$entry" ]; do
  case "$entry" in
    f\(\)*) : ;; # import the function definition only
    *) : ;;      # trailing code is inert
  esac
done <"$file"
exit 0
