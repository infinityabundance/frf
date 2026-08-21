#!/bin/sh
# The BUGGY importer (CVE-2014-6271): the entire import string is executed,
# so trailing code after the function definition runs with the function's
# privileges.
set -u
file=""
for arg in "$@"; do case "$arg" in *) file="$arg" ;; esac; done
[ -n "$file" ] || { echo "sh: no import file" >&2; exit 2; }
. "$file" # BUG: sources the whole string — function AND trailing code
exit 0
