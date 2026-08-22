#!/bin/sh
# The Log4Shell launcher — the FIXED jar set (Log4j 2.17.1).
# The classpath is relative to the staged case work directory (the side's
# cwd, where the v3 runner stages the corpus). $1 is the fixture object
# path (root-relative, resolvable from the cwd). The JVM heap + compressed
# class space are capped so the process fits the harness's per-side
# address-space envelope (RLIMIT_AS 2 GiB).
exec java -XX:CompressedClassSpaceSize=64m -Xmx256m -cp "builds/probe.jar:builds/lib/log4j-api-2.17.1.jar:builds/lib/log4j-core-2.17.1.jar" Log4ShellProbe "$1"
