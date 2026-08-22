#!/bin/sh
# The Log4Shell launcher — the VULNERABLE jar set (Log4j 2.14.1).
# The classpath is relative to the staged case work directory (the side's
# cwd, where the v3 runner stages the corpus). $1 is the fixture object
# path (root-relative, resolvable from the cwd).
#
# The JVM is tuned to fit the harness's per-side address-space envelope
# (RLIMIT_AS 2 GiB) with margin on every JVM: the compressed class space is
# capped (its default reservation is ~1 GiB of VIRTUAL address space), the
# heap, metaspace ceiling, and code cache are capped, and thread stacks are
# halved — otherwise the JVM's native reservations intermittently exceed the
# envelope and the runtime dies with "There is insufficient memory for the
# Java Runtime Environment to continue" (fatal error, exit 1) on some
# JVM/kernel/glibc combinations, exactly where CI runs.
exec java \
  -Xmx128m \
  -XX:CompressedClassSpaceSize=64m \
  -XX:MaxMetaspaceSize=96m \
  -XX:ReservedCodeCacheSize=48m \
  -Xss512k \
  -XX:-UsePerfData \
  -cp "builds/probe.jar:builds/lib/log4j-api-2.14.1.jar:builds/lib/log4j-core-2.14.1.jar" \
  Log4ShellProbe "$1"
