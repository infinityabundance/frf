/*
 * The Goto Fail (CVE-2014-1266) handshake verifier — the semantic second
 * domain of the v3 corpus.
 *
 * A TLS handshake record carries a signature; the signature must match the
 * data's checksum or the handshake is refused. This program models the
 * historical Apple Secure Transport defect: the buggy build (compiled with
 * -DGO_TO_FAIL) carries a duplicated `goto fail;` that skips the signature
 * comparison entirely, so EVERY handshake — including a tampered one — is
 * accepted. The clean build performs the comparison.
 *
 * The observable is a VERDICT (accepted/refused), not a byte diff: the
 * `tls.verdict` axis is served by an external comparator that reads the
 * verdict line, exactly as the memory-leak study's semantic comparators
 * read the leak observables. This is the "it generalizes" proof: the same
 * recipe (semantic comparator + minimizer kappa-route + mutation challenge)
 * works for a TLS-verdict domain, not only for information leaks.
 *
 * Record format (text, one record per file):
 *
 *     sig=<hex>      the claimed signature (lowercase hex)
 *     len=<n>        the declared payload length (decimal) — the TLS record
 *                    header's length field, so the payload length is a
 *                    first-class record dimension the minimizer can reduce
 *     data=<ascii>   the signed data; its length MUST equal len, and its
 *                    byte-sum mod 256 is the expected sig
 *
 * Exit: 0 = handshake accepted, 1 = signature mismatch (refused),
 *       2 = malformed record (no sig / no data / bad hex / length mismatch).
 * Verdict lines: "tls: handshake accepted" (stdout) and
 *                "tls: signature mismatch (got X, expected Y)" (stderr).
 *
 * Build (see build/build.sh):
 *     gcc -O2 -o sslcheck-clean src/sslcheck.c
 *     gcc -O2 -DGO_TO_FAIL -o sslcheck-buggy src/sslcheck.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char checksum(const char *data) {
    unsigned int sum = 0;
    for (const char *p = data; *p; p++) {
        sum = (sum + (unsigned char)*p) % 256;
    }
    return (unsigned char)sum;
}

int main(int argc, char **argv) {
    const char *file = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') file = argv[i];
    }
    if (!file) {
        fprintf(stderr, "tls: no record file\n");
        return 2;
    }

    char sig[1024] = "";
    char data[65536] = "";
    long len = -1;
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "tls: cannot open record\n");
        return 2;
    }
    char line[65536];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (strncmp(line, "sig=", 4) == 0) {
            snprintf(sig, sizeof sig, "%s", line + 4);
        } else if (strncmp(line, "len=", 4) == 0) {
            len = strtol(line + 4, NULL, 10);
        } else if (strncmp(line, "data=", 5) == 0) {
            snprintf(data, sizeof data, "%s", line + 5);
        }
    }
    fclose(f);

    if (sig[0] == 0 || data[0] == 0 || len < 0) {
        fprintf(stderr, "tls: missing signature, length, or data\n");
        return 2;
    }
    if (strlen(data) != (size_t)len) {
        fprintf(stderr, "tls: length mismatch (declared %ld, got %zu)\n", len, strlen(data));
        return 2;
    }
    for (const char *p = sig; *p; p++) {
        if (hexval(*p) < 0) {
            fprintf(stderr, "tls: malformed signature\n");
            return 2;
        }
    }

    unsigned char want = checksum(data);
    char expected[8];
    snprintf(expected, sizeof expected, "%02x", want);

    int verified = strcmp(sig, expected) == 0;

#ifdef GO_TO_FAIL
    /* The historical CVE-2014-1266 shape: the duplicated `goto fail;`
     * skips the comparison below — the record is accepted whatever the
     * signature says. */
    if (!verified) goto fail;
fail:
    printf("tls: handshake accepted\n");
    return 0;
#else
    if (verified) {
        printf("tls: handshake accepted\n");
        return 0;
    }
    fprintf(stderr, "tls: signature mismatch (got %s, expected %s)\n", sig, expected);
    return 1;
#endif
}
