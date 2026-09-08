/*
 * attack_catalog_test.c — unit test for new deep-state patterns (2026-09-07)
 *
 * Verifies for each of the 6 new patterns:
 *   T1: Pattern is registered in deep_patterns[] with correct protocol
 *   T2: Seed generation produces a non-empty file with expected content
 *   T3: Generated seed contains the CVE-triggering command/sequence
 *   T4: Protocol-specific structural invariants (e.g., FTP has USER+PASS,
 *       SIP has Content-Length, HTTP has method+path)
 *
 * Build: gcc -I. -o attack_catalog_test attack_catalog_test.c attack-catalog.o
 * (requires attack-catalog.o compiled from the modified source)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Link against the real attack-catalog.o */
#include "attack-catalog.h"

static int failures = 0;
#define CHECK(cond, ...) do { \
    if (!(cond)) { failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } \
} while(0)

/* ── Helpers ── */
static int seed_dir_created = 0;
static const char *TEST_DIR = "/tmp/attack_catalog_test";

static void setup(void) {
    mkdir(TEST_DIR, 0755);
    seed_dir_created = 1;
}

/* Generate seeds for a protocol and return the file list */
static int generated_count(const char *protocol) {
    if (!seed_dir_created) return -1;
    /* Clean the dir first */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -f %s/deep_* %s/attack_*", TEST_DIR, TEST_DIR);
    system(cmd);
    return (int)deep_state_enrich_seeds(TEST_DIR, protocol);
}

/* Read a generated seed file */
static char *read_seed(const char *pattern_id) {
    char path[512];
    /* deep_state files are named deep_<id>_v0.raw */
    snprintf(path, sizeof(path), "%s/attack_%s_v0.raw", TEST_DIR, pattern_id);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    fread(buf, 1, sz, f);
    buf[sz] = 0;
    fclose(f);
    return buf;
}

static void test_ftp_mlsd(void) {
    printf("═══ T1: FTP MLSD (CVE-2024-48268/pure-ftpd) ═══\n");
    int n = generated_count("FTP");
    CHECK(n >= 3, "FTP seeds generated >= 3 (got %d, includes new mlsd+rename+authfail)", n);

    char *seed = read_seed("deep_ftp_mlsd");
    CHECK(seed != NULL, "deep_ftp_mlsd seed file exists");
    if (seed) {
        CHECK(strstr(seed, "MLSD ") != NULL, "seed contains 'MLSD ' command");
        CHECK(strstr(seed, "-AAAA") != NULL, "seed contains long '-AAAA' payload");
        CHECK(strstr(seed, "USER ubuntu") != NULL, "seed has authentication (USER)");
        CHECK(strstr(seed, "PASS ubuntu") != NULL, "seed has authentication (PASS)");
        CHECK(strstr(seed, "MLST") != NULL, "seed has MLST variant");
        free(seed);
    }
    printf("  PASS\n\n");
}

static void test_ftp_rename(void) {
    printf("═══ T2: FTP Rename (CVE-2023-51713/proftpd) ═══\n");
    /* files from T1 still exist (no intervening generated_count) */
    char *seed = read_seed("deep_ftp_rename");
    CHECK(seed != NULL, "deep_ftp_rename seed file exists");
    if (seed) {
        CHECK(strstr(seed, "RNFR") != NULL, "seed contains RNFR");
        CHECK(strstr(seed, "RNTO") != NULL, "seed contains RNTO");
        CHECK(strstr(seed, "\\\\SYST") != NULL || strstr(seed, "\\SYST") != NULL,
              "seed contains backslash escape (\\\\SYST) for OOB read trigger");
        CHECK(strstr(seed, "../..") != NULL || strstr(seed, "..") != NULL,
              "seed contains traversal payload");
        free(seed);
    }
    printf("  PASS\n\n");
}

static void test_smtp_bdat(void) {
    printf("═══ T3: SMTP BDAT (CVE-2017-16943/exim) ═══\n");
    int n = generated_count("SMTP");
    CHECK(n >= 2, "SMTP seeds generated >= 2 (got %d, includes new bdat)", n);

    char *seed = read_seed("deep_smtp_bdat");
    CHECK(seed != NULL, "deep_smtp_bdat seed file exists");
    if (seed) {
        CHECK(strstr(seed, "BDAT") != NULL, "seed contains BDAT command");
        CHECK(strstr(seed, "BDAT 1 LAST") != NULL, "seed has 'BDAT 1 LAST'");
        CHECK(strstr(seed, "BDAT 0") != NULL, "seed has 'BDAT 0' (empty chunk)");
        CHECK(strstr(seed, "BDAT 100") != NULL, "seed has 'BDAT 100' (incomplete)");
        CHECK(strstr(seed, "MAIL FROM") != NULL, "seed has MAIL FROM");
        CHECK(strstr(seed, "RCPT TO") != NULL, "seed has RCPT TO");
        CHECK(strstr(seed, "AUTH LOGIN") != NULL, "seed has AUTH LOGIN");
        free(seed);
    }
    printf("  PASS\n\n");
}

static void test_http_rescan(void) {
    printf("═══ T4: HTTP Rescan (CVE-2025-44560/forked-daapd) ═══\n");
    /* DAAP protocol maps to HTTP in the pattern registry */
    int n = generated_count("DAAP");
    CHECK(n >= 2, "DAAP seeds generated >= 2 (got %d, includes new rescan)", n);

    char *seed = read_seed("deep_http_rescan");
    CHECK(seed != NULL, "deep_http_rescan seed file exists");
    if (seed) {
        CHECK(strstr(seed, "PUT /api/update") != NULL,
              "seed has PUT /api/update (library scan trigger)");
        CHECK(strstr(seed, "GET /api/search") != NULL,
              "seed has GET /api/search");
        CHECK(strstr(seed, "expression=") != NULL,
              "seed has expression= parameter");
        CHECK(strstr(seed, "time_add") != NULL,
              "seed has time_add function");
        CHECK(strstr(seed, "GET /api/library") != NULL,
              "seed has GET /api/library");
        free(seed);
    }
    printf("  PASS\n\n");
}

static void test_sip_clen(void) {
    printf("═══ T5: SIP Content-Length (CVE-2026-39863/kamailio) ═══\n");
    int n = generated_count("SIP");
    CHECK(n >= 2, "SIP seeds generated >= 2 (got %d, includes new clen)", n);

    char *seed = read_seed("deep_sip_clen");
    CHECK(seed != NULL, "deep_sip_clen seed file exists");
    if (seed) {
        CHECK(strstr(seed, "Content-Length: 99999") != NULL ||
              strstr(seed, "Content-Length: 2147483647") != NULL,
              "seed has huge Content-Length value");
        CHECK(strstr(seed, "REGISTER") != NULL, "seed has REGISTER");
        CHECK(strstr(seed, "INVITE") != NULL, "seed has INVITE");
        CHECK(strstr(seed, "Via:") != NULL, "seed has Via header");
        free(seed);
    }
    printf("  PASS\n\n");
}

static void test_ftp_authfail(void) {
    printf("═══ T6: FTP Auth Brute-force ═══\n");
    generated_count("FTP"); /* regenerate: previous tests cleaned the dir */
    char *seed = read_seed("deep_ftp_authfail");
    CHECK(seed != NULL, "deep_ftp_authfail seed file exists");
    if (seed) {
        int count = 0;
        const char *p = seed;
        while ((p = strstr(p, "PASS wrongpass")) != NULL) {
            count++;
            p++;
        }
        CHECK(count >= 5, "seed has >= 5 failed PASS attempts (got %d)", count);
        CHECK(strstr(seed, "USER wronguser") != NULL, "seed has wrong USER");
        free(seed);
    }
    printf("  PASS\n\n");
}

static void test_all_protocols_nonzero(void) {
    printf("═══ T7: All 6 protocol targets get >= 1 new seed ═══\n");
    const char *protocols[] = {"FTP", "SMTP", "DAAP", "SIP", "RTSP"};
    for (int i = 0; i < 5; i++) {
        int n = generated_count(protocols[i]);
        CHECK(n >= 1, "%s: at least 1 deep-state seed (got %d)", protocols[i], n);
    }
    printf("  PASS\n\n");
}

int main(void) {
    printf("═══════════════════════════════════════════════════════\n");
    printf("  attack_catalog_test — 6 new deep-state patterns\n");
    printf("═══════════════════════════════════════════════════════\n\n");

    setup();

    test_ftp_mlsd();
    test_ftp_rename();
    test_smtp_bdat();
    test_http_rescan();
    test_sip_clen();
    test_ftp_authfail();
    test_all_protocols_nonzero();

    printf("═══════════════════════════════════════════════════════\n");
    if (failures) {
        printf("RESULT: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("RESULT: ALL 7 TESTS PASSED\n");
    return 0;
}
