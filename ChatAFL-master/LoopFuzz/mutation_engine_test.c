/*
 * mutation_engine_test.c — unit test for Protocol-Aware Mutation Engine.
 *
 * 2026-09-07 rewrite: links the REAL implementation in mutation-ops.o
 * (previously this file tested a hand-copied replica that had already
 * drifted from afl-fuzz.c). mut_ur() is overridden with a scripted
 * sequence so every branch is deterministic.
 *
 * Tests:
 *   T1: Auth-Prefix Protection — USER/PASS restored after corruption
 *   T2: Auth-Prefix Protection — EHLO/AUTH (SMTP) restored
 *   T3: Auth-Prefix Protection — non-auth commands NOT restored
 *   T4: CVE Mutation S1 — SIP Content-Length overflow
 *   T5: CVE Mutation S2a — FTP RNTO trailing backslash
 *   T6: CVE Mutation S2b — FTP MLSD argument extension
 *   T7: CVE Mutation S3 — SMTP AUTH base64 boundary
 *   T8: CVE Mutation S4 — RTSP Session token replacement
 *   T9: Auth protection restores content exactly (bit-for-bit)
 *   T10: CVE mutations don't fire on wrong protocol / short buffer
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "mutation-ops.h"

static int failures = 0;
#define CHECK(cond, ...) do { \
    if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } \
} while(0)

/* ── Scripted RNG (strong override of the weak default) ── */
static uint32_t script_vals[32];
static int script_len = 0, script_pos = 0;
uint32_t mut_ur(uint32_t bound) {
    uint32_t v = (script_pos < script_len) ? script_vals[script_pos++] : 0;
    return v % bound;
}
static void rng_script(uint32_t first, ...) {
    va_list ap; script_len = 0; script_pos = 0;
    va_start(ap, first);
    for (uint32_t v = first; v != 0xFFFFFFFFu; v = va_arg(ap, uint32_t))
        script_vals[script_len++] = v;
    va_end(ap);
}
#define SCRIPT(...) rng_script(__VA_ARGS__, 0xFFFFFFFFu)
#define CLEAR_SCRIPT() do { script_len = 0; script_pos = 0; } while (0)

#define MAX_BUF (1 << 20)

static uint32_t load(uint8_t *buf, const char *s) {
    uint32_t n = (uint32_t)strlen(s);
    memcpy(buf, s, n);
    return n;
}

int main(void) {
    printf("═══ Mutation Engine Tests (REAL mutation-ops.o) ═══\n\n");
    static uint8_t orig[MAX_BUF], mut[MAX_BUF];

    /* ── T1: FTP USER/PASS restored ── */
    printf("T1: FTP auth-prefix restore\n");
    {
        const char *seed = "USER ubuntu\r\nPASS ubuntu\r\nLIST\r\n";
        uint32_t n = load(orig, seed);
        memcpy(mut, orig, n);
        /* Havoc corrupts the username */
        memcpy(mut + 5, "\x01\x02\x03\x04\x05\x06", 6);
        CLEAR_SCRIPT();
        uint32_t r = auth_prefix_protect(mut, orig, n, n, "FTP");
        CHECK(r > 0, "restored > 0 (got %u)", r);
        CHECK(memcmp(mut, orig, n) == 0, "USER line restored exactly");
        CHECK(auth_prefix_calls >= 1, "auth_prefix_calls incremented");
        printf("  restored=%u\n\n", r);
    }

    /* ── T2: SMTP EHLO/AUTH restored ── */
    printf("T2: SMTP auth-prefix restore\n");
    {
        const char *seed = "EHLO localhost\r\nAUTH LOGIN dXNlcg==\r\nMAIL FROM:<a@b>\r\n";
        uint32_t n = load(orig, seed);
        memcpy(mut, orig, n);
        mut[5] = 'X'; mut[20] = 'Y'; /* corrupt EHLO + AUTH */
        CLEAR_SCRIPT();
        uint32_t r = auth_prefix_protect(mut, orig, n, n, "SMTP");
        CHECK(memcmp(mut, orig, n) == 0, "EHLO+AUTH lines restored exactly");
        CHECK(r >= (uint32_t)strlen("EHLO localhost\r\n"), "restored covers EHLO");
        printf("  restored=%u\n\n", r);
    }

    /* ── T3: non-auth command NOT restored ── */
    printf("T3: non-auth command untouched\n");
    {
        const char *seed = "USER ubuntu\r\nPASS ubuntu\r\nLIST /tmp\r\n";
        uint32_t n = load(orig, seed);
        memcpy(mut, orig, n);
        memcpy(mut + 26, "ZZZZZ", 5); /* corrupt LIST argument */
        CLEAR_SCRIPT();
        uint32_t r = auth_prefix_protect(mut, orig, n, n, "FTP");
        CHECK(r == 0, "no restore for LIST corruption (got %u)", r);
        CHECK(memcmp(mut + 26, "ZZZZZ", 5) == 0, "LIST corruption preserved");
        printf("  PASS\n\n");
    }

    /* ── T4: S1 Content-Length overflow ── */
    printf("T4: SIP Content-Length overflow (S1)\n");
    {
        const char *seed =
            "REGISTER sip:33@127.0.0.1 SIP/2.0\r\n"
            "Content-Length: 0\r\n\r\n";
        uint32_t n = load(mut, seed);
        uint32_t before = cve_mutations_applied;
        SCRIPT(0u); /* overflow_vals[0] = INT_MAX */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "SIP");
        CHECK(fired == 1, "S1 fired");
        CHECK(cve_mutations_applied == before + 1, "counter incremented");
        CHECK(strstr((char *)mut, "Content-Length: 2147483647") != NULL,
              "CL replaced with INT_MAX");
        CHECK(strstr((char *)mut, "SIP/2.0") != NULL, "request line intact");
        printf("  PASS\n\n");
    }

    /* ── T5: S2a RNTO trailing backslash ── */
    printf("T5: FTP RNTO trailing backslash (S2a)\n");
    {
        const char *seed = "USER u\r\nRNTO /tmp/x\r\nQUIT\r\n";
        uint32_t n = load(mut, seed);
        uint32_t orig_n = n;
        SCRIPT(1u); /* insert_char = '\\' (ternary: nonzero → backslash) */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "FTP");
        CHECK(fired == 1, "S2a fired");
        CHECK(n == orig_n + 1, "len grew by 1 (%u -> %u)", orig_n, n);
        CHECK(memmem(mut, n, "RNTO /tmp/x\\\r", 13) != NULL,
              "backslash inserted before CR");
        printf("  PASS\n\n");
    }

    /* ── T6: S2b MLSD argument extension ── */
    printf("T6: FTP MLSD argument extension (S2b)\n");
    {
        const char *seed = "MLSD /\r\nQUIT\r\n";
        uint32_t n = load(mut, seed);
        uint32_t orig_n = n;
        SCRIPT(0u); /* extend = 100 */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "FTP");
        CHECK(fired == 1, "S2b fired");
        CHECK(n == orig_n + 100, "len grew by 100 (%u -> %u)", orig_n, n);
        CHECK(mut[5] == 'A' && mut[104] == 'A', "'A' run prepended to arg");
        CHECK(mut[105] == '/' && mut[106] == '\r',
              "original arg + CRLF preserved after extension");
        printf("  PASS\n\n");
    }

    /* ── T7: S3 AUTH base64 boundary ── */
    printf("T7: SMTP AUTH base64 boundary (S3)\n");
    {
        const char *seed = "AUTH LOGIN dXNlcm5hbWU=\r\nQUIT\r\n";
        uint32_t n = load(mut, seed);
        uint32_t orig_n = n;
        SCRIPT(2u, 1u); /* choice=2 (char replace), mut_ur(2)=1 → '/' */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        CHECK(fired == 1, "S3 fired");
        CHECK(n == orig_n, "length unchanged for char replace");
        CHECK(strchr((char *)mut + 11, '/') != NULL ||
              strchr((char *)mut + 11, '+') != NULL,
              "b64 char replaced with + or /");
        printf("  PASS\n\n");
    }

    /* ── T8: S4 RTSP Session token ── */
    printf("T8: RTSP Session token replacement (S4)\n");
    {
        const char *seed =
            "PLAY rtsp://x/m RTSP/1.0\r\nSession: ABCDEFGH\r\n\r\n";
        uint32_t n = load(mut, seed);
        SCRIPT(0u); /* session_ids[0] = "000022B8" */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "RTSP");
        CHECK(fired == 1, "S4 fired");
        CHECK(strstr((char *)mut, "Session: 000022B8") != NULL,
              "session id replaced with deterministic counter");
        printf("  PASS\n\n");
    }

    /* ── T9: exact restore (bit-for-bit) ── */
    printf("T9: exact restore bit-for-bit\n");
    {
        const char *seed = "USER ubuntu\r\nPASS ubuntu\r\nSYST\r\n";
        uint32_t n = load(orig, seed);
        memcpy(mut, orig, n);
        for (uint32_t k = 0; k < n; k++) mut[k] ^= 0x55; /* total havoc */
        CLEAR_SCRIPT();
        (void)auth_prefix_protect(mut, orig, n, n, "FTP");
        CHECK(memcmp(mut, orig, strlen("USER ubuntu\r\n")) == 0,
              "USER line bit-identical after restore");
        CHECK(memcmp(mut + strlen("USER ubuntu\r\n"),
                     orig + strlen("USER ubuntu\r\n"),
                     strlen("PASS ubuntu\r\n")) == 0,
              "PASS line bit-identical after restore");
        printf("  PASS\n\n");
    }

    /* ── T10: wrong protocol / short buffer no-op ── */
    printf("T10: wrong protocol no-op\n");
    {
        const char *seed = "GET /api/config HTTP/1.1\r\nHost: x\r\n\r\n";
        uint32_t n = load(mut, seed);
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "IRC");
        CHECK(fired == 0, "IRC proto: no mutation");
        fired = cve_targeted_mutate(mut, &n, MAX_BUF, "FTP");
        CHECK(fired == 0, "FTP proto: no HTTP mutation");
        uint32_t r = auth_prefix_protect(mut, orig, n, n, "IRC");
        CHECK(r == 0, "IRC proto: no auth restore");
        uint32_t tiny = 3;
        fired = cve_targeted_mutate(mut, &tiny, MAX_BUF, "FTP");
        CHECK(fired == 0, "len < 8: no mutation");
        printf("  PASS\n\n");
    }

    printf("══════════════════════════════════════════\n");
    if (failures) {
        printf("RESULT: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("RESULT: ALL 10 TESTS PASSED\n");
    return 0;
}
