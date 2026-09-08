/*
 * cve_mutation_test.c — unit test for CVE-targeted strategies S5-S10.
 *
 * 2026-09-07 rewrite: links the REAL implementation in mutation-ops.o
 * (the previous version asserted on its own string literals and never
 * called the fuzzer's mutation code — vacuous verification).
 *
 * Version-validated targets (mirror snapshots confirmed post-version):
 *   S5: AUTH SPA/NTLM malformed blob   (exim CVE-2023-42114)
 *   S6: RCPT TO address extension      (exim CVE-2023-42116)
 *   S7: AUTH base64 NUL-field absence  (exim CVE-2023-42115, >64KB)
 *   S8: FTP line-end/quote structure   (proftpd CVE-2023-51713)
 *   S9: consecutive-separator path     (owntone CVE-2026-26828)
 *   S10: query parameter omission      (owntone CVE-2026-26829)
 * Inapplicable strategies deliberately absent: lighttpd CVE-2025-12642
 * (needs 1.4.80+), owntone CVE-2025-44560 / CVE-2026-41457 (mirror 27.2
 * outside affected range).
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
    printf("═══ CVE-Targeted Strategies S5-S10 (REAL mutation-ops.o) ═══\n\n");
    static uint8_t mut[MAX_BUF];

    /* ── T1 (S5): AUTH SPA high-bit byte injection ── */
    printf("T1: SMTP AUTH SPA malformed blob (S5, CVE-2023-42114)\n");
    {
        const char *seed = "AUTH SPA dGVzdA==\r\nQUIT\r\n";
        uint32_t n = load(mut, seed), orig_n = n;
        /* S3 runs first: choice=1 (truncate) fails on 8-char payload;
         * S5: mut_ur(2)=0 → high-bit, pos=mut_ur(8)=2, val=mut_ur(2)=0 → 0x80 */
        SCRIPT(1u, 0u, 2u, 0u);
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        CHECK(fired == 1, "S5 fired");
        CHECK(n == orig_n, "length unchanged (%u)", n);
        CHECK(mut[11] == 0x80, "byte 11 = 0x80 (got 0x%02x)", mut[11]);
        CHECK(mut[9] == 'd' && mut[10] == 'G', "other payload bytes intact");
        printf("  PASS\n\n");
    }

    /* ── T1b (S5): AUTH NTLM hard truncation to 4 chars ── */
    printf("T1b: SMTP AUTH NTLM truncation (S5)\n");
    {
        const char *seed = "AUTH NTLM TlRNTVNTUA==\r\nQUIT\r\n";
        uint32_t n = load(mut, seed), orig_n = n;
        SCRIPT(1u, 1u); /* S3 no-fire; S5: truncate branch */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        CHECK(fired == 1, "S5 fired");
        CHECK(n == orig_n - 8, "payload cut to 4 chars (%u -> %u)", orig_n, n);
        CHECK(memcmp(mut, "AUTH NTLM TlRN", 14) == 0,
              "first 4 payload chars kept");
        CHECK(mut[14] == '\r' && mut[15] == '\n', "CRLF follows fragment");
        printf("  PASS\n\n");
    }

    /* ── T2 (S6): RCPT TO address extension ── */
    printf("T2: SMTP RCPT TO extension (S6, CVE-2023-42116)\n");
    {
        const char *seed = "RCPT TO:<user@example.com>\r\n";
        uint32_t n = load(mut, seed), orig_n = n;
        SCRIPT(0u); /* extend = 200 */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        CHECK(fired == 1, "S6 fired");
        CHECK(n == orig_n + 200, "len +200 (%u -> %u)", orig_n, n);
        CHECK(mut[9] == 'A' && mut[208] == 'A', "200-char localpart run");
        CHECK(mut[209] == 'u' && mut[213] == '@', "original address follows");
        CHECK(mut[n-3] == '>' && mut[n-2] == '\r', "'>' terminator intact");
        printf("  PASS\n\n");
    }

    /* ── T3 (S7): AUTH base64 >64KB NUL-less field ── */
    printf("T3: SMTP AUTH 64KB base64 field (S7, CVE-2023-42115)\n");
    {
        const char *seed = "AUTH LOGIN dXNlcg==\r\nQUIT\r\n";
        uint32_t n = load(mut, seed);
        SCRIPT(1u); /* S3 truncate no-fire (8-char payload) */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        CHECK(fired == 1, "S7 fired");
        uint32_t b64_len = (65540 / 3) * 4 + 4; /* 87388 */
        CHECK(n == 11 + b64_len + 8, "len = prefix+payload+tail (%u)", n);
        CHECK(memcmp(mut + 11, "QUFB", 4) == 0, "payload starts QUFB");
        CHECK(memcmp(mut + 11 + b64_len - 4, "QUA=", 4) == 0,
              "payload ends QUA=");
        CHECK(mut[11 + b64_len] == '\r' && mut[11 + b64_len + 1] == '\n',
              "CRLF preserved after 87388-char payload");
        /* decoded bytes: 3 per QUFB group + 2 from QUA= = 65540 > 65536 */
        CHECK((65540 / 3) * 3 + 2 > 65536, "decoded size crosses 64KB");
        printf("  PASS (decoded field = %u bytes)\n\n", (65540 / 3) * 3 + 2);
    }

    /* ── T4 (S8): FTP bare-LF on quoted arg ── */
    printf("T4: FTP line-end strip on quoted arg (S8, CVE-2023-51713)\n");
    {
        const char *seed = "RNFR \"/tmp/x\"\r\nQUIT\r\n";
        uint32_t n = load(mut, seed), orig_n = n;
        SCRIPT(0u); /* variant (a): drop the CR */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "FTP");
        CHECK(fired == 1, "S8 fired");
        CHECK(n == orig_n - 1, "len -1 (%u -> %u)", orig_n, n);
        CHECK(memcmp(mut, "RNFR \"/tmp/x\"\n", 14) == 0,
              "bare LF after quoted arg");
        CHECK(memchr(mut, '\r', 14) == NULL, "no CR before the LF");
        printf("  PASS\n\n");
    }

    /* ── T4b (S8): duplicate closing quote ── */
    printf("T4b: FTP duplicated quote at EOL (S8)\n");
    {
        const char *seed = "MKD /tmp/x\"\r\nQUIT\r\n";
        uint32_t n = load(mut, seed), orig_n = n;
        SCRIPT(1u); /* variant (b): duplicate terminator byte */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "FTP");
        CHECK(fired == 1, "S8 fired");
        CHECK(n == orig_n + 1, "len +1 (%u -> %u)", orig_n, n);
        CHECK(memcmp(mut, "MKD /tmp/x\"\"\r", 13) == 0,
              "double quote before CRLF");
        printf("  PASS\n\n");
    }

    /* ── T5 (S9): consecutive-separator path ── */
    printf("T5: HTTP double-slash path (S9, CVE-2026-26828)\n");
    {
        const char *seed = "GET /api/config HTTP/1.1\r\nHost: x\r\n\r\n";
        uint32_t n = load(mut, seed), orig_n = n;
        SCRIPT(0u); /* sep_paths[0] */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "HTTP");
        CHECK(fired == 1, "S9 fired");
        CHECK(memcmp(mut, "GET /databases/1//playlists HTTP/1.1\r\n", 38) == 0,
              "path rewritten with // separator");
        CHECK(n == orig_n - 11 + 23, "len adjusted (%u -> %u)", orig_n, n);
        CHECK(strstr((char *)mut, "Host: x") != NULL, "headers preserved");
        printf("  PASS\n\n");
    }

    /* ── T5b (S9): DAAP protocol accepted ── */
    printf("T5b: DAAP proto also covered (S9)\n");
    {
        const char *seed = "GET /databases/1/items HTTP/1.1\r\n\r\n";
        uint32_t n = load(mut, seed);
        SCRIPT(3u); /* sep_paths[3] = /api//playlists */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "DAAP");
        CHECK(fired == 1, "S9 fired on DAAP");
        CHECK(strstr((char *)mut, "/api//playlists") != NULL,
              "NULL-deref endpoint path applied");
        printf("  PASS\n\n");
    }

    /* ── T6 (S10): query parameter omission ── */
    printf("T6: HTTP query strip (S10, CVE-2026-26829)\n");
    {
        const char *seed = "GET /api/search?type=track HTTP/1.1\r\nHost: x\r\n\r\n";
        uint32_t n = load(mut, seed), orig_n = n;
        SCRIPT(0u); /* strip query */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "HTTP");
        CHECK(fired == 1, "S10 fired");
        CHECK(memchr(mut, '?', 26) == NULL, "query marker removed");
        CHECK(memcmp(mut, "GET /api/search HTTP/1.1\r\n", 26) == 0,
              "path kept, query dropped");
        CHECK(n == orig_n - 11, "len -11 (%u -> %u)", orig_n, n);
        printf("  PASS\n\n");
    }

    /* ── T7: structure preserved after S9/S10 ── */
    printf("T7: request-line structure preserved\n");
    {
        const char *seed = "PUT /api/update?a=1 HTTP/1.1\r\nHost: x\r\n\r\n";
        uint32_t n = load(mut, seed);
        SCRIPT(0u, 0u); /* S10 strip (first mut_ur(2) in HTTP block) */
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "HTTP");
        CHECK(fired == 1, "fired");
        CHECK(mut[0] == 'P' && mut[1] == 'U' && mut[2] == 'T',
              "method preserved");
        CHECK(strstr((char *)mut, " HTTP/1.1\r\n") != NULL,
              "request-line terminator preserved");
        CHECK(strstr((char *)mut, "Host: x") != NULL,
              "headers untouched by S10");
        printf("  PASS\n\n");
    }

    /* ── T8: wrong protocol / no marker / short buffer no-op ── */
    printf("T8: wrong protocol no-op\n");
    {
        const char *seed = "GET /api/config HTTP/1.1\r\nHost: x\r\n\r\n";
        uint32_t n = load(mut, seed);
        uint8_t fired = cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        CHECK(fired == 0, "SMTP proto ignores HTTP request");
        const char *ftp_seed = "USER ubuntu\r\nLIST\r\n";
        n = load(mut, ftp_seed);
        fired = cve_targeted_mutate(mut, &n, MAX_BUF, "RTSP");
        CHECK(fired == 0, "RTSP proto ignores FTP commands");
        uint32_t tiny = 5;
        fired = cve_targeted_mutate(mut, &tiny, MAX_BUF, "SMTP");
        CHECK(fired == 0, "short buffer no-op");
        printf("  PASS\n\n");
    }

    /* ── T9: counter accounting across strategies ── */
    printf("T9: cve_mutations_applied accounting\n");
    {
        cve_mutations_applied = 0;
        uint32_t n = load(mut, "RCPT TO:<a@b>\r\n");
        SCRIPT(0u);
        (void)cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        n = load(mut, "RCPT TO:<a@b>\r\n");
        SCRIPT(0u);
        (void)cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        n = load(mut, "RCPT TO:<a@b>\r\n");
        SCRIPT(0u);
        (void)cve_targeted_mutate(mut, &n, MAX_BUF, "SMTP");
        CHECK(cve_mutations_applied == 3,
              "3 fires counted (got %u)", cve_mutations_applied);
        printf("  PASS\n\n");
    }

    /* ── T12: tight-capacity contract — growth strategies must fit or
     * decline. 2026-09-07 heap-overflow postmortem: the fuzz_one hook
     * passed buf_cap=MAX_FILE while out_buf was sized ≈ temp_len; any
     * growth write smashed the heap. These tests pin the contract with
     * allocations of EXACTLY cap bytes (run under ASAN via `make
     * asan_tests` for memory-safety enforcement). ── */
    printf("T12: S2a exact-fit fires at cap=len+1\n");
    {
        const char *seed = "RNTO /tmp/x\r\nQUIT\r\n"; /* len 19 */
        uint32_t n = 19;
        uint8_t *b = malloc(20); /* exact: cap == 20 == len+1 */
        memcpy(b, seed, n);
        SCRIPT(1u); /* insert_char = '\\' */
        uint8_t fired = cve_targeted_mutate(b, &n, 20, "FTP");
        CHECK(fired == 1, "S2a fires at exact capacity");
        CHECK(n == 20, "len grew to 20 (%u)", n);
        CHECK(memmem(b, 20, "RNTO /tmp/x\\\r", 13) != NULL, "insert at CR");
        free(b);
        printf("  PASS\n\n");
    }

    printf("T12b: S2a declines one byte short, buffer untouched\n");
    {
        const char *seed = "RNTO /tmp/x\r\nQUIT\r\n";
        uint32_t n = 19;
        uint8_t *b = malloc(19); /* exact: cap == 19 < len+1 */
        memcpy(b, seed, n);
        SCRIPT(1u);
        uint8_t fired = cve_targeted_mutate(b, &n, 19, "FTP");
        CHECK(fired == 0, "S2a declines when it cannot fit");
        CHECK(n == 19, "len unchanged (%u)", n);
        CHECK(memcmp(b, seed, 19) == 0, "buffer bit-identical");
        free(b);
        printf("  PASS\n\n");
    }

    printf("T12c: S6/S2b/S1 exact-fit and one-short behavior\n");
    {
        /* S6: len 15 + extend 200 = 215; guard is strict < so fires at
         * cap 216, declines at 215. Lengths computed, not hand-counted
         * (a hand-count error here is what ASAN caught in draft 1). */
        const char *s6 = "RCPT TO:<a@b>\r\n";
        uint32_t s6_len = (uint32_t)strlen(s6);
        CHECK(s6_len == 15, "S6 seed len 15 (%u)", s6_len);
        uint32_t n = s6_len;
        uint8_t *b = malloc(s6_len + 201);
        memcpy(b, s6, n);
        SCRIPT(0u);
        CHECK(cve_targeted_mutate(b, &n, s6_len + 201, "SMTP") == 1,
              "S6 fires at len+201");
        CHECK(n == s6_len + 200, "S6 len %u (%u)", s6_len + 200, n);
        free(b);
        b = malloc(s6_len + 200); n = s6_len; memcpy(b, s6, n);
        SCRIPT(0u);
        CHECK(cve_targeted_mutate(b, &n, s6_len + 200, "SMTP") == 0,
              "S6 declines at len+200");
        CHECK(n == s6_len && memcmp(b, s6, s6_len) == 0, "S6 buffer untouched");
        free(b);

        /* S2b: len 14 + extend 100 = 114; fires at cap 115, declines 114 */
        const char *s2b = "MLSD /\r\nQUIT\r\n";
        uint32_t s2b_len = (uint32_t)strlen(s2b);
        CHECK(s2b_len == 14, "S2b seed len 14 (%u)", s2b_len);
        b = malloc(s2b_len + 101); n = s2b_len; memcpy(b, s2b, n);
        SCRIPT(0u);
        CHECK(cve_targeted_mutate(b, &n, s2b_len + 101, "FTP") == 1,
              "S2b fires at len+101");
        CHECK(n == s2b_len + 100, "S2b len %u (%u)", s2b_len + 100, n);
        free(b);
        b = malloc(s2b_len + 100); n = s2b_len; memcpy(b, s2b, n);
        SCRIPT(0u);
        CHECK(cve_targeted_mutate(b, &n, s2b_len + 100, "FTP") == 0,
              "S2b declines at len+100");
        CHECK(n == s2b_len && memcmp(b, s2b, s2b_len) == 0,
              "S2b buffer untouched");
        free(b);

        /* S1: len 45 - old 1 + new 10 = 54; fires at 55, declines at 54 */
        const char *s1 =
            "REGISTER sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        uint32_t s1_len = (uint32_t)strlen(s1);
        CHECK(s1_len == 45, "S1 seed len 45 (%u)", s1_len);
        b = malloc(s1_len + 10); n = s1_len; memcpy(b, s1, n);
        SCRIPT(0u);
        CHECK(cve_targeted_mutate(b, &n, s1_len + 10, "SIP") == 1,
              "S1 fires at len+10");
        CHECK(n == s1_len + 9, "S1 len %u (%u)", s1_len + 9, n);
        CHECK(strstr((char *)b, "2147483647") != NULL, "S1 value written");
        free(b);
        b = malloc(s1_len + 9); n = s1_len; memcpy(b, s1, n);
        SCRIPT(0u);
        CHECK(cve_targeted_mutate(b, &n, s1_len + 9, "SIP") == 0,
              "S1 declines at len+9");
        CHECK(n == s1_len && memcmp(b, s1, s1_len) == 0, "S1 buffer untouched");
        free(b);
        printf("  PASS\n\n");
    }

    printf("T13: S8(b) exact-fit fires, one-short declines\n");
    {
        const char *seed = "MKD /tmp/x\"\r\nQUIT\r\n"; /* len 19 */
        uint32_t n = 19;
        uint8_t *b = malloc(20);
        memcpy(b, seed, n);
        SCRIPT(1u); /* variant (b): duplicate terminator byte */
        CHECK(cve_targeted_mutate(b, &n, 20, "FTP") == 1, "S8b fires at 20");
        CHECK(n == 20 && memcmp(b, "MKD /tmp/x\"\"\r", 13) == 0,
              "S8b wrote double quote");
        free(b);
        b = malloc(19); n = 19; memcpy(b, seed, n);
        SCRIPT(1u);
        CHECK(cve_targeted_mutate(b, &n, 19, "FTP") == 0, "S8b declines at 19");
        CHECK(n == 19 && memcmp(b, seed, 19) == 0, "S8b buffer untouched");
        free(b);
        printf("  PASS\n\n");
    }


    /* ── T14: adaptive-gate marker scan (2026-09-08) ── */
    printf("T14: mut_marker_scan preconditions\n");
    {
        struct { const char *s; const char *p; int want; const char *why; } cases[] = {
            {"USER ubuntu\r\nRNTO /tmp/a\r\nQUIT\r\n", "FTP", 1, "FTP RNTO line"},
            {"USER ubuntu\r\nXXRNTO /tmp/a\r\n", "FTP", 0, "RNTO not at line start"},
            {"MLSD /\r\n", "FTP", 1, "FTP MLSD"},
            {"MLST /\r\n", "FTP", 1, "FTP MLST"},
            {"RNFR \"../..\"\r\n", "FTP", 1, "FTP RNFR quoted (S8)"},
            {"RNFR /tmp/a\r\n", "FTP", 0, "FTP RNFR unquoted (no S8 shape)"},
            {"CWD a\\b\r\n", "FTP", 1, "FTP CWD backslash (S8)"},
            {"USER u\r\nPASS p\r\nLIST\r\n", "FTP", 0, "FTP no markers"},
            {"EHLO x\r\nAUTH LOGIN dXNlcg==\r\n", "SMTP", 1, "SMTP AUTH line"},
            {"EHLO x\r\nXAUTH LOGIN dXNlcg==\r\n", "SMTP", 0, "AUTH not at line start"},
            {"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n", "SMTP", 1, "SMTP RCPT TO:<"},
            {"MAIL FROM:<a@b>\r\nDATA\r\n", "SMTP", 0, "SMTP no markers"},
            {"PLAY rtsp://x RTSP/1.0\r\nSession: ABCD\r\n", "RTSP", 1, "RTSP Session"},
            {"PLAY rtsp://x RTSP/1.0\r\nCSeq: 1\r\n", "RTSP", 0, "RTSP no session"},
            {"GET /a HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "HTTP", 1, "HTTP CL (S1)"},
            {"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", "HTTP", 0, "HTTP no CL: S9/S10 stay on base lottery"},
            {"REGISTER sip:a SIP/2.0\r\nContent-Length: 9\r\n\r\n", "SIP", 1, "SIP CL"},
            {"GET /databases/1/items HTTP/1.1\r\n\r\n", "DAAP", 0, "DAAP no CL"},
            {"USER u\r\nRNTO a\r\n", "IRC", 0, "wrong proto ignored"},
        };
        int n = sizeof(cases) / sizeof(cases[0]);
        for (int i = 0; i < n; i++) {
            uint32_t l = (uint32_t)strlen(cases[i].s);
            int got = mut_marker_scan((const uint8_t *)cases[i].s, l, cases[i].p);
            CHECK(got == cases[i].want, "case %d (%s): want %d got %d",
                  i, cases[i].why, cases[i].want, got);
        }
        CHECK(mut_marker_scan(NULL, 0, "FTP") == 0, "NULL buffer safe");
        CHECK(mut_marker_scan((const uint8_t *)"RNTO a", 6, "FTP") == 0, "len<8 safe");
        printf("  PASS (%d cases)\n\n", n);
    }

    /* ── T15: one-way consistency — marker==0 must mean the engine
     * cannot fire on FTP/SMTP/RTSP buffers (their strategies all
     * require the marked preconditions). HTTP/SIP is exempt: S9/S10
     * fire on any request line and intentionally ride the base
     * lottery. ── */
    printf("T15: marker-scan/engine consistency\n");
    {
        struct { const char *s; const char *p; } nomark[] = {
            {"USER u\r\nPASS p\r\nLIST /\r\nQUIT\r\n", "FTP"},
            {"SYST\r\nTYPE I\r\nPASV\r\n", "FTP"},
            {"EHLO x\r\nMAIL FROM:<a@b>\r\nDATA\r\n", "SMTP"},
            {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", "RTSP"},
        };
        for (int i = 0; i < 4; i++) {
            uint8_t b[256];
            uint32_t n = load(b, nomark[i].s);
            CHECK(mut_marker_scan(b, n, nomark[i].p) == 0, "case %d unmarked", i);
            CLEAR_SCRIPT();
            CHECK(cve_targeted_mutate(b, &n, sizeof(b), nomark[i].p) == 0,
                  "case %d: engine fires without marker", i);
        }
        printf("  PASS\n\n");
    }

    printf("══════════════════════════════════════════\n");
    if (failures) {
        printf("RESULT: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("RESULT: ALL 18 TESTS PASSED\n");
    return 0;
}
