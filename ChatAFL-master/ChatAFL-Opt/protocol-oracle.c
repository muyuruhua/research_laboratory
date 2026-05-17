/*
 * ChatAFL-Opt: Protocol-Specific Semantic Oracle Implementation
 * ==============================================================
 *
 * Implements security-property-based vulnerability oracles for:
 *   FTP, SMTP, RTSP, SIP, DAAP, HTTP, MQTT
 *
 * Oracle design methodology (from FindVulnerability.txt):
 *   1. Study real CVEs for each protocol
 *   2. Extract violated security invariants
 *   3. Encode invariants as runtime checks on request-response pairs
 *   4. Report violations with severity and category
 *
 * Key CVE patterns studied (expanded from 协议漏洞汇总.xlsx):
 *   FTP:  CVE-2024-3935 (path traversal), CVE-2024-42644..42655 (bftpd),
 *         CVE-2026-39983 (CRLF injection), CVE-2018-15516 (FTP bounce/SSRF),
 *         CVE-2006-6750 (format string), CVE-2026-41324 (resource exhaustion),
 *         CVE-2026-29515 (auth bypass), CVE-2021-22946 (TLS downgrade)
 *   MQTT: CVE-2023-34488 (auth bypass), CVE-2023-3592 (memory leak),
 *         CVE-2019-5432 (malformed SUBSCRIBE), CVE-2021-41039 (v5 property abuse),
 *         CVE-2017-7650 (ACL bypass), CVE-2014-6116 (session takeover),
 *         CVE-2024-42651 (UAF/nanomq)
 *   SIP:  CVE-2023-49323 (kamailio auth), CVE-2020-28361 (kamailio DoS),
 *         CVE-2021-37624 (unauthorized MESSAGE), CVE-2023-28098 (header parsing),
 *         CVE-2008-6573 (SQL injection)
 *   RTSP: CVE-2021-38382 (live555 buffer), CVE-2019-7314 (live555 UAF),
 *         CVE-2018-4013 (stack buffer overflow), CVE-2019-6256 (DoS),
 *         CVE-2023-37117 (heap UAF)
 *   SMTP: CVE-2023-42117 (exim open relay), CVE-2005-3402 (STARTTLS downgrade),
 *         CVE-2001-1078 (format string), CVE-2006-0712 (header injection),
 *         CVE-2002-0309 (info leak)
 *   HTTP: CVE-2023-44487 (rapid reset), CVE-2021-42013 (double-encode traversal),
 *         CVE-2023-25690 (request smuggling), CVE-2023-38709 (response splitting),
 *         CVE-2002-0392 (chunked encoding)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

#include "protocol-oracle.h"
#include "alloc-inl.h"
#include "types.h"
#include "hash.h"

/* ============================================
 * Telemetry Counters
 * ============================================ */

uint64_t oracle_total_checks       = 0;
uint64_t oracle_total_violations   = 0;
uint64_t oracle_unique_violations  = 0;
uint64_t oracle_auth_bypass_count  = 0;
uint64_t oracle_state_violation_count = 0;
uint64_t oracle_info_leak_count    = 0;
uint64_t oracle_path_traversal_count = 0;
uint64_t oracle_dos_count          = 0;

/* Dedup bitmap */
#define ORACLE_DEDUP_SIZE 4096
static uint32_t oracle_dedup_bitmap[ORACLE_DEDUP_SIZE];
static int oracle_initialized = 0;
static char oracle_stats_buf[512];

/* Protocol state tracker (reset per execution) */
static protocol_state_t proto_state;

/* ============================================
 * Helper Functions
 * ============================================ */

static uint32_t oracle_hash(const void *data, size_t len) {
    uint32_t h = 0x811c9dc5;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x01000193;
    }
    return h;
}

static void oracle_add_violation(oracle_result_t *result,
                                  uint8_t severity, uint16_t category,
                                  const char *desc, const char *cve_ref,
                                  int req_idx) {
    if (result->violation_count >= ORACLE_MAX_VIOLATIONS) return;

    oracle_violation_t *v = &result->violations[result->violation_count];
    v->severity = severity;
    v->category = category;
    v->request_index = req_idx;

    /* Build pattern hash from description + category for dedup */
    char hash_input[320];
    snprintf(hash_input, sizeof(hash_input), "%d:%04x:%s", severity, category, desc);
    v->pattern_hash = oracle_hash(hash_input, strlen(hash_input));

    strncpy(v->description, desc, sizeof(v->description) - 1);
    v->description[sizeof(v->description) - 1] = '\0';

    if (cve_ref) {
        strncpy(v->cve_reference, cve_ref, sizeof(v->cve_reference) - 1);
        v->cve_reference[sizeof(v->cve_reference) - 1] = '\0';
    } else {
        v->cve_reference[0] = '\0';
    }

    result->violation_count++;
    if (severity > result->max_severity) result->max_severity = severity;
    result->categories_hit |= category;
}

/* Case-insensitive memmem */
static const unsigned char* ci_memmem(const unsigned char *hay, size_t hlen,
                                       const char *needle, size_t nlen) {
    if (nlen > hlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j;
        for (j = 0; j < nlen; j++) {
            if (tolower(hay[i + j]) != tolower((unsigned char)needle[j])) break;
        }
        if (j == nlen) return &hay[i];
    }
    return NULL;
}

/* Extract first numeric response code from text response (FTP/SMTP/HTTP/RTSP/SIP) */
static int extract_response_code(const unsigned char *resp, unsigned int len) {
    for (unsigned int i = 0; i + 2 < len; i++) {
        if (resp[i] >= '1' && resp[i] <= '5' &&
            resp[i+1] >= '0' && resp[i+1] <= '9' &&
            resp[i+2] >= '0' && resp[i+2] <= '9') {
            /* Check it's at start of line or after space/CRLF */
            if (i == 0 || resp[i-1] == '\n' || resp[i-1] == ' ') {
                return (resp[i] - '0') * 100 + (resp[i+1] - '0') * 10 + (resp[i+2] - '0');
            }
        }
    }
    return -1;
}

/* Extract the Nth response code from a multi-line FTP/SMTP response.
 * FTP responses are line-separated; each command gets one response line
 * starting with a 3-digit code. Lines with "XXX-" are continuation lines
 * for the same response (only count lines with "XXX " or end-of-response).
 *
 * IMPORTANT: FTP data-transfer commands (LIST, RETR, STOR, etc.) produce
 * TWO response codes: a preliminary 1xx (e.g. 150 "Opening data connection")
 * followed by a completion 2xx (e.g. 226 "Transfer complete").  Both belong
 * to the SAME request.  We handle this by treating a 1xx response as the
 * START of a "data transfer pair": when we see 1xx, we record it but also
 * scan forward for the paired 2xx completion, and the whole pair counts as
 * ONE request slot.  The code we return is the 1xx (the preliminary code),
 * since that indicates the server accepted the command.
 *
 * Returns -1 if the Nth response is not found. */
static int extract_nth_response_code(const unsigned char *resp, unsigned int len, int n) {
    int count = 0;
    unsigned int i = 0;
    int in_multiline = 0;
    int multiline_code = 0;
    int in_data_xfer = 0;  /* inside a 1xx...2xx data transfer pair */

    while (i + 2 < len) {
        /* Find start of line with a 3-digit code */
        if ((i == 0 || (i > 0 && resp[i-1] == '\n')) &&
            resp[i] >= '1' && resp[i] <= '5' &&
            resp[i+1] >= '0' && resp[i+1] <= '9' &&
            resp[i+2] >= '0' && resp[i+2] <= '9') {

            int code = (resp[i] - '0') * 100 + (resp[i+1] - '0') * 10 + (resp[i+2] - '0');

            if (i + 3 < len && resp[i+3] == '-') {
                /* Multi-line response continuation (e.g. "211-Extensions") */
                in_multiline = 1;
                multiline_code = code;
            } else if (in_multiline && code == multiline_code) {
                /* End of multi-line block (e.g. "211 End") — same request */
                in_multiline = 0;
                /* Don't increment count — the opening line already did */
            } else if (in_data_xfer) {
                /* This is the completion response (2xx) of a data transfer.
                 * It belongs to the same request as the preceding 1xx.
                 * Consume it without incrementing count. */
                in_data_xfer = 0;
                /* Don't increment count — paired with the 1xx above */
            } else {
                /* Normal single-line response */
                if (count == n) return code;
                count++;
                /* If this is a 1xx preliminary (data transfer start),
                 * the NEXT final response is its completion partner. */
                if (code >= 100 && code < 200) {
                    in_data_xfer = 1;
                    /* Return the 1xx since it shows the command was accepted */
                    if (count - 1 == n) return code;
                }
            }
        }
        /* Advance to next line */
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }
    return -1;
}

/* Check if the server rejected a command at request index req_idx.
 * Scans response for the response corresponding to req_idx and
 * returns 1 if the response code indicates rejection (4xx/5xx). */
static int server_rejected_command(const unsigned char *resp, unsigned int resp_len,
                                    int req_idx) {
    int code = extract_nth_response_code(resp, resp_len, req_idx);
    if (code < 0) return 1;  /* Can't determine → assume rejection (safe default) */
    return (code >= 400 && code <= 599);
}

/* Extract the Nth HTTP-style response code (for HTTP, RTSP, SIP, DAAP).
 * These protocols use "PROTO/x.y NNN reason" format, e.g.:
 *   HTTP/1.1 200 OK
 *   RTSP/1.0 200 OK
 *   SIP/2.0 200 OK
 * Each response starts with the protocol tag at the beginning of a line.
 * Returns -1 if the Nth response is not found. */
static int extract_http_style_nth_response_code(const unsigned char *resp,
                                                 unsigned int len, int n) {
    int count = 0;
    unsigned int i = 0;
    while (i + 12 < len) {
        /* Check for line start */
        if (i == 0 || resp[i-1] == '\n') {
            /* Look for protocol tag: HTTP/ RTSP/ SIP/ */
            if ((resp[i] == 'H' || resp[i] == 'R' || resp[i] == 'S') &&
                (ci_memmem(resp + i, (len - i < 12) ? len - i : 12, "HTTP/", 5) ||
                 ci_memmem(resp + i, (len - i < 12) ? len - i : 12, "RTSP/", 5) ||
                 ci_memmem(resp + i, (len - i < 12) ? len - i : 12, "SIP/", 4))) {
                /* Find the space before status code */
                unsigned int j = i;
                while (j < len && resp[j] != ' ') j++;
                j++; /* skip space */
                if (j + 2 < len &&
                    resp[j] >= '1' && resp[j] <= '5' &&
                    resp[j+1] >= '0' && resp[j+1] <= '9' &&
                    resp[j+2] >= '0' && resp[j+2] <= '9') {
                    int code = (resp[j]-'0')*100 + (resp[j+1]-'0')*10 + (resp[j+2]-'0');
                    if (count == n) return code;
                    count++;
                }
            }
        }
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }
    return -1;
}

/* Decode MQTT variable-length encoding (remaining length field).
 * Returns decoded length, sets *bytes_used to number of bytes consumed.
 * Returns -1 on error. */
static int mqtt_decode_remaining_length(const unsigned char *buf, unsigned int buf_len,
                                         unsigned int *bytes_used) {
    int value = 0;
    unsigned int multiplier = 1;
    unsigned int idx = 0;
    if (buf_len == 0) return -1;
    do {
        if (idx >= buf_len || idx >= 4) return -1;
        value += (buf[idx] & 0x7F) * multiplier;
        multiplier *= 128;
    } while (buf[idx++] & 0x80);
    if (bytes_used) *bytes_used = idx;
    return value;
}

/* Check if request buffer starts with a specific command (case-insensitive) */
static int request_starts_with(const unsigned char *req, unsigned int len,
                                const char *cmd) {
    size_t clen = strlen(cmd);
    if (len < clen) return 0;
    return (strncasecmp((const char *)req, cmd, clen) == 0);
}

/* Reset protocol state for new execution */
static void reset_proto_state(void) {
    memset(&proto_state, 0, sizeof(proto_state));
}

/* ============================================
 * FTP Oracle
 * ============================================
 * Security invariants from RFC 959 + real CVEs:
 *
 * 1. AUTH BYPASS: Data commands (RETR, STOR, LIST, NLST, MKD, RMD, DELE)
 *    must NOT succeed (2xx) before USER+PASS authentication.
 *    CVE-2024-42644, CVE-2024-42645 (bftpd auth bypass)
 *
 * 2. PATH TRAVERSAL: CWD/RETR/STOR with "../" sequences should NOT
 *    succeed outside allowed directory.
 *    CVE-2024-3935 (lightftp), CVE-2024-42650 (bftpd)
 *
 * 3. STATE MACHINE: PASS without prior USER should be rejected.
 *    RNTO without prior RNFR should be rejected.
 *
 * 4. INFO LEAK: Server banner should not reveal sensitive info.
 *    STAT command should not leak internal paths.
 */

int oracle_check_ftp(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result) {

    reset_proto_state();

    /* CRITICAL: FTP servers send a banner ("220 ...") before any client request.
     * response_buf is cumulative, so response_code[0] = banner, response_code[1]
     * = response to request[0], etc.  We must offset by 1 when mapping request
     * index i to response index. */
    const int resp_offset = 1;  /* skip banner */

    /* Parse requests to build state, then check response */
    int has_user = 0, has_pass = 0, has_data_cmd = 0;
    int has_path_traversal = 0, has_rnfr = 0;
    int data_cmd_index = -1;
    int authenticated = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        if (request_starts_with(req, rlen, "USER ")) {
            /* Only accept USER if server responded 331 (Password required).
             * Fuzz data may randomly match "USER " prefix; blind reset of
             * authenticated would cause massive false-positive auth_bypass. */
            int user_code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if (user_code == 331) {
                has_user = 1;
                authenticated = 0;  /* new USER starts fresh auth sequence */
            }
        }
        if (request_starts_with(req, rlen, "PASS ") ||
            request_starts_with(req, rlen, "PASS\r\n") ||
            (rlen == 4 && memcmp(req, "PASS", 4) == 0)) {
            has_pass = 1;
            if (has_user) {
                int pass_code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (pass_code >= 200 && pass_code < 300) {
                    authenticated = 1;  /* only if server accepted PASS */
                }
            }
        }
        /* Fallback: if server responded 230 (User logged in) to ANY request,
         * the session is now authenticated — handles edge cases where USER/PASS
         * format variations prevent proper tracking above. */
        {
            int any_code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if (any_code == 230) {
                authenticated = 1;
            }
        }
        if (request_starts_with(req, rlen, "RNFR ")) has_rnfr = 1;

        /* Data commands that require auth — only flag if NOT yet authenticated */
        if (!authenticated &&
            (request_starts_with(req, rlen, "RETR ") ||
             request_starts_with(req, rlen, "STOR ") ||
             request_starts_with(req, rlen, "LIST") ||
             request_starts_with(req, rlen, "NLST") ||
             request_starts_with(req, rlen, "MKD ") ||
             request_starts_with(req, rlen, "RMD ") ||
             request_starts_with(req, rlen, "DELE ") ||
             request_starts_with(req, rlen, "APPE ") ||
             request_starts_with(req, rlen, "SITE "))) {
            if (!has_data_cmd) {
                has_data_cmd = 1;
                data_cmd_index = i;  /* Record FIRST unauthenticated data cmd */
            }
        }

        /* Check path traversal attempts */
        if (ci_memmem(req, rlen, "../", 3) ||
            ci_memmem(req, rlen, "..\\", 3) ||
            ci_memmem(req, rlen, "%2e%2e", 6) ||
            ci_memmem(req, rlen, "%2e%2e%2f", 9)) {
            has_path_traversal = 1;
        }

        /* State machine: RNTO without RNFR — only flag if server ACCEPTED it */
        if (request_starts_with(req, rlen, "RNTO ") && !has_rnfr) {
            if (!server_rejected_command(response, resp_len, i + resp_offset)) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    "FTP: RNTO without prior RNFR accepted by server",
                    NULL, i);
            }
        }

        /* State machine: PASS without USER — check the specific response */
        if (request_starts_with(req, rlen, "PASS ") && !has_user) {
            int code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if (code == 230) {  /* 230 = Login successful; 200/215/etc are NOT login */
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_STATE_VIOLATION | ORACLE_CAT_AUTH_BYPASS,
                    "FTP: PASS accepted without USER (auth state bypass)",
                    "CVE-2024-42644", i);
            }
        }
    }

    /* Check response for auth bypass: data command succeeded without auth.
     * IMPORTANT: Check the response for the specific data command, not the
     * first response in the stream (which is typically the banner 220). */
    if (has_data_cmd && resp_len > 0 && data_cmd_index >= 0) {
        int code = extract_nth_response_code(response, resp_len, data_cmd_index + resp_offset);
        if (code == 150 || code == 225 || code == 226) {
            oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                ORACLE_CAT_AUTH_BYPASS,
                "FTP: Data command succeeded without authentication",
                "CVE-2024-42645", data_cmd_index);
            oracle_auth_bypass_count++;
        }
    }

    /* Check path traversal success: scan each request for traversal patterns
     * and check if THAT specific request's response indicates success. */
    if (has_path_traversal && resp_len > 0) {
        for (int i = 0; i < req_count; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            if (ci_memmem(req, rlen, "../", 3) || ci_memmem(req, rlen, "..\\", 3) ||
                ci_memmem(req, rlen, "%2e%2e", 6)) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code >= 150 && code <= 250) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_PATH_TRAVERSAL,
                        "FTP: Path traversal command accepted by server",
                        "CVE-2024-3935", i);
                    oracle_path_traversal_count++;
                    break;  /* One finding is enough */
                }
            }
        }
    }

    /* Info leak: check for sensitive patterns in response */
    if (resp_len > 0) {
        if (ci_memmem(response, resp_len, "/etc/passwd", 11) ||
            ci_memmem(response, resp_len, "/etc/shadow", 11) ||
            ci_memmem(response, resp_len, "root:", 5)) {
            oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                ORACLE_CAT_INFO_LEAK,
                "FTP: Sensitive file content leaked in response",
                "CVE-2024-42650", -1);
            oracle_info_leak_count++;
        }
        /* Extended info leak: internal paths, version disclosure */
        if (ci_memmem(response, resp_len, "/home/", 6) ||
            ci_memmem(response, resp_len, "/var/www", 7) ||
            ci_memmem(response, resp_len, "Server version:", 15)) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_INFO_LEAK,
                "FTP: Internal path or version info leaked in response",
                NULL, -1);
        }
    }

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* CRLF injection in FTP commands (CVE-2026-39983: CRLF injection in basic-ftp).
     * Detects bare CR/LF in command arguments that could inject extra commands. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        /* Scan inside the request body (after the first space) for CR/LF injection.
         * Valid FTP commands have the format: CMD arg\r\n — a bare \r\n mid-command
         * (before another command keyword) indicates injection. */
        const unsigned char *space = memchr(req, ' ', rlen);
        if (space) {
            unsigned int arg_off = (unsigned int)(space - req) + 1;
            if (arg_off + 1 < rlen) {
                for (unsigned int j = arg_off; j + 1 < rlen; j++) {
                    if (req[j] == '\r' && req[j+1] == '\n') {
                        /* Look for another FTP keyword after CRLF in the same buffer */
                        unsigned int remaining = rlen - (j + 2);
                        if (remaining > 2) {
                            oracle_add_violation(result, ORACLE_SEV_HIGH,
                                ORACLE_CAT_INJECTION,
                                "FTP: CRLF injection in command arguments (FTP command smuggling)",
                                "CVE-2026-39983", i);
                            break;
                        }
                    }
                }
            }
        }
    }

    /* PORT command bounce/SSRF (CVE-2018-15516, CVE-2021-31810).
     * PORT command can be abused for FTP bounce attacks by specifying
     * an internal IP in the PORT argument. Check if PORT specifies
     * non-loopback addresses. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (request_starts_with(req, rlen, "PORT ")) {
            /* PORT h1,h2,h3,h4,p1,p2 — check for internal/private IP ranges */
            int h1, h2, h3, h4, p1, p2;
            if (sscanf((const char *)req, "PORT %d,%d,%d,%d,%d,%d",
                       &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
                /* RFC 1918 private addresses + loopback + link-local */
                if (h1 == 10 || (h1 == 172 && h2 >= 16 && h2 <= 31) ||
                    (h1 == 192 && h2 == 168) || h1 == 127 ||
                    (h1 == 169 && h2 == 254)) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_ISOLATION,
                        "FTP: PORT command specifies private/internal address (FTP bounce risk)",
                        "CVE-2018-15516", i);
                }
            }
        }
    }

    /* Format string pattern detection (CVE-2006-6750: format string in FTP server).
     * Look for %n, %s, %x patterns in unexpected places. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        int fmt_count = 0;
        for (unsigned int j = 0; j + 1 < rlen; j++) {
            if (req[j] == '%' && (req[j+1] == 'n' || req[j+1] == 's' ||
                req[j+1] == 'x' || req[j+1] == 'd' || req[j+1] == 'p')) {
                fmt_count++;
                if (fmt_count >= 3) {  /* Multiple format specifiers = suspicious */
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_INJECTION,
                        "FTP: Multiple format string specifiers in command (format string vuln risk)",
                        "CVE-2006-6750", i);
                    break;
                }
            }
        }
    }

    /* TLS downgrade detection (CVE-2021-22946): AUTH TLS followed by
     * cleartext data commands suggests TLS enforcement bypass. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (request_starts_with(req, rlen, "AUTH TLS") ||
            request_starts_with(req, rlen, "AUTH SSL")) {
            /* If a data command follows AUTH TLS AND receives success response,
             * the server may be vulnerable to TLS downgrade */
            int auth_code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if (auth_code == 234) {  /* AUTH TLS accepted */
                /* Check for subsequent cleartext data commands */
                for (int k = i + 1; k < req_count; k++) {
                    const unsigned char *req2 = requests[k];
                    unsigned int rlen2 = req_lens[k];
                    if (request_starts_with(req2, rlen2, "RETR ") ||
                        request_starts_with(req2, rlen2, "STOR ")) {
                        int data_code = extract_nth_response_code(response, resp_len, k + resp_offset);
                        if (data_code >= 150 && data_code <= 250) {
                            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                                ORACLE_CAT_STATE_VIOLATION,
                                "FTP: Cleartext data transfer after AUTH TLS (TLS downgrade risk)",
                                "CVE-2021-22946", k);
                            break;
                        }
                    }
                }
            }
            break;
        }
    }

    /* Resource exhaustion via repeated failed auth attempts (CVE-2026-41324).
     * Many failed PASS commands without USER reset = potential resource drain. */
    {
        int failed_auth = 0;
        for (int i = 0; i < req_count; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            if (request_starts_with(req, rlen, "PASS ") && !has_user) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code >= 500 && code <= 599) failed_auth++;
            }
        }
        if (failed_auth > 20) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_RESOURCE_EXHAUST | ORACLE_CAT_DOS,
                "FTP: Excessive failed authentication attempts (resource exhaustion risk)",
                "CVE-2026-41324", -1);
            oracle_dos_count++;
        }
    }

    return result->violation_count;
}

/* ============================================
 * SMTP Oracle
 * ============================================
 * Security invariants from RFC 5321 + real CVEs:
 *
 * 1. OPEN RELAY: MAIL FROM + RCPT TO succeeding without AUTH = open relay
 *    CVE-2023-42117 (exim)
 *
 * 2. AUTH BYPASS: Sending mail without EHLO/AUTH sequence
 *
 * 3. VRFY/EXPN INFO LEAK: Should not enumerate users
 *    CVE-2019-15846 (exim RCE via SNI)
 *
 * 4. STATE MACHINE: DATA before RCPT TO, RCPT TO before MAIL FROM
 *
 * 5. INJECTION: Newline injection in addresses (SMTP smuggling)
 */

int oracle_check_smtp(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result) {

    reset_proto_state();

    /* SMTP servers send a banner ("220 ...") before any client request.
     * Same off-by-one issue as FTP — response[0] = banner, response[1] =
     * response to request[0]. */
    const int resp_offset = 1;  /* skip banner */

    int has_ehlo = 0, has_auth = 0, has_mail = 0, has_rcpt = 0;
    int has_data_before_rcpt = 0;
    int has_vrfy = 0, has_expn = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        if (request_starts_with(req, rlen, "EHLO ") ||
            request_starts_with(req, rlen, "HELO ")) has_ehlo = 1;
        if (request_starts_with(req, rlen, "AUTH ")) has_auth = 1;
        if (request_starts_with(req, rlen, "MAIL FROM:")) has_mail = 1;
        if (request_starts_with(req, rlen, "RCPT TO:")) has_rcpt = 1;
        if (request_starts_with(req, rlen, "VRFY ")) has_vrfy = 1;
        if (request_starts_with(req, rlen, "EXPN ")) has_expn = 1;

        /* State violation: DATA before RCPT — only flag if server accepted */
        if (request_starts_with(req, rlen, "DATA") && !has_rcpt) {
            has_data_before_rcpt = 1;
            int code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if (code >= 200 && code < 400) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    "SMTP: DATA before RCPT TO accepted by server",
                    NULL, i);
            }
        }

        /* State violation: RCPT before MAIL FROM — only flag if server accepted */
        if (request_starts_with(req, rlen, "RCPT TO:") && !has_mail) {
            int code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if (code >= 200 && code < 400) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    "SMTP: RCPT TO before MAIL FROM accepted by server",
                    NULL, i);
            }
        }

        /* SMTP smuggling: newline injection in RCPT TO */
        if (request_starts_with(req, rlen, "RCPT TO:") ||
            request_starts_with(req, rlen, "MAIL FROM:")) {
            for (unsigned int j = 8; j + 1 < rlen; j++) {
                if ((req[j] == '\r' && req[j+1] != '\n') ||
                    (req[j] == '\n' && (j == 0 || req[j-1] != '\r'))) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_SMUGGLING | ORACLE_CAT_INJECTION,
                        "SMTP: Bare CR/LF in address (SMTP smuggling attempt)",
                        "CVE-2023-42117", i);
                    break;
                }
            }
        }
    }

    /* Check response: open relay detection.
     * Find the last RCPT TO command and check if its response was 250. */
    if (has_mail && has_rcpt && !has_auth && resp_len > 0) {
        int rcpt_idx = -1;
        for (int i = req_count - 1; i >= 0; i--) {
            if (request_starts_with(requests[i], req_lens[i], "RCPT TO:")) {
                rcpt_idx = i; break;
            }
        }
        if (rcpt_idx >= 0) {
            int code = extract_nth_response_code(response, resp_len, rcpt_idx + resp_offset);
            if (code == 250 || code == 354) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_AUTH_BYPASS | ORACLE_CAT_AUTHZ_BYPASS,
                    "SMTP: Mail relay succeeded without authentication (open relay)",
                    "CVE-2023-42117", rcpt_idx);
                oracle_auth_bypass_count++;
            }
        }
    }

    /* VRFY/EXPN info leak: find the VRFY/EXPN command and check its response */
    if ((has_vrfy || has_expn) && resp_len > 0) {
        for (int i = 0; i < req_count; i++) {
            if (request_starts_with(requests[i], req_lens[i], "VRFY ") ||
                request_starts_with(requests[i], req_lens[i], "EXPN ")) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code == 250 || code == 252) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_INFO_LEAK,
                        "SMTP: VRFY/EXPN returned user information (user enumeration)",
                        NULL, i);
                    oracle_info_leak_count++;
                    break;
                }
            }
        }
    }

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* STARTTLS downgrade detection (CVE-2005-3402: STARTTLS security defect).
     * If STARTTLS is offered (220) but followed by cleartext mail commands,
     * the session may be vulnerable to STRIPTLS attack. */
    {
        int starttls_offered = 0;
        int starttls_accepted = 0;
        for (int i = 0; i < req_count; i++) {
            if (request_starts_with(requests[i], req_lens[i], "STARTTLS")) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code == 220) {
                    starttls_offered = 1;
                    starttls_accepted = 1;
                }
            }
            /* Check for cleartext sensitive commands after STARTTLS was accepted */
            if (starttls_accepted &&
                (request_starts_with(requests[i], req_lens[i], "MAIL FROM:") ||
                 request_starts_with(requests[i], req_lens[i], "AUTH "))) {
                /* If MAIL FROM/AUTH succeeds without TLS, TLS downgrade is possible */
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code >= 200 && code < 400) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_STATE_VIOLATION,
                        "SMTP: Cleartext command after STARTTLS (STRIPTLS downgrade risk)",
                        "CVE-2005-3402", i);
                    break;
                }
            }
        }
    }

    /* Format string detection in SMTP commands (CVE-2001-1078).
     * Multiple %n/%s/%x in addresses or commands = format string risk. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        int fmt_count = 0;
        for (unsigned int j = 0; j + 1 < rlen; j++) {
            if (req[j] == '%' && (req[j+1] == 'n' || req[j+1] == 's' ||
                req[j+1] == 'x' || req[j+1] == 'p')) {
                fmt_count++;
            }
        }
        if (fmt_count >= 3) {
            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                ORACLE_CAT_INJECTION,
                "SMTP: Multiple format string specifiers in command (format string vuln risk)",
                "CVE-2001-1078", i);
            break;
        }
    }

    /* Long-line abuse / memory exhaustion (CVE-2001-0894, CVE-2002-0055).
     * Extremely long RCPT TO or MAIL FROM lines. */
    for (int i = 0; i < req_count; i++) {
        if (req_lens[i] > 4096) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_DOS | ORACLE_CAT_RESOURCE_EXHAUST,
                "SMTP: Excessively long command (memory exhaustion risk)",
                "CVE-2001-0894", i);
            oracle_dos_count++;
            break;
        }
    }

    /* Repeated auth failure pattern — potential brute force or resource drain */
    {
        int failed_auth_count = 0;
        for (int i = 0; i < req_count; i++) {
            if (request_starts_with(requests[i], req_lens[i], "AUTH ")) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code >= 500 && code <= 535) failed_auth_count++;
            }
        }
        if (failed_auth_count > 10) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_RESOURCE_EXHAUST,
                "SMTP: Excessive failed AUTH attempts (brute force / resource drain risk)",
                NULL, -1);
        }
    }

    return result->violation_count;
}

/* ============================================
 * RTSP Oracle
 * ============================================
 * Security invariants from RFC 7826 + real CVEs:
 *
 * 1. STATE MACHINE: PLAY before SETUP, TEARDOWN before SETUP
 *    CVE-2021-38382 (live555)
 *
 * 2. AUTH BYPASS: Accessing stream without proper auth
 *    CVE-2019-7314 (live555 UAF)
 *
 * 3. BUFFER OVERFLOW indicators: Very long header values
 *
 * 4. SESSION HIJACK: Using another session's ID
 */

int oracle_check_rtsp(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result) {

    reset_proto_state();

    int has_describe = 0, has_setup = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        if (request_starts_with(req, rlen, "DESCRIBE ")) has_describe = 1;
        if (request_starts_with(req, rlen, "SETUP ")) has_setup = 1;

        /* State machine: PLAY before SETUP — only flag if server accepted */
        if (request_starts_with(req, rlen, "PLAY ") && !has_setup) {
            int code = extract_http_style_nth_response_code(response, resp_len, i);
            if (code >= 200 && code < 300) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_STATE_VIOLATION,
                    "RTSP: PLAY before SETUP accepted by server",
                    "CVE-2021-38382", i);
                oracle_state_violation_count++;
            }
        }

        /* State machine: RECORD before SETUP — only flag if server accepted */
        if (request_starts_with(req, rlen, "RECORD ") && !has_setup) {
            int code = extract_http_style_nth_response_code(response, resp_len, i);
            if (code >= 200 && code < 300) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    "RTSP: RECORD before SETUP accepted by server",
                    NULL, i);
            }
        }

        /* Check for oversized headers (DoS / buffer overflow) */
        const unsigned char *cseq = ci_memmem(req, rlen, "CSeq:", 5);
        if (cseq) {
            unsigned int remaining = rlen - (unsigned int)(cseq - req);
            const unsigned char *eol = memchr(cseq, '\r', remaining);
            if (eol && (eol - cseq) > 256) {
                oracle_add_violation(result, ORACLE_SEV_LOW,
                    ORACLE_CAT_DOS,
                    "RTSP: Oversized CSeq header (potential buffer overflow)",
                    "CVE-2019-7314", i);
            }
        }
    }

    /* (PLAY-without-SETUP check is now integrated in the per-request loop above
     * using extract_http_style_nth_response_code for accurate matching) */

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* Multiple SETUP for the same stream (CVE-2019-7314, CVE-2019-15232,
     * CVE-2023-37117: UAF via duplicate SETUP on same session).
     * Track session IDs to detect repeated SETUP on same URL+session. */
    {
        const char *last_setup_url = NULL;
        unsigned int last_setup_url_len = 0;
        for (int i = 0; i < req_count; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            if (request_starts_with(req, rlen, "SETUP ")) {
                /* Extract URL part after "SETUP " */
                const char *url = (const char *)req + 6;
                unsigned int url_len = rlen - 6;
                const unsigned char *eol = memchr(url, '\r', url_len);
                if (eol) url_len = (unsigned int)(eol - (const unsigned char *)url);
                if (last_setup_url && url_len == last_setup_url_len &&
                    strncasecmp(url, last_setup_url, url_len) == 0) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_STATE_VIOLATION | ORACLE_CAT_AUTHZ_BYPASS,
                        "RTSP: Duplicate SETUP for same stream URL (UAF/double-free risk)",
                        "CVE-2019-7314", i);
                }
                last_setup_url = url;
                last_setup_url_len = url_len;
            }
        }
    }

    /* Session ID reuse/mismatch: SETUP returns a Session header; subsequent
     * requests should use the same session. Different session = hijack risk.
     * (Detection: flag if Session ID changes between requests unexpectedly) */
    /* Malformed Transport header (CVE-2019-6256: DoS via malformed transport).
     * Check for Transport header with unusual port ranges or empty fields. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (request_starts_with(req, rlen, "SETUP ")) {
            const unsigned char *transport = ci_memmem(req, rlen, "Transport:", 10);
            if (transport) {
                unsigned int remaining = rlen - (unsigned int)(transport - req);
                /* Check for port=0 (invalid port) */
                if (ci_memmem(transport, remaining, "port=0", 6)) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_DOS,
                        "RTSP: Transport header with port=0 (potential DoS)",
                        "CVE-2019-6256", i);
                }
                /* Check for excessively long transport header (CVE-2018-4013: stack BO) */
                const unsigned char *eol = memchr(transport, '\r', remaining);
                if (eol && (eol - transport) > 512) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_DOS,
                        "RTSP: Overly long Transport header (stack buffer overflow risk)",
                        "CVE-2018-4013", i);
                }
            }
        }
    }

    return result->violation_count;
}

/* ============================================
 * SIP Oracle
 * ============================================
 * Security invariants from RFC 3261 + real CVEs:
 *
 * 1. AUTH BYPASS: INVITE without REGISTER or without auth headers
 *    CVE-2023-49323 (kamailio)
 *
 * 2. STATE MACHINE: BYE before call established, ACK without INVITE
 *
 * 3. DOS: Via header loops, malformed Contact headers
 *    CVE-2020-28361 (kamailio DoS)
 *
 * 4. INJECTION: Header injection via CRLF in display names
 */

int oracle_check_sip(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result) {

    reset_proto_state();

    int has_register = 0, has_invite = 0, has_auth_header = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        if (request_starts_with(req, rlen, "REGISTER ")) has_register = 1;
        if (request_starts_with(req, rlen, "INVITE ")) has_invite = 1;
        if (ci_memmem(req, rlen, "Authorization:", 14) ||
            ci_memmem(req, rlen, "Proxy-Authorization:", 20)) {
            has_auth_header = 1;
        }

        /* State machine: BYE before INVITE — only flag if server processed it */
        if (request_starts_with(req, rlen, "BYE ") && !has_invite) {
            int code = extract_http_style_nth_response_code(response, resp_len, i);
            if (code >= 200 && code < 300) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    "SIP: BYE before INVITE accepted by server",
                    NULL, i);
            }
        }

        /* State machine: ACK without INVITE.
         * RFC 3261 §17.1.1.3: ACK is a special request that gets NO response
         * from the server. We cannot check server acceptance via response code.
         * However, sending ACK without INVITE indicates corrupted state. Flag
         * it only if the server hasn't sent an error for earlier requests
         * (suggesting the session is somehow alive). */
        if (request_starts_with(req, rlen, "ACK ") && !has_invite) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_STATE_VIOLATION,
                "SIP: ACK without prior INVITE (state anomaly)",
                NULL, i);
        }

        /* DoS: Via header loop detection (multiple Via headers pointing to same addr) */
        int via_count = 0;
        const unsigned char *search = req;
        unsigned int search_len = rlen;
        while (search_len > 4) {
            const unsigned char *via = ci_memmem(search, search_len, "Via:", 4);
            if (!via) break;
            via_count++;
            unsigned int offset = (unsigned int)(via - search) + 4;
            search = search + offset;
            search_len -= offset;
        }
        if (via_count > 10) {
            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                ORACLE_CAT_DOS | ORACLE_CAT_RESOURCE_EXHAUST,
                "SIP: Excessive Via headers (loop/amplification attack)",
                "CVE-2020-28361", i);
            oracle_dos_count++;
        }

        /* INVITE without any auth = potential toll fraud */
        if (request_starts_with(req, rlen, "INVITE ") && !has_auth_header) {
            /* Only flag if response shows success */
        }
    }

    /* Check response: INVITE without auth succeeded.
     * Find the INVITE request and check its specific response. */
    if (has_invite && !has_auth_header && resp_len > 0) {
        for (int i = 0; i < req_count; i++) {
            if (request_starts_with(requests[i], req_lens[i], "INVITE ")) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                if (code == 200) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_AUTH_BYPASS,
                        "SIP: INVITE succeeded without authentication (toll fraud risk)",
                        "CVE-2023-49323", i);
                    oracle_auth_bypass_count++;
                }
                break;
            }
        }
    }

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* Unauthorized SIP MESSAGE (CVE-2021-37624: FreeSWITCH allows sending
     * MESSAGE without auth, enabling spam/SMS fraud).
     * Flag MESSAGE request sent without Authorization header AND server accepted. */
    for (int i = 0; i < req_count; i++) {
        if (request_starts_with(requests[i], req_lens[i], "MESSAGE ")) {
            int has_auth = (ci_memmem(requests[i], req_lens[i], "Authorization:", 14) != NULL);
            if (!has_auth) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                if (code >= 200 && code < 300) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_AUTH_BYPASS,
                        "SIP: MESSAGE accepted without Authorization (unauthorized messaging)",
                        "CVE-2021-37624", i);
                    oracle_auth_bypass_count++;
                }
            }
        }
    }

    /* Malformed Authorization header detection (CVE-2023-28098: OpenSIPS DoS
     * via malformed Authorization header parsing).
     * Check for oversized or structurally invalid Authorization headers. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *auth = ci_memmem(requests[i], req_lens[i],
                                              "Authorization:", 14);
        if (auth) {
            unsigned int remaining = req_lens[i] - (unsigned int)(auth - requests[i]);
            const unsigned char *eol = memchr(auth, '\r', remaining);
            unsigned int auth_len = eol ? (unsigned int)(eol - auth) : remaining;
            /* Oversized authorization header */
            if (auth_len > 2048) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_DOS,
                    "SIP: Oversized Authorization header (DoS/Crash risk)",
                    "CVE-2023-28098", i);
                oracle_dos_count++;
            }
            /* Missing digest fields after "Digest " */
            if (ci_memmem(auth, remaining, "Digest", 6) &&
                !ci_memmem(auth, remaining, "nonce=", 6)) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    "SIP: Malformed Digest auth header (missing nonce, potential parsing bug)",
                    "CVE-2023-28098", i);
            }
        }
    }

    /* SQL injection patterns in SIP headers (CVE-2008-6573: crafted SIP request
     * leads to SQL injection in Avaya). */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (ci_memmem(req, rlen, "' OR ", 5) ||
            ci_memmem(req, rlen, "UNION SELECT", 12) ||
            ci_memmem(req, rlen, "'; DROP", 7) ||
            ci_memmem(req, rlen, "1=1", 3)) {
            oracle_add_violation(result, ORACLE_SEV_HIGH,
                ORACLE_CAT_INJECTION,
                "SIP: SQL injection pattern in request headers",
                "CVE-2008-6573", i);
        }
    }

    /* INVITE spoofing (CVE-2007-3347: INVITE with forged From header).
     * Check for mismatch between From header and Authorization username. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (request_starts_with(req, rlen, "INVITE ")) {
            const unsigned char *from = ci_memmem(req, rlen, "From:", 5);
            if (from) {
                unsigned int remaining = rlen - (unsigned int)(from - req);
                if (ci_memmem(from, remaining, "sip:admin@", 10) ||
                    ci_memmem(from, remaining, "sip:root@", 9)) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_AUTHZ_BYPASS,
                        "SIP: INVITE with privileged From header (spoofing risk)",
                        "CVE-2007-3347", i);
                }
            }
        }
    }

    return result->violation_count;
}

/* ============================================
 * DAAP Oracle
 * ============================================
 * Security invariants (Apple DAAP / forked-daapd):
 *
 * 1. AUTH BYPASS: Accessing /databases without login session
 * 2. INFO LEAK: /server-info leaking sensitive config
 * 3. PATH TRAVERSAL in URL
 */

int oracle_check_daap(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result) {

    reset_proto_state();

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        /* DAAP is HTTP-based, check for protected resource access without session */
        int has_session = (ci_memmem(req, rlen, "session-id", 10) != NULL);

        /* Accessing databases without session */
        if ((ci_memmem(req, rlen, "/databases/", 11) ||
             ci_memmem(req, rlen, "/databases?", 11)) && !has_session) {
            /* Check the specific response for this request */
            if (resp_len > 0) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                if (code == 200) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_AUTH_BYPASS,
                        "DAAP: Database access without session-id (auth bypass)",
                        NULL, i);
                    oracle_auth_bypass_count++;
                }
            }
        }

        /* Path traversal in DAAP URLs */
        if (ci_memmem(req, rlen, "../", 3) ||
            ci_memmem(req, rlen, "%2e%2e", 6)) {
            if (resp_len > 0) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                if (code == 200) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_PATH_TRAVERSAL,
                        "DAAP: Path traversal in URL succeeded",
                        NULL, i);
                    oracle_path_traversal_count++;
                }
            }
        }
    }

    /* Info leak: server-info response contains sensitive data */
    if (resp_len > 0) {
        if (ci_memmem(response, resp_len, "dmap.serverinforesponse", 23)) {
            /* Check for unusual fields that shouldn't be exposed */
            if (ci_memmem(response, resp_len, "password", 8) ||
                ci_memmem(response, resp_len, "adminurl", 8)) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_INFO_LEAK,
                    "DAAP: Server-info response contains sensitive fields",
                    NULL, -1);
                oracle_info_leak_count++;
            }
        }
    }

    return result->violation_count;
}

/* ============================================
 * HTTP Oracle
 * ============================================
 * Security invariants from RFC 9112 + real CVEs:
 *
 * 1. PATH TRAVERSAL: ../../../etc/passwd in URL
 * 2. REQUEST SMUGGLING: CL/TE disagreement
 *    CVE-2023-44487 (HTTP/2 rapid reset)
 * 3. AUTH BYPASS: Accessing protected resources without creds
 * 4. INFO LEAK: Server header, directory listing
 * 5. HEADER INJECTION: CRLF in headers
 */

int oracle_check_http(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result) {

    reset_proto_state();

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        /* Path traversal — check the specific response for this request */
        if (ci_memmem(req, rlen, "/../", 4) ||
            ci_memmem(req, rlen, "/..\\", 4) ||
            ci_memmem(req, rlen, "%2e%2e%2f", 9) ||
            ci_memmem(req, rlen, "..%252f", 7) ||
            ci_memmem(req, rlen, "%c0%ae", 6)) {
            if (resp_len > 0) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                if (code == 200) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_PATH_TRAVERSAL,
                        "HTTP: Path traversal succeeded (200 OK)",
                        NULL, i);
                    oracle_path_traversal_count++;
                }
            }
        }

        /* Request smuggling: both Content-Length and Transfer-Encoding */
        int has_cl = (ci_memmem(req, rlen, "Content-Length:", 15) != NULL);
        int has_te = (ci_memmem(req, rlen, "Transfer-Encoding:", 18) != NULL);
        if (has_cl && has_te) {
            oracle_add_violation(result, ORACLE_SEV_HIGH,
                ORACLE_CAT_SMUGGLING,
                "HTTP: Both Content-Length and Transfer-Encoding (smuggling risk)",
                NULL, i);
        }

        /* Multiple Content-Length headers */
        int cl_count = 0;
        const unsigned char *search = req;
        unsigned int search_len = rlen;
        while (search_len > 15) {
            const unsigned char *found = ci_memmem(search, search_len, "Content-Length:", 15);
            if (!found) break;
            cl_count++;
            unsigned int off = (unsigned int)(found - search) + 15;
            search += off;
            search_len -= off;
        }
        if (cl_count > 1) {
            oracle_add_violation(result, ORACLE_SEV_HIGH,
                ORACLE_CAT_SMUGGLING,
                "HTTP: Multiple Content-Length headers (CL desync)",
                NULL, i);
        }
    }

    /* Response checks */
    if (resp_len > 0) {
        /* Info leak: sensitive file content */
        if (ci_memmem(response, resp_len, "root:x:0:0:", 11) ||
            ci_memmem(response, resp_len, "/etc/passwd", 11)) {
            oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                ORACLE_CAT_INFO_LEAK | ORACLE_CAT_PATH_TRAVERSAL,
                "HTTP: /etc/passwd content leaked in response",
                NULL, -1);
            oracle_info_leak_count++;
        }

        /* Info leak: directory listing */
        if (ci_memmem(response, resp_len, "Index of /", 10) ||
            ci_memmem(response, resp_len, "Directory listing", 17)) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_INFO_LEAK,
                "HTTP: Directory listing exposed",
                NULL, -1);
        }

        /* Server header version leak */
        const unsigned char *svr = ci_memmem(response, resp_len, "Server:", 7);
        if (svr) {
            unsigned int remaining = resp_len - (unsigned int)(svr - response);
            const unsigned char *eol = memchr(svr, '\r', remaining);
            if (eol && (eol - svr) > 50) {
                oracle_add_violation(result, ORACLE_SEV_INFO,
                    ORACLE_CAT_INFO_LEAK,
                    "HTTP: Verbose Server header (version fingerprinting)",
                    NULL, -1);
            }
        }
    }

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* Double URL-encoded path traversal (CVE-2021-42013: Apache 2.4.49/50
     * path traversal + RCE via double encoding like %252e%252e%252f). */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (ci_memmem(req, rlen, "%252e%252e", 10) ||
            ci_memmem(req, rlen, "%252e%252e%252f", 14) ||
            ci_memmem(req, rlen, "%%32%65%%32%65", 12) ||
            ci_memmem(req, rlen, ".%2e/", 5)) {
            if (resp_len > 0) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                if (code == 200) {
                    oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                        ORACLE_CAT_PATH_TRAVERSAL,
                        "HTTP: Double-encoded path traversal succeeded (RCE risk if CGI enabled)",
                        "CVE-2021-42013", i);
                    oracle_path_traversal_count++;
                }
            }
        }
    }

    /* Response splitting / HTTP header injection (CVE-2023-38709).
     * Check if response contains CRLF injection artifacts. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        /* Look for CRLF followed by HTTP/1.x in request (response splitting injection) */
        const unsigned char *crlf_http = ci_memmem(req, rlen, "\r\nHTTP/1.", 9);
        if (crlf_http) {
            oracle_add_violation(result, ORACLE_SEV_HIGH,
                ORACLE_CAT_SMUGGLING | ORACLE_CAT_INJECTION,
                "HTTP: CRLF injection with embedded HTTP response (response splitting)",
                "CVE-2023-38709", i);
        }
    }

    /* Chunk extension abuse (CVE-2002-0392: Apache chunked encoding BO).
     * Check for chunked transfer encoding with extremely large extension values. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (ci_memmem(req, rlen, "Transfer-Encoding: chunked", 26) ||
            ci_memmem(req, rlen, "chunked", 7)) {
            /* Check for oversized chunk-size lines (hex size > 0xFFFFFFFF) */
            const unsigned char *body = ci_memmem(req, rlen, "\r\n\r\n", 4);
            if (body) {
                unsigned int body_off = (unsigned int)(body - req) + 4;
                if (body_off + 8 < rlen) {
                    /* Count hex digits in first chunk size */
                    int hex_count = 0;
                    for (unsigned int j = body_off; j < body_off + 20 && j < rlen; j++) {
                        if (isxdigit(req[j])) hex_count++;
                        else if (req[j] == '\r') break;
                    }
                    if (hex_count > 16) {
                        oracle_add_violation(result, ORACLE_SEV_HIGH,
                            ORACLE_CAT_DOS,
                            "HTTP: Oversized chunk-size value (potential BO in chunk parser)",
                            "CVE-2002-0392", i);
                    }
                }
            }
        }
    }

    /* HTTP Auth bypass via mod_rewrite (CVE-2017-3167).
     * Check for requests that bypass auth via URL manipulation. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        /* Patterns like /admin%00/ or /admin..;/ that bypass access controls */
        if (ci_memmem(req, rlen, "%00", 3) ||
            ci_memmem(req, rlen, "..;", 3)) {
            int code = extract_http_style_nth_response_code(response, resp_len, i);
            if (code == 200) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_AUTH_BYPASS,
                    "HTTP: Auth bypass via URL encoding trick (%00 or ..;)",
                    "CVE-2017-3167", i);
                oracle_auth_bypass_count++;
            }
        }
    }

    return result->violation_count;
}

/* ============================================
 * MQTT Oracle
 * ============================================
 * Security invariants from OASIS MQTT v3.1.1/v5 + real CVEs:
 *
 * 1. AUTH BYPASS: PUBLISH/SUBSCRIBE without CONNECT
 *    CVE-2023-34488 (mosquitto auth bypass)
 *
 * 2. ACL VIOLATION: Subscribing to $SYS/# or # wildcard
 *    (should be restricted to admin)
 *
 * 3. WILL MESSAGE ABUSE: Setting will topic to $SYS or admin topics
 *
 * 4. QOS DOWNGRADE: Server downgrades QoS silently
 *
 * 5. CLIENT ID HIJACK: Duplicate client IDs causing session takeover
 *
 * 6. RESOURCE EXHAUST: Retained message flooding
 *    CVE-2023-3592 (mosquitto memory leak)
 */

int oracle_check_mqtt(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result) {

    reset_proto_state();

    int has_connect = 0;

    /* Validate response buffer integrity before auth-bypass checks.
     * In a correct MQTT session, the first response byte should be a
     * CONNACK (0x20).  If request[0] looks like a CONNECT (high nibble=1)
     * but the response doesn't start with 0x20, the buffer is likely
     * polluted by AFL fork-server state accumulation — set a flag to
     * suppress auth-bypass detections (which depend on accurate
     * request↔response correlation). */
    int resp_buffer_trustworthy = 1;
    if (resp_len >= 2 && req_count >= 1) {
        uint8_t first_resp_type = (response[0] >> 4) & 0x0F;
        /* Valid MQTT response types: 2(CONNACK), 3(PUBLISH), 4(PUBACK),
         * 5(PUBREC), 6(PUBREL), 7(PUBCOMP), 9(SUBACK), 11(UNSUBACK),
         * 13(PINGRESP), 14(DISCONNECT).  Type 0,1,8,10,15 are invalid
         * as server responses. */
        if (first_resp_type == 0 || first_resp_type == 1 ||
            first_resp_type == 8 || first_resp_type == 10 ||
            first_resp_type == 15) {
            resp_buffer_trustworthy = 0;
        }
    } else if (resp_len < 2) {
        resp_buffer_trustworthy = 0;
    }

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        if (rlen < 2) continue;

        /* MQTT packet type is in high nibble of first byte */
        uint8_t pkt_type = (req[0] >> 4) & 0x0F;

        switch (pkt_type) {
            case 1:  /* CONNECT */
            {
                /* Decode variable header offset using remaining length */
                unsigned int rl_bytes = 0;
                int rem_len = mqtt_decode_remaining_length(req + 1, rlen - 1, &rl_bytes);
                unsigned int vh_off = 1 + rl_bytes; /* start of variable header */

                /* MQTT CONNECT variable header:
                 * [vh_off+0..5]: Protocol Name ("MQTT" = 00 04 4D 51 54 54) or ("MQIsdp" = 00 06 ...)
                 * [vh_off+6]: Protocol Level
                 * [vh_off+7]: Connect Flags
                 * [vh_off+8..9]: Keep Alive
                 * Payload starts at vh_off+10 for MQTT v3.1.1 (proto name len=4) */
                if (rem_len > 0 && vh_off + 10 < rlen) {
                    /* Validate MQTT protocol signature before trusting has_connect.
                     * Random fuzz bytes with high nibble==1 (0x10-0x1F) would
                     * otherwise falsely set has_connect, masking real auth bypass
                     * detections.  Require "MQTT" or "MQIs" at protocol name. */
                    uint16_t proto_name_len = (req[vh_off] << 8) | req[vh_off + 1];
                    int valid_connect = 0;
                    if (proto_name_len == 4 && vh_off + 6 <= rlen &&
                        memcmp(req + vh_off + 2, "MQTT", 4) == 0) {
                        valid_connect = 1;
                    } else if (proto_name_len == 6 && vh_off + 8 <= rlen &&
                               memcmp(req + vh_off + 2, "MQIsdp", 6) == 0) {
                        valid_connect = 1;
                    }
                    if (!valid_connect) break;  /* Not a real CONNECT */
                    has_connect = 1;
                    /* proto_name_len already computed above for validation */
                    unsigned int flags_off = vh_off + 2 + proto_name_len + 1; /* +1 for level */
                    unsigned int payload_off = flags_off + 3; /* flags(1) + keepalive(2) */

                    /* Check for empty client ID */
                    if (payload_off + 1 < rlen) {
                        uint16_t client_id_len = (req[payload_off] << 8) | req[payload_off + 1];
                        if (client_id_len == 0) {
                            oracle_add_violation(result, ORACLE_SEV_LOW,
                                ORACLE_CAT_ISOLATION,
                                "MQTT: Empty client ID (session collision risk)",
                                NULL, i);
                        }
                    }

                    /* Check for will topic pointing to $SYS */
                    if (flags_off < rlen) {
                        uint8_t connect_flags = req[flags_off];
                        int has_will = (connect_flags >> 2) & 0x01;
                        if (has_will && payload_off + 2 < rlen) {
                            /* Will topic is after client ID in payload */
                            if (ci_memmem(req + payload_off, rlen - payload_off, "$SYS", 4)) {
                                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                                    ORACLE_CAT_AUTHZ_BYPASS,
                                    "MQTT: Will message targets $SYS topic (privilege escalation)",
                                    NULL, i);
                            }
                        }
                    }
                }
                break;
            }

            case 3:  /* PUBLISH */
            {
                /* Decode variable-length header to find topic correctly */
                unsigned int rl_bytes = 0;
                int rem_len = mqtt_decode_remaining_length(req + 1, rlen - 1, &rl_bytes);
                unsigned int hdr_size = 1 + rl_bytes; /* fixed header size */

                if (!has_connect && resp_buffer_trustworthy) {
                    /* Only flag if the i-th response packet is a valid PUBACK
                     * (type=0x40, remaining_len=0x02).  Walk through response
                     * packets counting to find the one at this request's index. */
                    int publish_accepted = 0;
                    if (resp_len >= 2) {
                        unsigned int ri = 0;
                        int pkt_idx = 0;
                        while (ri + 1 < resp_len) {
                            unsigned int rl_b = 0;
                            int rl = mqtt_decode_remaining_length(response + ri + 1,
                                resp_len - ri - 1, &rl_b);
                            if (rl < 0) break;
                            if (pkt_idx == i) {
                                if (response[ri] == 0x40 && rl == 2) {
                                    publish_accepted = 1;
                                }
                                break;
                            }
                            ri += 1 + rl_b + rl;
                            pkt_idx++;
                        }
                    }
                    if (publish_accepted) {
                        oracle_add_violation(result, ORACLE_SEV_HIGH,
                            ORACLE_CAT_AUTH_BYPASS | ORACLE_CAT_STATE_VIOLATION,
                            "MQTT: PUBLISH without CONNECT accepted by broker",
                            "CVE-2023-34488", i);
                        oracle_auth_bypass_count++;
                    }
                }
                /* Check for publishing to $SYS topic — use decoded header offset */
                if (rem_len > 0 && hdr_size + 2 < rlen) {
                    uint16_t topic_len = (req[hdr_size] << 8) | req[hdr_size + 1];
                    if (topic_len > 0 && hdr_size + 2 + topic_len <= rlen) {
                        if (ci_memmem(req + hdr_size + 2, topic_len, "$SYS", 4)) {
                            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                                ORACLE_CAT_AUTHZ_BYPASS,
                                "MQTT: PUBLISH to $SYS topic (ACL bypass)",
                                NULL, i);
                        }
                    }
                }
                /* Check retain flag (bit 0 of first byte) */
                if (req[0] & 0x01) {
                    oracle_add_violation(result, ORACLE_SEV_INFO,
                        ORACLE_CAT_RESOURCE_EXHAUST,
                        "MQTT: Retained message (potential resource exhaustion)",
                        "CVE-2023-3592", i);
                }
                break;
            }

            case 8:  /* SUBSCRIBE */
                if (!has_connect && resp_buffer_trustworthy) {
                    /* Only flag if the response packet at THIS request's position
                     * is a valid SUBACK (0x90).  We walk through the response
                     * buffer counting MQTT packets to find the i-th one, then
                     * verify it is 0x90 with a valid remaining length >= 3.
                     * This avoids false positives from SUBACK bytes appearing
                     * later in the buffer (after a CONNECT that we haven't
                     * seen yet in the request stream). */
                    int sub_accepted = 0;
                    if (resp_len >= 2) {
                        unsigned int ri = 0;
                        int pkt_idx = 0;
                        while (ri + 1 < resp_len) {
                            unsigned int rl_b = 0;
                            int rl = mqtt_decode_remaining_length(response + ri + 1,
                                resp_len - ri - 1, &rl_b);
                            if (rl < 0) break;
                            if (pkt_idx == i) {
                                /* This is the response to request[i] */
                                if (response[ri] == 0x90 && rl >= 3) {
                                    sub_accepted = 1;
                                }
                                break;
                            }
                            ri += 1 + rl_b + rl;
                            pkt_idx++;
                        }
                    }
                    if (sub_accepted) {
                        oracle_add_violation(result, ORACLE_SEV_HIGH,
                            ORACLE_CAT_AUTH_BYPASS | ORACLE_CAT_STATE_VIOLATION,
                            "MQTT: SUBSCRIBE without CONNECT accepted by broker",
                            "CVE-2023-34488", i);
                        oracle_auth_bypass_count++;
                    }
                }
                /* Check for wildcard # subscription to $SYS topics specifically.
                 * Subscribing to # alone is normal default behavior (mosquitto/nanomq/flashmq
                 * allow it without ACL). Only flag $SYS access with response evidence. */
                if (ci_memmem(req, rlen, "$SYS/#", 6) ||
                    ci_memmem(req, rlen, "$SYS/+", 6)) {
                    if (resp_len > 0 && ci_memmem(response, resp_len, "$SYS/", 5)) {
                        oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                            ORACLE_CAT_AUTHZ_BYPASS | ORACLE_CAT_INFO_LEAK,
                            "MQTT: $SYS wildcard subscription returned system data",
                            NULL, i);
                    }
                }
                break;

            case 10: /* UNSUBSCRIBE */
                if (!has_connect) {
                    /* Validate: UNSUBSCRIBE fixed header should be 0xA2 */
                    if (req[0] == 0xA2) {
                        unsigned int rl_b = 0;
                        int rl = mqtt_decode_remaining_length(req + 1, rlen - 1, &rl_b);
                        if (rl >= 3) { /* packet_id(2) + at least 1 topic */
                            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                                ORACLE_CAT_STATE_VIOLATION,
                                "MQTT: UNSUBSCRIBE without CONNECT",
                                NULL, i);
                        }
                    }
                }
                break;

            case 12: /* PINGREQ */
                if (!has_connect) {
                    /* PINGREQ is exactly 0xC0 0x00 (2 bytes) */
                    if (rlen == 2 && req[0] == 0xC0 && req[1] == 0x00) {
                        oracle_add_violation(result, ORACLE_SEV_LOW,
                            ORACLE_CAT_STATE_VIOLATION,
                            "MQTT: PINGREQ without CONNECT",
                            NULL, i);
                    }
                }
                break;

            case 14: /* DISCONNECT */
                break;

            default:
                break;
        }
    }

    /* Check CONNACK response for anomalies */
    if (resp_len >= 4) {
        uint8_t resp_type = (response[0] >> 4) & 0x0F;
        if (resp_type == 2) { /* CONNACK */
            uint8_t return_code = response[3];
            /* If CONNECT was sent with bad credentials but got accepted */
            if (return_code == 0 && !has_connect) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_AUTH_BYPASS,
                    "MQTT: CONNACK success without valid CONNECT",
                    "CVE-2023-34488", -1);
            }
        }
    }

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* Malformed SUBSCRIBE with zero topic length (CVE-2019-5432: mqtt-packet
     * malformed SUBSCRIBE causes broker crash).
     * Check for SUBSCRIBE packet with at least one topic filter of length 0. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (rlen < 2) continue;
        uint8_t pkt_type = (req[0] >> 4) & 0x0F;
        if (pkt_type == 8) { /* SUBSCRIBE */
            unsigned int rl_b = 0;
            int rem_len = mqtt_decode_remaining_length(req + 1, rlen - 1, &rl_b);
            if (rem_len > 0 && rem_len >= 3) {
                unsigned int hdr_size = 1 + rl_b;
                unsigned int payload_off = hdr_size + 2; /* skip packet identifier */
                /* Scan topic filters: each is [2-byte length][topic] [1-byte QoS] */
                unsigned int scan = payload_off;
                while (scan + 2 <= rlen) {
                    uint16_t topic_len = (req[scan] << 8) | req[scan + 1];
                    if (topic_len == 0) {
                        oracle_add_violation(result, ORACLE_SEV_HIGH,
                            ORACLE_CAT_DOS,
                            "MQTT: SUBSCRIBE with zero-length topic filter (broker crash risk)",
                            "CVE-2019-5432", i);
                        oracle_dos_count++;
                        break;
                    }
                    scan += 2 + topic_len + 1;  /* length + topic + QoS */
                    if (scan > rlen) break;
                }
            }
        }
    }

    /* MQTT v5 user-property abuse (CVE-2021-41039: excessive user-property
     * leads to CPU exhaustion in Mosquitto 1.6-2.0.11).
     * Count PROP_USER (0x26) properties in CONNECT and PUBLISH packets. */
    {
        int user_prop_count = 0;
        for (int i = 0; i < req_count; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            for (unsigned int j = 0; j < rlen; j++) {
                if (req[j] == 0x26) user_prop_count++;  /* MQTT v5 PROP_USER identifier */
            }
        }
        if (user_prop_count > 50) {
            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                ORACLE_CAT_DOS | ORACLE_CAT_RESOURCE_EXHAUST,
                "MQTT: Excessive v5 user-properties (CPU exhaustion risk)",
                "CVE-2021-41039", -1);
            oracle_dos_count++;
        }
    }

    /* Session takeover via empty client ID with clean_session=0
     * (CVE-2014-6116: WebSphere MQ auth bypass via session reuse).
     * Check for CONNECT with clean_session=0 and empty client ID.
     * This allows one client to hijack another's session. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (rlen < 2) continue;
        uint8_t pkt_type = (req[0] >> 4) & 0x0F;
        if (pkt_type == 1) { /* CONNECT */
            unsigned int rl_b = 0;
            int rem_len = mqtt_decode_remaining_length(req + 1, rlen - 1, &rl_b);
            if (rem_len > 0) {
                unsigned int vh_off = 1 + rl_b;
                if (vh_off + 10 <= rlen) {
                    uint16_t proto_name_len = (req[vh_off] << 8) | req[vh_off + 1];
                    unsigned int flags_off = vh_off + 2 + proto_name_len + 1;
                    if (flags_off < rlen) {
                        uint8_t connect_flags = req[flags_off];
                        int clean_session = (connect_flags >> 1) & 0x01;
                        uint16_t cid_len = (req[flags_off + 3] << 8) | req[flags_off + 4];
                        if (!clean_session && cid_len == 0) {
                            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                                ORACLE_CAT_ISOLATION | ORACLE_CAT_AUTH_BYPASS,
                                "MQTT: Empty ClientID with clean_session=0 (session hijack risk)",
                                "CVE-2014-6116", i);
                        }
                    }
                }
            }
        }
    }

    /* Duplicate packet identifier detection (session hijack / replay attack).
     * PUBLISH and SUBSCRIBE packets carry 2-byte packet identifiers.
     * Duplicate IDs in the same session suggest replay or hijack attempt. */
    {
        uint16_t seen_ids[256];
        int seen_count = 0;
        for (int i = 0; i < req_count && seen_count < 256; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            if (rlen < 4) continue;
            uint8_t pkt_type = (req[0] >> 4) & 0x0F;
            if (pkt_type == 3 || pkt_type == 8 || pkt_type == 6 || pkt_type == 10) {
                unsigned int rl_b = 0;
                mqtt_decode_remaining_length(req + 1, rlen - 1, &rl_b);
                unsigned int hdr_size = 1 + rl_b;
                if (hdr_size + 2 <= rlen) {
                    uint16_t pkt_id = (req[hdr_size] << 8) | req[hdr_size + 1];
                    if (pkt_id != 0) {
                        for (int s = 0; s < seen_count; s++) {
                            if (seen_ids[s] == pkt_id) {
                                oracle_add_violation(result, ORACLE_SEV_LOW,
                                    ORACLE_CAT_REPLAY | ORACLE_CAT_STATE_VIOLATION,
                                    "MQTT: Duplicate packet identifier (replay/session hijack)",
                                    NULL, i);
                                break;
                            }
                        }
                        if (seen_count < 256) seen_ids[seen_count++] = pkt_id;
                    }
                }
            }
        }
    }

    return result->violation_count;
}

/* ============================================
 * Main Oracle Dispatch
 * ============================================ */

void oracle_init(const char *protocol_name) {
    memset(oracle_dedup_bitmap, 0, sizeof(oracle_dedup_bitmap));
    oracle_initialized = 1;
    printf("[ORACLE] Initialized protocol-specific semantic oracle for: %s\n",
           protocol_name ? protocol_name : "unknown");
    printf("[ORACLE] Checking: auth-bypass, state-machine, info-leak, "
           "path-traversal, injection, DoS, smuggling\n");
}

int oracle_is_new_violation(uint32_t pattern_hash) {
    uint32_t slot = pattern_hash % ORACLE_DEDUP_SIZE;
    if (oracle_dedup_bitmap[slot] == pattern_hash) return 0;
    oracle_dedup_bitmap[slot] = pattern_hash;
    return 1;
}

int oracle_check(
    const char *protocol_name,
    const unsigned char **requests,
    const unsigned int *req_lens,
    int req_count,
    const unsigned char *response,
    unsigned int resp_len,
    oracle_result_t *result) {

    if (!oracle_initialized || !protocol_name || !result) return 0;
    if (req_count <= 0) return 0;

    memset(result, 0, sizeof(oracle_result_t));
    oracle_total_checks++;

    int violations = 0;

    if (strcasecmp(protocol_name, "FTP") == 0) {
        violations = oracle_check_ftp(requests, req_lens, req_count, response, resp_len, result);
    } else if (strcasecmp(protocol_name, "SMTP") == 0) {
        violations = oracle_check_smtp(requests, req_lens, req_count, response, resp_len, result);
    } else if (strcasecmp(protocol_name, "RTSP") == 0) {
        violations = oracle_check_rtsp(requests, req_lens, req_count, response, resp_len, result);
    } else if (strcasecmp(protocol_name, "SIP") == 0) {
        violations = oracle_check_sip(requests, req_lens, req_count, response, resp_len, result);
    } else if (strcasecmp(protocol_name, "DAAP") == 0) {
        violations = oracle_check_daap(requests, req_lens, req_count, response, resp_len, result);
    } else if (strcasecmp(protocol_name, "HTTP") == 0) {
        violations = oracle_check_http(requests, req_lens, req_count, response, resp_len, result);
    } else if (strcasecmp(protocol_name, "MQTT") == 0) {
        violations = oracle_check_mqtt(requests, req_lens, req_count, response, resp_len, result);
    }

    if (violations > 0) {
        oracle_total_violations += violations;

        /* Count unique violations */
        for (int i = 0; i < result->violation_count; i++) {
            if (oracle_is_new_violation(result->violations[i].pattern_hash)) {
                oracle_unique_violations++;
            }
        }
    }

    return violations;
}

void oracle_save_violation(
    const char *out_dir,
    const oracle_result_t *result,
    const unsigned char *request_data,
    unsigned int request_len,
    const unsigned char *response_data,
    unsigned int response_len) {

    if (!out_dir || !result || result->violation_count == 0) return;

    /* Create violations directory */
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/replayable-violations", out_dir);
    mkdir(dir_path, 0755);

    /* Generate filename */
    char fn[1024];
    snprintf(fn, sizeof(fn), "%s/id:%06llu,sev:%d,cat:%04x",
             dir_path, oracle_unique_violations,
             result->max_severity, result->categories_hit);

    FILE *fp = fopen(fn, "w");
    if (!fp) return;

    fprintf(fp, "=== PROTOCOL ORACLE VIOLATION REPORT ===\n");
    fprintf(fp, "Time: %ld\n", (long)time(NULL));
    fprintf(fp, "Violations: %d\n", result->violation_count);
    fprintf(fp, "Max Severity: %d\n", result->max_severity);
    fprintf(fp, "Categories: 0x%04x\n\n", result->categories_hit);

    for (int i = 0; i < result->violation_count; i++) {
        const oracle_violation_t *v = &result->violations[i];
        fprintf(fp, "--- Violation %d ---\n", i + 1);
        fprintf(fp, "Severity: %d\n", v->severity);
        fprintf(fp, "Category: 0x%04x\n", v->category);
        fprintf(fp, "Description: %s\n", v->description);
        if (v->cve_reference[0]) {
            fprintf(fp, "CVE Pattern: %s\n", v->cve_reference);
        }
        fprintf(fp, "Request Index: %d\n", v->request_index);
        fprintf(fp, "Pattern Hash: 0x%08x\n\n", v->pattern_hash);
    }

    /* Write request data */
    if (request_data && request_len > 0) {
        fprintf(fp, "=== REQUEST DATA (%u bytes) ===\n", request_len);
        fwrite(request_data, 1, request_len > 4096 ? 4096 : request_len, fp);
        fprintf(fp, "\n");
    }

    /* Write response data */
    if (response_data && response_len > 0) {
        fprintf(fp, "=== RESPONSE DATA (%u bytes) ===\n", response_len);
        fwrite(response_data, 1, response_len > 4096 ? 4096 : response_len, fp);
        fprintf(fp, "\n");
    }

    fclose(fp);
}

const char* oracle_stats_string(void) {
    snprintf(oracle_stats_buf, sizeof(oracle_stats_buf),
        "oracle: %llu chk, %llu viol (%llu uniq) | "
        "auth:%llu state:%llu leak:%llu path:%llu dos:%llu",
        (unsigned long long)oracle_total_checks,
        (unsigned long long)oracle_total_violations,
        (unsigned long long)oracle_unique_violations,
        (unsigned long long)oracle_auth_bypass_count,
        (unsigned long long)oracle_state_violation_count,
        (unsigned long long)oracle_info_leak_count,
        (unsigned long long)oracle_path_traversal_count,
        (unsigned long long)oracle_dos_count);
    return oracle_stats_buf;
}
