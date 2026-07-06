/*
 * ChatAFL-Opt: Protocol Behavioral Deviation Oracle
 * ===================================================
 *
 * Observes request-response traffic and flags protocol-level behavioural
 * deviations from RFC-mandated behaviour and known attack patterns.
 *
 * THE ORACLE DOES NOT DETECT VULNERABILITIES.  It detects observable
 * deviations that would be necessary (but not sufficient) conditions
 * for vulnerability exploitation.  Every saved report is a CANDIDATE
 * requiring manual triage against server configuration and deployment
 * context.
 *
 * Four evidence quality levels guard against false positives:
 *   EVIDENCE_STRONG   (3): Precise response-code match (==230, SUBACK pktID)
 *   EVIDENCE_MODERATE (2): Response-code range (>=200) + position verified
 *   EVIDENCE_WEAK     (1): Response content pattern, no per-request mapping
 *   EVIDENCE_HEURISTIC(0): Aggregate threshold, weakest signal
 *
 * Output pipeline:
 *   INFO/LOW (1-2)    -> contextual observations, not counted as findings
 *   MEDIUM+  (3-5)    -> reportable candidates with full request+response
 *
 * CVE references are kept only when they are target-relevant; otherwise the
 * report uses N/A and describes the observable protocol deviation.
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
                                  uint8_t evidence_quality,
                                  const char *desc, const char *cve_ref,
                                  int req_idx) {
    if (result->violation_count >= ORACLE_MAX_VIOLATIONS) return;

    oracle_violation_t *v = &result->violations[result->violation_count];
    v->severity = severity;
    v->category = category;
    v->evidence_quality = evidence_quality;
    v->request_index = req_idx;

    /* Build pattern hash from description + category + evidence for dedup */
    char hash_input[320];
    snprintf(hash_input, sizeof(hash_input), "%d:%04x:%d:%s",
             severity, category, evidence_quality, desc);
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
static int __attribute__((unused)) extract_response_code(const unsigned char *resp, unsigned int len) {
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
static int __attribute__((unused))
server_rejected_command(const unsigned char *resp, unsigned int resp_len,
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
    if (strncasecmp((const char *)req, cmd, clen) != 0) return 0;

    /* If the caller supplied a syntactic separator, the prefix is enough.
     * Otherwise require a command boundary so "LIS2" does not match "LIST". */
    if (clen == 0) return 1;
    char last = cmd[clen - 1];
    if (last == ' ' || last == ':' || last == '\r' || last == '\n')
        return 1;
    if (len == clen) return 1;
    return req[clen] == ' ' || req[clen] == '\r' ||
           req[clen] == '\n' || req[clen] == '\t';
}

static int code_is_2xx(int code) {
    return code >= 200 && code < 300;
}

static int response_has_phrase(const unsigned char *resp, unsigned int resp_len,
                               const char *phrase) {
    return resp && phrase && ci_memmem(resp, resp_len, phrase, strlen(phrase)) != NULL;
}

static int request_contains_any(const unsigned char **requests,
                                const unsigned int *req_lens, int req_count,
                                const char *needle) {
    size_t nlen = strlen(needle);
    for (int i = 0; i < req_count; i++) {
        if (ci_memmem(requests[i], req_lens[i], needle, nlen)) return 1;
    }
    return 0;
}

static int command_boundary_ok(const unsigned char *buf, unsigned int len,
                               unsigned int off, const char *cmd) {
    size_t clen = strlen(cmd);
    if (off + clen > len) return 0;
    if (strncasecmp((const char *)buf + off, cmd, clen) != 0) return 0;

    if (clen == 0) return 1;
    char last = cmd[clen - 1];
    if (last == ' ' || last == ':' || last == '\r' || last == '\n')
        return 1;
    if (off + clen == len) return 1;
    return buf[off + clen] == ' ' || buf[off + clen] == '\r' ||
           buf[off + clen] == '\n' || buf[off + clen] == '\t' ||
           buf[off + clen] == ':';
}

/* AFLNet can put multiple text-protocol commands in one request region.  These
 * helpers inspect command lines, not only the first bytes of the region. */
static int request_line_command_pos(const unsigned char *req, unsigned int len,
                                    const char *cmd, unsigned int *pos) {
    unsigned int i = 0;
    while (i < len) {
        while (i < len && (req[i] == '\r' || req[i] == '\n')) i++;
        unsigned int line_start = i;
        if (command_boundary_ok(req, len, line_start, cmd)) {
            if (pos) *pos = line_start;
            return 1;
        }
        while (i < len && req[i] != '\n') i++;
        if (i < len) i++;
    }
    return 0;
}

static int request_has_line_command(const unsigned char *req, unsigned int len,
                                    const char *cmd) {
    return request_line_command_pos(req, len, cmd, NULL);
}

static int prior_requests_have_line_command(const unsigned char **requests,
                                            const unsigned int *req_lens,
                                            int req_count, const char *cmd) {
    for (int i = 0; i < req_count; i++) {
        if (request_has_line_command(requests[i], req_lens[i], cmd)) return 1;
    }
    return 0;
}

/* Match an HTTP-style header at the beginning of a header line. This avoids
 * counting "Content-Length:" embedded inside a value as a second header. */
static int count_header_lines(const unsigned char *buf, unsigned int len,
                              const char *header_name) {
    size_t hlen = strlen(header_name);
    int count = 0;
    unsigned int i = 0;

    while (i + hlen < len) {
        if ((i == 0 || buf[i - 1] == '\n') &&
            strncasecmp((const char *)buf + i, header_name, hlen) == 0) {
            unsigned int j = i + hlen;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
            if (j < len && buf[j] == ':') count++;
        }
        while (i < len && buf[i] != '\n') i++;
        if (i < len) i++;
    }
    return count;
}

static int __attribute__((unused))
header_line_length_exceeds(const unsigned char *buf, unsigned int len,
                           const char *header_name, unsigned int limit) {
    size_t hlen = strlen(header_name);
    unsigned int i = 0;

    while (i + hlen < len) {
        if ((i == 0 || buf[i - 1] == '\n') &&
            strncasecmp((const char *)buf + i, header_name, hlen) == 0) {
            unsigned int j = i;
            while (j < len && buf[j] != '\r' && buf[j] != '\n') j++;
            return (j - i) > limit;
        }
        while (i < len && buf[i] != '\n') i++;
        if (i < len) i++;
    }
    return 0;
}

static int parse_header_uint(const unsigned char *buf, unsigned int len,
                             const char *header_name, unsigned int *out) {
    size_t hlen = strlen(header_name);
    unsigned int i = 0;

    while (i + hlen < len) {
        if ((i == 0 || buf[i - 1] == '\n') &&
            strncasecmp((const char *)buf + i, header_name, hlen) == 0) {
            unsigned int j = i + hlen;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
            if (j >= len || buf[j] != ':') return 0;
            j++;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
            if (j >= len || !isdigit(buf[j])) return 0;
            unsigned int val = 0;
            while (j < len && isdigit(buf[j])) {
                val = val * 10 + (unsigned int)(buf[j] - '0');
                j++;
            }
            if (out) *out = val;
            return 1;
        }
        while (i < len && buf[i] != '\n') i++;
        if (i < len) i++;
    }
    return 0;
}

static int extract_rtsp_cseq(const unsigned char *req, unsigned int len,
                             unsigned int *cseq) {
    return parse_header_uint(req, len, "CSeq", cseq);
}

static int rtsp_response_block_by_cseq_unique(const unsigned char *resp,
                                              unsigned int len,
                                              unsigned int want_cseq,
                                              const unsigned char **block,
                                              unsigned int *block_len,
                                              int *code_out) {
    unsigned int i = 0;
    int matches = 0;
    const unsigned char *found_block = NULL;
    unsigned int found_len = 0;
    int found_code = -1;

    while (i + 12 < len) {
        if ((i == 0 || resp[i - 1] == '\n') &&
            ci_memmem(resp + i, (len - i < 12) ? len - i : 12, "RTSP/", 5)) {
            unsigned int j = i;
            while (j < len && resp[j] != ' ') j++;
            if (++j + 2 >= len) break;
            if (!isdigit(resp[j]) || !isdigit(resp[j + 1]) || !isdigit(resp[j + 2])) {
                while (i < len && resp[i] != '\n') i++;
                if (i < len) i++;
                continue;
            }
            int code = (resp[j] - '0') * 100 +
                       (resp[j + 1] - '0') * 10 +
                       (resp[j + 2] - '0');

            unsigned int block_start = i;
            unsigned int block_end = len;
            unsigned int k = i + 1;
            while (k + 5 < len) {
                while (k < len && resp[k] != '\n') k++;
                if (k < len) k++;
                if (k + 5 < len && ci_memmem(resp + k,
                    (len - k < 12) ? len - k : 12, "RTSP/", 5)) {
                    block_end = k;
                    break;
                }
            }

            unsigned int cseq = 0;
            if (parse_header_uint(resp + block_start, block_end - block_start,
                                  "CSeq", &cseq) && cseq == want_cseq) {
                matches++;
                found_block = resp + block_start;
                found_len = block_end - block_start;
                found_code = code;
            }
            i = block_end;
            continue;
        }
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }
    if (matches == 1) {
        if (block) *block = found_block;
        if (block_len) *block_len = found_len;
        if (code_out) *code_out = found_code;
        return 1;
    }
    return 0;
}

static int extract_rtsp_response_code_by_cseq(const unsigned char *resp,
                                              unsigned int len,
                                              unsigned int want_cseq) {
    int code = -1;
    if (rtsp_response_block_by_cseq_unique(resp, len, want_cseq,
                                           NULL, NULL, &code))
        return code;
    return -1;
}

typedef struct {
    unsigned int pkt_end;
    unsigned int proto_level;
    unsigned int flags_off;
    unsigned int payload_off;
    uint8_t connect_flags;
} mqtt_connect_info_t;

static int mqtt_parse_connect(const unsigned char *req, unsigned int rlen,
                              mqtt_connect_info_t *out) {
    if (!req || rlen < 2 || ((req[0] >> 4) & 0x0F) != 1) return 0;

    unsigned int rl_b = 0;
    int rem_len = mqtt_decode_remaining_length(req + 1, rlen - 1, &rl_b);
    if (rem_len < 0) return 0;
    unsigned int pkt_end = 1 + rl_b + (unsigned int)rem_len;
    if (pkt_end > rlen) return 0;

    unsigned int vh_off = 1 + rl_b;
    if (vh_off + 2 > pkt_end) return 0;
    uint16_t proto_name_len = (req[vh_off] << 8) | req[vh_off + 1];
    if (vh_off + 2 + proto_name_len + 4 > pkt_end) return 0;

    int valid_connect = 0;
    if (proto_name_len == 4 &&
        memcmp(req + vh_off + 2, "MQTT", 4) == 0) {
        valid_connect = 1;
    } else if (proto_name_len == 6 &&
               memcmp(req + vh_off + 2, "MQIsdp", 6) == 0) {
        valid_connect = 1;
    }
    if (!valid_connect) return 0;

    unsigned int level_off = vh_off + 2 + proto_name_len;
    unsigned int flags_off = level_off + 1;
    if (flags_off + 3 > pkt_end) return 0;

    unsigned int payload_off = flags_off + 3; /* flags + keepalive */
    unsigned int proto_level = req[level_off];

    if (proto_level == 5) {
        unsigned int prop_len_bytes = 0;
        int prop_len = mqtt_decode_remaining_length(req + payload_off,
            pkt_end - payload_off, &prop_len_bytes);
        if (prop_len < 0) return 0;
        payload_off += prop_len_bytes + (unsigned int)prop_len;
        if (payload_off > pkt_end) return 0;
    }

    if (out) {
        out->pkt_end = pkt_end;
        out->proto_level = proto_level;
        out->flags_off = flags_off;
        out->payload_off = payload_off;
        out->connect_flags = req[flags_off];
    }
    return 1;
}

static int mqtt_response_has_connack_success(const unsigned char *resp,
                                             unsigned int resp_len) {
    for (unsigned int off = 0; off + 1 < resp_len; ) {
        uint8_t pkt_type = (resp[off] >> 4) & 0x0F;
        unsigned int rl_b = 0;
        int rem_len = mqtt_decode_remaining_length(resp + off + 1,
            resp_len - off - 1, &rl_b);
        if (rem_len < 0) return 0;

        unsigned int pkt_start = off + 1 + rl_b;
        unsigned int pkt_end = pkt_start + (unsigned int)rem_len;
        if (pkt_end > resp_len) return 0;

        if (pkt_type == 2) { /* CONNACK */
            return rem_len >= 2 && pkt_start + 1 < resp_len &&
                   resp[pkt_start + 1] == 0x00;
        }

        off = pkt_end;
    }
    return 0;
}

static int smtp_path_has_bare_crlf(const unsigned char *req, unsigned int len) {
    const unsigned char *lt = memchr(req, '<', len);
    if (!lt) return 0;
    unsigned int off = (unsigned int)(lt - req) + 1;
    for (unsigned int i = off; i < len; i++) {
        if (req[i] == '>') return 0;
        if (req[i] == '\r') return (i + 1 >= len || req[i + 1] != '\n');
        if (req[i] == '\n') return (i == 0 || req[i - 1] != '\r');
    }
    return 0;
}

static int smtp_rcpt_domain_is_external(const unsigned char *req, unsigned int len) {
    const unsigned char *at = memchr(req, '@', len);
    if (!at) return 0;
    unsigned int start = (unsigned int)(at - req) + 1;
    unsigned int end = start;
    while (end < len && req[end] != '>' && req[end] != '\r' &&
           req[end] != '\n' && req[end] != ' ' && req[end] != '\t') {
        end++;
    }
    if (end <= start) return 0;

    unsigned int dlen = end - start;
    if (dlen == 9 && strncasecmp((const char *)req + start, "localhost", 9) == 0)
        return 0;
    if (dlen == 6 && strncasecmp((const char *)req + start, "ubuntu", 6) == 0)
        return 0;
    if (dlen == 11 && strncasecmp((const char *)req + start, "localdomain", 11) == 0)
        return 0;
    if (dlen >= 4 && strncasecmp((const char *)req + start, "127.", 4) == 0)
        return 0;

    for (unsigned int i = start; i < end; i++) {
        if (req[i] == '.') return 1;
    }
    return 0;
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
    int has_user = 0, has_data_cmd = 0;
    int has_path_traversal = 0, has_rnfr = 0;
    int data_cmd_index = -1;
    int authenticated = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        int code = extract_nth_response_code(response, resp_len, i + resp_offset);

        if (code == 331) {
            has_user = 1;
            authenticated = 0;
        } else if (code == 230) {
            authenticated = 1;
        }

        if (request_has_line_command(req, rlen, "USER ")) {
            /* Only accept USER if server responded 331 (Password required).
             * Fuzz data may randomly match "USER " prefix; blind reset of
             * authenticated would cause massive false-positive auth_bypass. */
            if (code == 331) {
                has_user = 1;
                authenticated = 0;  /* new USER starts fresh auth sequence */
            }
        }
        if (request_has_line_command(req, rlen, "PASS ") ||
            request_has_line_command(req, rlen, "PASS\r\n") ||
            (rlen == 4 && memcmp(req, "PASS", 4) == 0)) {
            if (has_user) {
                if (code >= 200 && code < 300) {
                    authenticated = 1;  /* only if server accepted PASS */
                }
            }
        }
        if (request_has_line_command(req, rlen, "RNFR ")) has_rnfr = 1;

        /* Data commands that require auth — only flag if NOT yet authenticated */
        if (!authenticated &&
            (request_has_line_command(req, rlen, "RETR ") ||
             request_has_line_command(req, rlen, "STOR ") ||
             request_has_line_command(req, rlen, "LIST") ||
             request_has_line_command(req, rlen, "NLST") ||
             request_has_line_command(req, rlen, "MKD ") ||
             request_has_line_command(req, rlen, "RMD ") ||
             request_has_line_command(req, rlen, "DELE ") ||
             request_has_line_command(req, rlen, "APPE ") ||
             request_has_line_command(req, rlen, "SITE "))) {
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
        if (request_has_line_command(req, rlen, "RNTO ") && !has_rnfr) {
            if (code == 250) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    ORACLE_EVIDENCE_STRONG,
                    "FTP: RNTO without prior RNFR accepted by server",
                    NULL, i);
            }
        }

        /* State machine: PASS without USER — check the specific response */
        if (request_has_line_command(req, rlen, "PASS ") && !has_user) {
            /* If any earlier request region contains USER, the splitter may have
             * lost command boundaries.  If any earlier response was 331, the
             * server objectively entered USER/PASS state even if USER syntax was
             * fuzzed, so do not claim PASS-without-USER. */
            int prior_user_seen =
                prior_requests_have_line_command(requests, req_lens, i, "USER ");
            for (int u = 0; u < i && !prior_user_seen; u++) {
                int prior_code = extract_nth_response_code(response, resp_len, u + resp_offset);
                if (prior_code == 331) prior_user_seen = 1;
            }
            if (!prior_user_seen && code == 230) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_STATE_VIOLATION | ORACLE_CAT_AUTH_BYPASS,
                    ORACLE_EVIDENCE_STRONG,
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
                ORACLE_EVIDENCE_STRONG,
                "FTP: Data command succeeded without authentication",
                "CVE-2024-42645", data_cmd_index);
            /* oracle_auth_bypass_count auto-derived by dispatcher */
        }
    }

    /* Check path traversal success: ONLY flag on filesystem-access commands.
     * Info/status commands (NOOP, STAT, HELP, SYST, FEAT) cannot traverse
     * the filesystem — their responses (200/211/214/215) would falsely
     * match the response code range.  Also restrict response codes to
     * data-transfer or path-specific codes (150, 226, 250, 257), excluding
     * generic success codes that could belong to non-filesystem commands. */
    if (has_path_traversal && resp_len > 0) {
        for (int i = 0; i < req_count; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            /* Only filesystem-access commands can perform path traversal */
            if (!request_starts_with(req, rlen, "RETR ") &&
                !request_starts_with(req, rlen, "STOR ") &&
                !request_starts_with(req, rlen, "DELE ") &&
                !request_starts_with(req, rlen, "RMD ")  &&
                !request_starts_with(req, rlen, "RNFR ") &&
                !request_starts_with(req, rlen, "RNTO ") &&
                !request_starts_with(req, rlen, "MKD ")  &&
                !request_starts_with(req, rlen, "CWD ")  &&
                !request_starts_with(req, rlen, "CDUP ") &&
                !request_starts_with(req, rlen, "LIST ") &&
                !request_starts_with(req, rlen, "NLST ") &&
                !request_starts_with(req, rlen, "MLSD ") &&
                !request_starts_with(req, rlen, "RETR")   &&
                !request_starts_with(req, rlen, "STOR")   &&
                !request_starts_with(req, rlen, "DELE")   &&
                !request_starts_with(req, rlen, "RMD")    &&
                !request_starts_with(req, rlen, "MKD")    &&
                !request_starts_with(req, rlen, "CWD")    &&
                !request_starts_with(req, rlen, "LIST")   &&
                !request_starts_with(req, rlen, "NLST"))
                continue;
            if (ci_memmem(req, rlen, "../", 3) || ci_memmem(req, rlen, "..\\", 3) ||
                ci_memmem(req, rlen, "%2e%2e", 6)) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code == 150 || code == 226 || code == 250 || code == 257) {
                    oracle_add_violation(result, ORACLE_SEV_LOW,
                        ORACLE_CAT_PATH_TRAVERSAL,
                        ORACLE_EVIDENCE_HEURISTIC,
                        "FTP: Traversal syntax accepted by filesystem command (manual replay required)",
                        "N/A", i);
                    break;  /* One finding is enough */
                }
            }
        }
    }

    /* Info leak: check for sensitive patterns in response.
     * Must NOT be echoed from client request (e.g. client sent
     * "RETR /etc/passwd" → server responds "550 Cannot access /etc/passwd"
     * is NOT a leak — it's the server correctly rejecting the request). */
    #define PAT_IN_REQ(pat, plen) do { \
        int _found = 0; \
        for (int _ri = 0; _ri < req_count && !_found; _ri++) \
            if (ci_memmem(requests[_ri], req_lens[_ri], pat, plen)) _found = 1; \
        checked_in_requests = _found; \
    } while(0)

    if (resp_len > 0) {
        int checked_in_requests = 0;

        /* Tier-1 CRITICAL: shadow/cert/key content */
        if (ci_memmem(response, resp_len, "/etc/shadow", 11) ||
            ci_memmem(response, resp_len, "root:$", 6) ||
            ci_memmem(response, resp_len, "-----BEGIN RSA PRIVATE KEY-----", 35) ||
            ci_memmem(response, resp_len, "-----BEGIN OPENSSH PRIVATE KEY-----", 38) ||
            ci_memmem(response, resp_len, "PRIVATE KEY-----", 16) ||
            ci_memmem(response, resp_len, "id_rsa", 6) ||
            ci_memmem(response, resp_len, "authorized_keys", 16)) {
            PAT_IN_REQ("BEGIN RSA PRIVATE KEY", 22);
            if (!checked_in_requests) PAT_IN_REQ("BEGIN OPENSSH PRIVATE KEY", 25);
            if (!checked_in_requests) PAT_IN_REQ("BEGIN PRIVATE KEY", 17);
            if (!checked_in_requests) PAT_IN_REQ("/etc/shadow", 11);
            if (!checked_in_requests) PAT_IN_REQ("authorized_keys", 16);
            if (!checked_in_requests) {
                oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                    ORACLE_CAT_INFO_LEAK,
                    ORACLE_EVIDENCE_WEAK,
                    "FTP: Sensitive file CONTENT leaked (shadow/cert/key)",
                    "CVE-2024-42650", -1);
            }
        }

        /* Tier-2 HIGH: /etc/passwd content */
        if ((ci_memmem(response, resp_len, "/etc/passwd", 11) ||
             ci_memmem(response, resp_len, "root:x:0:0:", 11))) {
            PAT_IN_REQ("/etc/passwd", 11);
            if (!checked_in_requests) PAT_IN_REQ("root:x:0:0:", 11);
            if (!checked_in_requests) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_INFO_LEAK,
                    ORACLE_EVIDENCE_WEAK,
                    "FTP: /etc/passwd content leaked (NOT command echo)",
                    "CVE-2024-42650", -1);
            }
        }

        /* Tier-3 LOW: internal path/version disclosure */
        if (ci_memmem(response, resp_len, "/home/", 6) ||
            ci_memmem(response, resp_len, "/var/www", 7)) {
            PAT_IN_REQ("/home/", 6);
            if (!checked_in_requests) PAT_IN_REQ("/var/www", 7);
            if (!checked_in_requests) {
                oracle_add_violation(result, ORACLE_SEV_LOW,
                    ORACLE_CAT_INFO_LEAK,
                    ORACLE_EVIDENCE_WEAK,
                    "FTP: Internal path disclosed in response",
                    NULL, -1);
            }
        }
    }
    #undef PAT_IN_REQ

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* REMOVED (2026-07-06): FTP CRLF-in-argument heuristic.
     * AFLNet request regions may legitimately contain multiple FTP commands
     * separated by CRLF.  Without a command-level tokenizer and response
     * binding for the injected command, CRLF inside a region is not objective
     * evidence of FTP command smuggling.  Real impact should surface as a
     * state/auth/path finding with its own accepted response or as a crash. */

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
                /* RFC 1918 private addresses + loopback + link-local.
                 * Modern FTP servers bind data connections to the
                 * control-channel IP by default, making FTP bounce
                 * attacks infeasible.  INFO severity — configuration
                 * observation, not a verified vulnerability. */
                if (h1 == 10 || (h1 == 172 && h2 >= 16 && h2 <= 31) ||
                    (h1 == 192 && h2 == 168) || h1 == 127 ||
                    (h1 == 169 && h2 == 254)) {
                    oracle_add_violation(result, ORACLE_SEV_INFO,
                        ORACLE_CAT_ISOLATION,
                        ORACLE_EVIDENCE_HEURISTIC,
                        "FTP: PORT command specifies private/internal address (configuration observation)",
                        "N/A", i);
                }
            }
        }
    }

    /* REMOVED (2026-07-04): Format string specifier detection.
     * Circular detection: the fuzzer's havoc mutation produces binary
     * data naturally containing %n/%s/%x/%d/%p bytes.  The oracle then
     * "discovers" these self-inflicted patterns as vulnerabilities.
     *   CVE-2006-6750 = XM Easy FTP Server — NOT a benchmark target.
     *   A genuine format-string vuln would cause a crash (AFL/ASAN).
     * Same pattern as removed QoS=3, BYE, ACK, Max-Forwards checks. */

    /* TLS downgrade detection: AUTH TLS followed by
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
                                ORACLE_EVIDENCE_STRONG,
                                "FTP: Cleartext data transfer after AUTH TLS (TLS downgrade risk)",
                                "N/A", k);
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
                ORACLE_EVIDENCE_HEURISTIC,
                "FTP: Excessive failed authentication attempts (resource exhaustion risk)",
                "CVE-2026-41324", -1);
            /* oracle_dos_count auto-derived by dispatcher */
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

    int has_auth = 0, has_mail = 0, has_rcpt = 0;
    int has_vrfy = 0, has_expn = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        unsigned int auth_pos = 0, mail_pos = 0, rcpt_pos = 0, data_pos = 0;
        unsigned int vrfy_pos = 0, expn_pos = 0;
        int cur_auth = request_line_command_pos(req, rlen, "AUTH ", &auth_pos);
        int cur_mail = request_line_command_pos(req, rlen, "MAIL FROM:", &mail_pos);
        int cur_rcpt = request_line_command_pos(req, rlen, "RCPT TO:", &rcpt_pos);
        int cur_data = request_line_command_pos(req, rlen, "DATA", &data_pos);
        int cur_vrfy = request_line_command_pos(req, rlen, "VRFY ", &vrfy_pos);
        int cur_expn = request_line_command_pos(req, rlen, "EXPN ", &expn_pos);
        (void)auth_pos;
        (void)vrfy_pos;
        (void)expn_pos;

        /* State violation: DATA before RCPT.  SMTP acceptance of DATA is
         * specifically 354; generic 2xx greetings/NOOP replies are not enough. */
        int rcpt_seen_before_data = has_rcpt || (cur_rcpt && rcpt_pos < data_pos);
        if (cur_data && !rcpt_seen_before_data) {
            int code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if (code == 354 &&
                !response_has_phrase(response, resp_len, "RCPT command must precede DATA")) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    ORACLE_EVIDENCE_STRONG,
                    "SMTP: DATA before RCPT TO accepted by server",
                    NULL, i);
            }
        }

        /* State violation: RCPT before MAIL FROM.  Require an RCPT accept code,
         * and suppress when Exim explicitly says the sender is missing. */
        int mail_seen_before_rcpt = has_mail || (cur_mail && mail_pos < rcpt_pos);
        if (cur_rcpt && !mail_seen_before_rcpt) {
            int code = extract_nth_response_code(response, resp_len, i + resp_offset);
            if ((code == 250 || code == 251) &&
                !response_has_phrase(response, resp_len, "sender not yet given")) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    ORACLE_EVIDENCE_STRONG,
                    "SMTP: RCPT TO before MAIL FROM accepted by server",
                    NULL, i);
            }
        }

        /* SMTP smuggling: newline injection in RCPT TO (CVE-2023-42117: Exim).
         * Only flag when server ACCEPTED (2xx/3xx) the address with CR/LF,
         * proving the server processed — not just received — the smuggling
         * payload.  4xx/5xx rejection = server correctly identified it. */
        if (cur_rcpt || cur_mail) {
            if (smtp_path_has_bare_crlf(req, rlen)) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if ((code == 250 || code == 251) &&
                    !response_has_phrase(response, resp_len, "NUL characters are not allowed") &&
                    !response_has_phrase(response, resp_len, "sender not yet given")) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_SMUGGLING | ORACLE_CAT_INJECTION,
                        ORACLE_EVIDENCE_STRONG,
                        "SMTP: Bare CR/LF inside address path accepted by server",
                        "N/A", i);
                }
            }
        }

        if (cur_auth) has_auth = 1;
        if (cur_mail) has_mail = 1;
        if (cur_rcpt) has_rcpt = 1;
        if (cur_vrfy) has_vrfy = 1;
        if (cur_expn) has_expn = 1;
    }

    /* Open relay detection.  Objective evidence requires:
     *   1. no AUTH in the conversation,
     *   2. RCPT target appears non-local (contains a dotted external domain),
     *   3. RCPT accepted with 250/251,
     *   4. DATA accepted with 354, and
     *   5. message queued with a final 250 OK.
     * Localhost/local-domain delivery is configuration-dependent, not relay. */
    if (has_mail && has_rcpt && !has_auth && resp_len > 0) {
        int rcpt_idx = -1;
        for (int i = req_count - 1; i >= 0; i--) {
            if (request_has_line_command(requests[i], req_lens[i], "RCPT TO:") &&
                smtp_rcpt_domain_is_external(requests[i], req_lens[i])) {
                rcpt_idx = i; break;
            }
        }
        if (rcpt_idx >= 0) {
            int rcpt_code = extract_nth_response_code(response, resp_len, rcpt_idx + resp_offset);
            int data_accepted = 0;
            for (int i = rcpt_idx + 1; i < req_count; i++) {
                if (request_has_line_command(requests[i], req_lens[i], "DATA")) {
                    int data_code = extract_nth_response_code(response, resp_len, i + resp_offset);
                    if (data_code == 354) data_accepted = 1;
                    break;
                }
            }
            if ((rcpt_code == 250 || rcpt_code == 251) && data_accepted &&
                response_has_phrase(response, resp_len, "250 OK id=")) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_AUTH_BYPASS | ORACLE_CAT_AUTHZ_BYPASS,
                    ORACLE_EVIDENCE_STRONG,
                    "SMTP: External mail relay accepted without authentication",
                    "N/A", rcpt_idx);
                /* oracle_auth_bypass_count auto-derived by dispatcher */
            }
        }
    }

    /* VRFY/EXPN is configuration-dependent.  RFC 5321 allows 252 as the
     * intentionally ambiguous "cannot verify" reply, so only a 250 response
     * is a low-severity enumeration observation. */
    if ((has_vrfy || has_expn) && resp_len > 0) {
        for (int i = 0; i < req_count; i++) {
            if (request_has_line_command(requests[i], req_lens[i], "VRFY ") ||
                request_has_line_command(requests[i], req_lens[i], "EXPN ")) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code == 250) {
                    oracle_add_violation(result, ORACLE_SEV_LOW,
                        ORACLE_CAT_INFO_LEAK,
                        ORACLE_EVIDENCE_STRONG,
                        "SMTP: VRFY/EXPN returned positive user information",
                        NULL, i);
                    /* oracle_info_leak_count auto-derived by dispatcher */
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
        int starttls_accepted = 0;
        for (int i = 0; i < req_count; i++) {
            if (request_has_line_command(requests[i], req_lens[i], "STARTTLS")) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code == 220) {
                    starttls_accepted = 1;
                }
            }
            /* Check for cleartext sensitive commands after STARTTLS was accepted */
            if (starttls_accepted &&
                (request_has_line_command(requests[i], req_lens[i], "MAIL FROM:") ||
                 request_has_line_command(requests[i], req_lens[i], "AUTH "))) {
                /* If MAIL FROM/AUTH succeeds without TLS, TLS downgrade is possible */
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code >= 200 && code < 400) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_STATE_VIOLATION,
                        ORACLE_EVIDENCE_STRONG,
                        "SMTP: Cleartext command after STARTTLS (STRIPTLS downgrade risk)",
                        "N/A", i);
                    break;
                }
            }
        }
    }

    /* REMOVED (2026-07-04): Format string specifier detection.
     * Circular detection: fuzzer's binary mutation produces %n/%s/%x/%p
     * bytes; oracle "discovers" these as format string vulnerabilities.
     * CVE-2001-1078 was EFTP (NOT exim benchmark target).  Same pattern
     * as removed FTP format string, QoS=3, BYE, ACK checks. */

    /* Long-line abuse / memory exhaustion (CVE-2001-0894, CVE-2002-0055).
     * Extremely long RCPT TO or MAIL FROM lines. */
    for (int i = 0; i < req_count; i++) {
        if (req_lens[i] > 4096) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_DOS | ORACLE_CAT_RESOURCE_EXHAUST,
                ORACLE_EVIDENCE_HEURISTIC,
                "SMTP: Excessively long command (memory exhaustion risk)",
                "N/A", i);
            /* oracle_dos_count auto-derived by dispatcher */
            break;
        }
    }

    /* Repeated auth failure pattern — potential brute force or resource drain */
    {
        int failed_auth_count = 0;
        for (int i = 0; i < req_count; i++) {
            if (request_has_line_command(requests[i], req_lens[i], "AUTH ")) {
                int code = extract_nth_response_code(response, resp_len, i + resp_offset);
                if (code >= 500 && code <= 535) failed_auth_count++;
            }
        }
        if (failed_auth_count > 10) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_RESOURCE_EXHAUST,
                ORACLE_EVIDENCE_HEURISTIC,
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

    int setup_accepted = 0;
    int setup_request_seen = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        unsigned int cseq = 0;
        int code = -1;
        int has_cseq = extract_rtsp_cseq(req, rlen, &cseq);
        if (has_cseq) {
            code = extract_rtsp_response_code_by_cseq(response, resp_len, cseq);
        }
        int is_setup = request_has_line_command(req, rlen, "SETUP ");
        int is_play = request_has_line_command(req, rlen, "PLAY ");
        int is_record = request_has_line_command(req, rlen, "RECORD ");

        if (is_setup) {
            setup_request_seen = 1;
            if (code_is_2xx(code)) setup_accepted = 1;
        }

        /* State machine: PLAY before SETUP.  If any prior SETUP request exists
         * but response correlation is ambiguous, suppress rather than guessing:
         * a duplicate CSeq can otherwise bind PLAY to an earlier OPTIONS/SETUP
         * response and create false positives. */
        if (is_play && !setup_accepted && !setup_request_seen && has_cseq) {
            if (code >= 200 && code < 300) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_STATE_VIOLATION,
                    ORACLE_EVIDENCE_STRONG,
                    "RTSP: PLAY before SETUP accepted by server",
                    "CVE-2021-38382", i);
                /* oracle_state_violation_count auto-derived by dispatcher */
            }
        }

        /* State machine: RECORD before SETUP — only flag if server accepted */
        if (is_record && !setup_accepted && !setup_request_seen && has_cseq) {
            if (code >= 200 && code < 300) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_STATE_VIOLATION,
                    ORACLE_EVIDENCE_STRONG,
                    "RTSP: RECORD before SETUP accepted by server",
                    NULL, i);
            }
        }

        /* Check for oversized headers (DoS / buffer overflow).
         * Only flag when server ACCEPTED (2xx) the request, proving
         * the oversized header was processed, not just received. */
        const unsigned char *cseq_hdr = ci_memmem(req, rlen, "CSeq:", 5);
        if (cseq_hdr && has_cseq) {
            unsigned int remaining = rlen - (unsigned int)(cseq_hdr - req);
            const unsigned char *eol = memchr(cseq_hdr, '\r', remaining);
            if (eol && (eol - cseq_hdr) > 256) {
                if (code >= 200 && code < 300) {
                    oracle_add_violation(result, ORACLE_SEV_LOW,
                        ORACLE_CAT_DOS,
                        ORACLE_EVIDENCE_STRONG,
                        "RTSP: Oversized CSeq header accepted by server (potential buffer overflow)",
                        "CVE-2019-7314", i);
                }
            }
        }
    }

    /* (PLAY-without-SETUP check is now integrated in the per-request loop above
     * using extract_http_style_nth_response_code for accurate matching) */

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* REMOVED (2026-07-04): Duplicate SETUP for same stream URL.
     * RFC 7826 §13.3.1: "A client that wants to change transport
     * parameters ... MAY do so by sending a SETUP request for a URI
     * for which it already has a session.  The server MUST respond
     * to this request with a 200 (OK) response."
     *
     * Duplicate SETUP is explicitly permitted by the RFC.  A UAF
     * triggered by double-SETUP (CVE-2019-7314, CVE-2023-37117)
     * would be caught by AFL's crash detection — no oracle-level
     * flagging needed for RFC-compliant behavior.  The previous
     * code did NOT verify whether the server assigned a NEW session
     * vs. reused the existing session, making the check unreliable. */
    /* Malformed Transport header (CVE-2019-6256: DoS via malformed transport).
     * Check for Transport header with unusual port ranges or empty fields. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (request_has_line_command(req, rlen, "SETUP ")) {
            const unsigned char *transport = ci_memmem(req, rlen, "Transport:", 10);
            if (transport) {
                unsigned int remaining = rlen - (unsigned int)(transport - req);
                /* Check for explicit client_port=0.  Do not match substrings
                 * such as "inTransport=0", which are not RTSP Transport ports. */
                if (ci_memmem(transport, remaining, "client_port=0", 13)) {
                    unsigned int cseq = 0;
                    int code = -1;
                    const unsigned char *resp_block = NULL;
                    unsigned int resp_block_len = 0;
                    if (extract_rtsp_cseq(req, rlen, &cseq)) {
                        rtsp_response_block_by_cseq_unique(response, resp_len, cseq,
                            &resp_block, &resp_block_len, &code);
                    }
                    if (code >= 200 && code < 300) {
                        if (resp_block &&
                            ci_memmem(resp_block, resp_block_len, "client_port=0", 13)) {
                            oracle_add_violation(result, ORACLE_SEV_LOW,
                                ORACLE_CAT_DOS,
                                ORACLE_EVIDENCE_MODERATE,
                                "RTSP: Transport client_port=0 echoed by server (manual DoS triage)",
                                "N/A", i);
                        }
                    }
                }
                /* Check for excessively long transport header.  A 2xx response
                 * without crash/hang/ASAN evidence is not a confirmed overflow;
                 * keep it as LOW context so it does not pollute vulnerability
                 * counters. */
                const unsigned char *eol = memchr(transport, '\r', remaining);
                if (eol && (eol - transport) > 512) {
                    unsigned int cseq = 0;
                    int code = -1;
                    if (extract_rtsp_cseq(req, rlen, &cseq))
                        code = extract_rtsp_response_code_by_cseq(response, resp_len, cseq);
                    if (code >= 200 && code < 300) {
                        oracle_add_violation(result, ORACLE_SEV_LOW,
                            ORACLE_CAT_DOS,
                            ORACLE_EVIDENCE_MODERATE,
                            "RTSP: Overly long Transport header accepted (manual DoS triage)",
                            "N/A", i);
                    }
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
    (void)requests;
    (void)req_lens;
    (void)req_count;
    (void)response;
    (void)resp_len;

    /* =========================================================================
     * SIP Oracle — Structural Limitations
     * =========================================================================
     *
     * The SIP oracle cannot produce reliable security findings without:
     *
     * 1. SERVER CONFIGURATION KNOWLEDGE: kamailio-basic.cfg explicitly
     *    comments "# To enable authentication execute: - define WITH_AUTH"
     *    The test server has NO auth module loaded.  INVITE/MESSAGE/REGISTER
     *    returning 200 without Authorization is CORRECT behavior when auth
     *    is not configured.  The oracle cannot distinguish "auth bypassed"
     *    from "auth not configured" at the wire level.
     *
     * 2. CSeq-BASED RESPONSE MATCHING: RFC 3261 §8.1.1.9 mandates that
     *    CSeq MUST be echoed in responses.  Without CSeq extraction and
     *    matching, positional response indexing is unreliable because:
     *    (a) SIP forking (RFC 3261 §16.2) produces multiple final responses
     *        for a single INVITE, breaking 1:1 request↔response ordering.
     *    (b) Provisional 1xx responses to INVITE consume response slots
     *        without being the "real" response the caller should check.
     *
     * 3. TARGET-SPECIFIC CVE RELEVANCE: All SIP CVE references in the
     *    original code targeted different products from the Kamailio
     *    benchmark target:
     *      CVE-2020-28361 → no known Kamailio CVE
     *      CVE-2021-37624 → FreeSWITCH, not Kamailio
     *      CVE-2023-28098 → OpenSIPS, not Kamailio
     *      CVE-2008-6573 → Avaya, not Kamailio
     *      CVE-2007-3347 → D-Link/Vonage, not Kamailio
     *      CVE-2023-49323 → no known Kamailio CVE
     *
     * REMOVED CHECKS (2026-07-04):
     *
     * [Circular detection — fuzzer creates condition, oracle "discovers" it]
     *   - BYE before INVITE: fuzzer corrupts "INVITE " → has_invite=0
     *   - ACK without INVITE: RFC 3261 §17.1.1.3 says ACK gets NO response
     *   - Malformed Digest missing nonce: fuzzer removes nonce from header
     *   - SQL injection pattern: fuzzer produces ' OR / UNION SELECT bytes
     *   - INVITE From-header spoofing: fuzzer produces "admin"/"root" strings
     *   - Oversized Authorization header: fuzzer produces long header values
     *   - Excessive Via headers >10: arbitrary threshold, no response verify
     *
     * [Configuration-dependent — cannot work without auth config knowledge]
     *   - INVITE without auth: always fires when auth is not configured
     *   - MESSAGE without auth: same issue
     *
     * Manual oracle_*_count++ calls also removed — oracle_check() dispatcher
     * auto-derives per-category counters from violation category bitmasks,
     * making manual increments both unnecessary and a source of double-counting.
     *
     * If a future SIP oracle is implemented, it MUST:
     *   - Know whether the server has authentication configured
     *   - Use CSeq-based response matching for ALL per-request checks
     *   - Verify response codes (2xx = server accepted) for all findings
     *   - Reference CVEs for the ACTUAL Kamailio target, not other products
     * ========================================================================= */

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
                int has_db_body = ci_memmem(response, resp_len, "avdb", 4) ||
                                  ci_memmem(response, resp_len, "dmap.listing", 12) ||
                                  ci_memmem(response, resp_len, "mlcl", 4);
                if (code == 200 && has_db_body) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_AUTH_BYPASS,
                        ORACLE_EVIDENCE_STRONG,
                        "DAAP: Database access without session-id (auth bypass)",
                        NULL, i);
                    /* oracle_auth_bypass_count auto-derived by dispatcher */
                }
            }
        }

        /* Path traversal in DAAP URLs */
        if (ci_memmem(req, rlen, "../", 3) ||
            ci_memmem(req, rlen, "%2e%2e", 6)) {
            if (resp_len > 0) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                int leaked_sensitive =
                    ci_memmem(response, resp_len, "root:x:0:0:", 11) ||
                    ci_memmem(response, resp_len, "PRIVATE KEY-----", 16) ||
                    ci_memmem(response, resp_len, "BEGIN OPENSSH PRIVATE KEY", 25);
                if (code == 200 && leaked_sensitive) {
                    oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                        ORACLE_CAT_PATH_TRAVERSAL | ORACLE_CAT_INFO_LEAK,
                        ORACLE_EVIDENCE_STRONG,
                        "DAAP: Path traversal leaked sensitive file content",
                        NULL, i);
            /* oracle_path_traversal_count auto-derived by dispatcher */
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
                    ORACLE_EVIDENCE_WEAK,
                    "DAAP: Server-info response contains sensitive fields",
                    NULL, -1);
                /* oracle_info_leak_count auto-derived by dispatcher */
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

        /* Path traversal: a 200 response to "../" is not enough evidence.
         * Servers may normalize the path inside document-root.  Only report
         * when sensitive file CONTENT appears in the response. */
        if (ci_memmem(req, rlen, "/../", 4) ||
            ci_memmem(req, rlen, "/..\\", 4) ||
            ci_memmem(req, rlen, "%2e%2e%2f", 9) ||
            ci_memmem(req, rlen, "..%252f", 7) ||
            ci_memmem(req, rlen, "%c0%ae", 6)) {
            if (resp_len > 0) {
                int code = extract_http_style_nth_response_code(response, resp_len, i);
                int leaked_sensitive =
                    ci_memmem(response, resp_len, "root:x:0:0:", 11) ||
                    ci_memmem(response, resp_len, "PRIVATE KEY-----", 16) ||
                    ci_memmem(response, resp_len, "BEGIN OPENSSH PRIVATE KEY", 25);
                if (code == 200 && leaked_sensitive) {
                    oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                        ORACLE_CAT_PATH_TRAVERSAL | ORACLE_CAT_INFO_LEAK,
                        ORACLE_EVIDENCE_STRONG,
                        "HTTP: Path traversal leaked sensitive file content",
                        NULL, i);
                }
            }
        }

        /* Request smuggling: both Content-Length and Transfer-Encoding.
         * RFC 7230 §3.3.3: MUST NOT include both.  Only flag when server
         * ACCEPTED (2xx) the malformed request, proving the server
         * processed — not just received — the ambiguous framing. */
        int has_cl = count_header_lines(req, rlen, "Content-Length") > 0;
        int has_te = count_header_lines(req, rlen, "Transfer-Encoding") > 0;
        if (has_cl && has_te) {
            int code = extract_http_style_nth_response_code(response, resp_len, i);
            if (code >= 200 && code < 300 &&
                !response_has_phrase(response, resp_len, "400 Bad Request")) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_SMUGGLING,
                    ORACLE_EVIDENCE_MODERATE,
                    "HTTP: Both Content-Length and Transfer-Encoding accepted (smuggling risk)",
                    NULL, i);
            }
        }

        /* Multiple Content-Length headers */
        int cl_count = count_header_lines(req, rlen, "Content-Length");
        if (cl_count > 1) {
            int code = extract_http_style_nth_response_code(response, resp_len, i);
            if (code >= 200 && code < 300 &&
                !response_has_phrase(response, resp_len, "400 Bad Request")) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_SMUGGLING,
                    ORACLE_EVIDENCE_MODERATE,
                    "HTTP: Multiple Content-Length headers accepted by server (CL desync)",
                    NULL, i);
            }
        }
    }

    /* Response checks */
    if (resp_len > 0) {
        /* Info leak: sensitive file content */
        if ((ci_memmem(response, resp_len, "root:x:0:0:", 11) &&
             !request_contains_any(requests, req_lens, req_count, "root:x:0:0:")) ||
            (ci_memmem(response, resp_len, "/etc/passwd", 11) &&
             !request_contains_any(requests, req_lens, req_count, "/etc/passwd"))) {
            oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                ORACLE_CAT_INFO_LEAK | ORACLE_CAT_PATH_TRAVERSAL,
                ORACLE_EVIDENCE_WEAK,
                "HTTP: /etc/passwd content leaked in response",
                NULL, -1);
            /* oracle_info_leak_count auto-derived by dispatcher */
        }

        /* Info leak: directory listing */
        if (ci_memmem(response, resp_len, "Index of /", 10) ||
            ci_memmem(response, resp_len, "Directory listing", 17)) {
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_INFO_LEAK,
                ORACLE_EVIDENCE_WEAK,
                "HTTP: Directory listing exposed",
                NULL, -1);
        }

        /* REMOVED (2026-07-06): Verbose Server header.
         * A Server header is normal HTTP behavior and version fingerprinting
         * is a configuration observation, not an oracle-level vulnerability.
         * Counting it on every response polluted fuzzer_stats. */
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
                int leaked_sensitive =
                    ci_memmem(response, resp_len, "root:x:0:0:", 11) ||
                    ci_memmem(response, resp_len, "PRIVATE KEY-----", 16) ||
                    ci_memmem(response, resp_len, "BEGIN OPENSSH PRIVATE KEY", 25);
                if (code == 200 && leaked_sensitive) {
                    oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                        ORACLE_CAT_PATH_TRAVERSAL | ORACLE_CAT_INFO_LEAK,
                        ORACLE_EVIDENCE_STRONG,
                        "HTTP: Double-encoded path traversal leaked sensitive content",
                        "N/A", i);
            /* oracle_path_traversal_count auto-derived by dispatcher */
                }
            }
        }
    }

    /* Response splitting / HTTP header injection.
     * CRLF followed by HTTP/1.x in request body can split the response
     * into multiple HTTP messages.  Only flag when server ACCEPTED (2xx)
     * the request containing the injection payload — a 4xx rejection
     * proves the server correctly identified it as malformed. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        const unsigned char *crlf_http = ci_memmem(req, rlen, "\r\nHTTP/1.", 9);
        if (crlf_http) {
            int code = extract_http_style_nth_response_code(response, resp_len, i);
            if (code >= 200 && code < 300 &&
                !response_has_phrase(response, resp_len, "400 Bad Request")) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_SMUGGLING | ORACLE_CAT_INJECTION,
                    ORACLE_EVIDENCE_MODERATE,
                    "HTTP: CRLF injection with embedded HTTP response accepted by server",
                    NULL, i);
            }
        }
    }

    /* Chunk extension abuse — chunked transfer encoding with oversized
     * chunk-size values (>16 hex digits exceeds uint64 range).
     * Only flag when server ACCEPTED (2xx) the request with oversized
     * chunk, proving the parser actually processed the overflow-inducing
     * value rather than rejecting it at the framing level. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        if (ci_memmem(req, rlen, "Transfer-Encoding: chunked", 26) ||
            ci_memmem(req, rlen, "chunked", 7)) {
            const unsigned char *body = ci_memmem(req, rlen, "\r\n\r\n", 4);
            if (body) {
                unsigned int body_off = (unsigned int)(body - req) + 4;
                if (body_off + 8 < rlen) {
                    int hex_count = 0;
                    for (unsigned int j = body_off; j < body_off + 20 && j < rlen; j++) {
                        if (isxdigit(req[j])) hex_count++;
                        else if (req[j] == '\r') break;
                    }
                    if (hex_count > 16) {
                        int code = extract_http_style_nth_response_code(response, resp_len, i);
                        if (code >= 200 && code < 300 &&
                            !response_has_phrase(response, resp_len, "400 Bad Request")) {
                            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                                ORACLE_CAT_DOS,
                                ORACLE_EVIDENCE_MODERATE,
                                "HTTP: Oversized chunk-size value accepted (potential BO in chunk parser)",
                                NULL, i);
                        }
                    }
                }
            }
        }
    }

    /* REMOVED (2026-07-06): %00 / "..;" auth-bypass heuristic.
     * Without a known protected resource baseline and an expected 401/403,
     * a 200 response to these bytes is not evidence of auth bypass. */

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

    /* Pre-scan response for CONNACK: if broker sent any CONNACK, a CONNECT
     * was processed — retroactively acknowledge has_connect BEFORE the
     * per-request loop, so PUBLISH/SUBSCRIBE after CONNECT don't false-trigger
     * auth-bypass (critical for anonymous fuzzing setups where fuzzed CONNECT
     * bytes fail the magic-byte check). */
    if (resp_len >= 4) {
        uint8_t first_resp = (response[0] >> 4) & 0x0F;
        if (first_resp == 2) { /* CONNACK */
            has_connect = 1;
        }
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
                mqtt_connect_info_t ci;
                if (mqtt_parse_connect(req, rlen, &ci)) {
                    has_connect = 1;
                    /* Empty ClientID is legal with clean session/start enabled.
                     * The clean_session=0 case is handled later as INFO only. */
                }
                break;
            }

            case 3:  /* PUBLISH */
            {
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
                            ORACLE_EVIDENCE_STRONG,
                            "MQTT: PUBLISH without CONNECT accepted by broker",
                            "N/A", i);
                        /* oracle_auth_bypass_count auto-derived by dispatcher */
                    }
                }
                /* REMOVED (2026-07-04): PUBLISH to $SYS topic check.
                 * Same circular detection pattern as Will $SYS:
                 * fuzzer puts $SYS in topic → oracle discovers.
                 * Mosquitto acl__check_dollar() blocks $SYS writes. */
                /* REMOVED (2026-07-04): Retained message flag check.
                 * Retained messages are a STANDARD MQTT feature (§3.3.2.3).
                 * Flagging every retained PUBLISH as "exhaustion risk" is
                 * circular detection — the fuzzer sets the RETAIN bit
                 * through mutation, oracle "discovers" it. */
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
                            ORACLE_EVIDENCE_STRONG,
                            "MQTT: SUBSCRIBE without CONNECT accepted by broker",
                            "N/A", i);
                        /* oracle_auth_bypass_count auto-derived by dispatcher */
                    }
                }
                /* REMOVED (2026-07-04): $SYS wildcard subscription check.
                 * Circular detection: fuzzer puts $SYS bytes in
                 * SUBSCRIBE topic filters via random mutation;
                 * oracle "discovers" them.  Mosquitto $SYS topics
                 * are read-only per acl__check_dollar(). */

            /* REMOVED (2026-07-04): UNSUBSCRIBE/PINGREQ without CONNECT.
             * Circular detection: has_connect flag depends on CONNECT
             * packet header not being corrupted by fuzzer.  When fuzzer
             * bit-flips the header byte (0x10 → 0x00), has_connect=0
             * and ALL subsequent operations are falsely flagged.
             * Same pattern as removed QoS=3 check. */
            case 10: /* UNSUBSCRIBE */
                break;

            case 12: /* PINGREQ */
                break;

            case 14: /* DISCONNECT */
                break;

            default:
                break;
        }
    }

    /* ── Optimized patterns from 协议漏洞汇总.xlsx ── */

    /* Malformed SUBSCRIBE with zero topic length (CVE-2019-5432: mqtt-packet
     * malformed SUBSCRIBE causes broker crash).
     * MQTT §3.8.3-1: topic filter length MUST be >= 1.
     *
     * FIXED (2026-07-04): Was purely content-based with no response-side
     * verification.  The fuzzer produces a SUBSCRIBE with topic_len==0
     * through mutation; the oracle then "discovers" this self-inflicted
     * condition as a vulnerability.  Circular detection:
     *   1. Fuzzer mutates topic length field → topic_len==0
     *   2. Oracle parses mutated field → flags as "broker crash risk"
     *   3. No evidence broker processed the malformed SUBSCRIBE
     *   4. No crash detected (AFL unique_crashes=0 across all runs)
     *
     * Now requires TWO-LAYER response verification:
     *   Layer 1: CONNACK with return code 0x00 (broker accepted CONNECT)
     *   Layer 2: SUBACK with matching packet ID (broker processed THIS
     *            specific SUBSCRIBE, confirming the zero-length filter
     *            was actually handled by the broker)
     * Without both layers, the check is suppressed — the fuzzer's
     * mutation caused the condition and the broker never processed it.
     *
     * Also removed manual oracle_dos_count++ — oracle_check() dispatcher
     * auto-derives per-category counters from category bitmasks. */
    {
        /* Pre-scan: verify CONNACK success (return code 0x00).
         * Without it, broker rejected the connection — all SUBSCRIBE
         * checks are moot. */
        int connack_success = mqtt_response_has_connack_success(response, resp_len);

        if (connack_success) {
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
                        unsigned int pkt_end = hdr_size + (unsigned int)rem_len;
                        if (pkt_end > rlen) continue;
                        /* Extract packet identifier for SUBACK matching */
                        uint16_t pkt_id = 0;
                        if (hdr_size + 2 <= pkt_end) {
                            pkt_id = (req[hdr_size] << 8) | req[hdr_size + 1];
                        }
                        unsigned int payload_off = hdr_size + 2;
                        unsigned int scan = payload_off;
                        while (scan + 2 <= pkt_end) {
                            uint16_t topic_len = (req[scan] << 8) | req[scan + 1];
                            if (topic_len == 0) {
                                /* Verify: did broker send SUBACK for this packet?
                                 * Scan response for SUBACK (type 9) with
                                 * matching packet ID.  Without both CONNACK
                                 * success AND matching SUBACK, the broker
                                 * never processed the zero-length filter. */
                                int suback_confirmed = 0;
                                for (unsigned int rs = 0; rs + 4 < resp_len; ) {
                                    uint8_t rt = (response[rs] >> 4) & 0x0F;
                                    if (rt == 9) { /* SUBACK */
                                        unsigned int sb = 0;
                                        int srl = mqtt_decode_remaining_length(
                                            response + rs + 1, resp_len - rs - 1, &sb);
                                        if (srl >= 2 && rs + 1 + sb + 2 <= resp_len) {
                                            uint16_t spid = (response[rs + 1 + sb] << 8)
                                                          | response[rs + 1 + sb + 1];
                                            if (spid == pkt_id) {
                                                suback_confirmed = 1; break;
                                            }
                                        }
                                    }
                                    unsigned int srb = 0;
                                    int sr = mqtt_decode_remaining_length(
                                        response + rs + 1, resp_len - rs - 1, &srb);
                                    if (sr < 0) break;
                                    rs += 1 + srb + sr;
                                }
                                if (suback_confirmed) {
                                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                                        ORACLE_CAT_DOS,
                                        ORACLE_EVIDENCE_STRONG,
                                        "MQTT: SUBSCRIBE with zero-length topic "
                                        "filter processed by broker",
                                        "N/A", i);
                                    break;
                                }
                                /* No matching SUBACK: broker did not process
                                 * this SUBSCRIBE.  The zero-length filter was
                                 * a fuzzer artifact, not a security finding.
                                 * Suppress entirely — no INFO fallback. */
                                break;
                            }
                            if (topic_len > pkt_end - scan - 2) break;
                            scan += 2 + topic_len + 1;
                            if (scan > pkt_end) break;
                        }
                    }
                }
            }
        }
    }

    /* MQTT v5 user-property abuse (CVE-2021-41039 class).
     * Count PROP_USER (0x26) only inside the MQTT v5 CONNECT properties
     * section.  MQTT v5 properties are in the CONNECT variable header after
     * keepalive and before payload; scanning payload/random bytes is noise. */
    {
        int user_prop_count = 0;
        for (int i = 0; i < req_count; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            mqtt_connect_info_t ci;
            if (mqtt_parse_connect(req, rlen, &ci) && ci.proto_level == 5) {
                unsigned int prop_len_bytes = 0;
                unsigned int prop_len_off = ci.flags_off + 3;
                int prop_len = mqtt_decode_remaining_length(req + prop_len_off,
                    ci.pkt_end - prop_len_off, &prop_len_bytes);
                if (prop_len < 0) continue;
                unsigned int prop_start = prop_len_off + prop_len_bytes;
                unsigned int prop_end = prop_start + (unsigned int)prop_len;
                if (prop_end > ci.pkt_end) continue;
                for (unsigned int j = prop_start; j < prop_end; j++) {
                    if (req[j] == 0x26) user_prop_count++;
                }
            }
        }
        if (user_prop_count > 50 &&
            mqtt_response_has_connack_success(response, resp_len)) {
            oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                ORACLE_CAT_DOS | ORACLE_CAT_RESOURCE_EXHAUST,
                ORACLE_EVIDENCE_MODERATE,
                "MQTT: Excessive v5 user-properties accepted in CONNECT (CPU exhaustion risk)",
                "CVE-2021-41039", -1);
        }
    }

    /* Session takeover via empty client ID with clean_session=0
     * (CVE-2014-6116: WebSphere MQ auth bypass via session reuse).
     * Check for CONNECT with clean_session=0 and empty client ID.
     * This allows one client to hijack another's session. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        mqtt_connect_info_t ci;
        if (mqtt_parse_connect(req, rlen, &ci)) {
            int clean_session = (ci.connect_flags >> 1) & 0x01;
            if (ci.payload_off + 2 <= ci.pkt_end) {
                uint16_t cid_len = (req[ci.payload_off] << 8) | req[ci.payload_off + 1];
                if (!clean_session && cid_len == 0) {
                    oracle_add_violation(result, ORACLE_SEV_INFO,
                        ORACLE_CAT_ISOLATION,
                        ORACLE_EVIDENCE_HEURISTIC,
                        "MQTT: Empty ClientID with clean_session=0 (configuration observation, requires broker-level attack chain)",
                        "N/A", i);
                }
            }
        }
    }

    /* REMOVED (2026-07-04): Duplicate packet identifier detection.
     * MQTT §2.2.1 requires packet identifiers to be unique "in a given
     * direction" for QoS>0, but allows reuse after PUBACK/PUBCOMP/PUBREL
     * (QoS handshake completion).  The fuzzer produces repeated PUBLISH/
     * SUBSCRIBE messages with naturally repeating packet IDs through
     * random mutation — oracle "discovers" these as replay attacks.
     * Circular detection.  Additionally, PUBLISH and SUBSCRIBE packet
     * ID spaces are independent per MQTT spec. */

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
        int reportable_violations = 0;
        for (int i = 0; i < result->violation_count; i++) {
            if (result->violations[i].severity < ORACLE_SEV_MEDIUM)
                continue;
            reportable_violations++;
            if (oracle_is_new_violation(result->violations[i].pattern_hash)) {
                oracle_unique_violations++;
            }
            /* Auto-derive per-category counters from violation bitmasks.
             * AUTHZ_BYPASS grouped with AUTH_BYPASS; RESOURCE_EXHAUST with DOS. */
            uint16_t cat = result->violations[i].category;
            if (cat & (ORACLE_CAT_AUTH_BYPASS | ORACLE_CAT_AUTHZ_BYPASS))
                oracle_auth_bypass_count++;
            if (cat & ORACLE_CAT_STATE_VIOLATION)
                oracle_state_violation_count++;
            if (cat & ORACLE_CAT_INFO_LEAK)
                oracle_info_leak_count++;
            if (cat & ORACLE_CAT_PATH_TRAVERSAL)
                oracle_path_traversal_count++;
            if (cat & (ORACLE_CAT_DOS | ORACLE_CAT_RESOURCE_EXHAUST))
                oracle_dos_count++;
        }
        oracle_total_violations += reportable_violations;
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
             dir_path, (unsigned long long)oracle_unique_violations,
             result->max_severity, result->categories_hit);

    FILE *fp = fopen(fn, "w");
    if (!fp) return;

    fprintf(fp, "=== PROTOCOL ORACLE DEVIATION REPORT ===\n");
    fprintf(fp, "NOTE: This is a candidate for manual triage, NOT a confirmed finding.\n");
    fprintf(fp, "The oracle detects protocol-level behavioural deviations;\n");
    fprintf(fp, "exploitability depends on server configuration and deployment context.\n");
    fprintf(fp, "Time: %ld\n", (long)time(NULL));
    fprintf(fp, "Violations: %d\n", result->violation_count);
    fprintf(fp, "Max Severity: %d\n", result->max_severity);
    fprintf(fp, "Categories: 0x%04x\n\n", result->categories_hit);

    for (int i = 0; i < result->violation_count; i++) {
        const oracle_violation_t *v = &result->violations[i];
        fprintf(fp, "--- Violation %d ---\n", i + 1);
        fprintf(fp, "Severity: %d\n", v->severity);
        fprintf(fp, "Category: 0x%04x\n", v->category);
        fprintf(fp, "Evidence Quality: %d (%s)\n", v->evidence_quality,
            v->evidence_quality == ORACLE_EVIDENCE_STRONG ? "STRONG — precise response-code match" :
            v->evidence_quality == ORACLE_EVIDENCE_MODERATE ? "MODERATE — response-code range + position verified" :
            v->evidence_quality == ORACLE_EVIDENCE_WEAK ? "WEAK — response content pattern, no per-request mapping" :
            "HEURISTIC — aggregate threshold, weakest signal");
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
