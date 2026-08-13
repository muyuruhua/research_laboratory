/*
 * LoopFuzz: Protocol Behavioral Deviation Oracle
 * ===================================================
 *
 * Observes request-response traffic and flags protocol-level behavioural
 * deviation candidates from RFC-mandated behaviour and target-relevant
 * attack patterns.
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
 *                         saved under replayable-violations, including
 *                         complete binary request/response sidecars
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
#include <limits.h>

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
static uint64_t oracle_saved_reports = 0;

/* Dedup bitmap */
#define ORACLE_DEDUP_SIZE 4096
static uint32_t oracle_dedup_bitmap[ORACLE_DEDUP_SIZE];
static int oracle_initialized = 0;
static char oracle_stats_buf[512];

/* Protocol state tracker (reset per execution) */
static protocol_state_t proto_state;

/* ============================================
 * Per-Execution Indexes (single-pass optimization)
 * ============================================
 * The original precise oracle re-scans the request regions and the
 * response buffer from scratch for every command (text_response_code_
 * for_command calls text_response_slot_count_before_pos which re-tokenizes
 * ALL prior regions, plus extract_nth_response_code which re-scans the
 * whole response).  That is O(N*M) per oracle_check call and the dominant
 * cause of the ~2.4x per-exec overhead.  Instead, we build flat indexes
 * ONCE per oracle_check execution and make the hot helpers consult them
 * (O(1) / O(slots)).  The index is built with the exact same tokenizer /
 * code extractors, so results are bit-identical to the old multi-pass scan.
 */
#define ORACLE_CMD_CAP    256   /* req_count<=64 * ~4 cmd/region worst case */
#define ORACLE_RESP_CAP   512
#define ORACLE_HTTP_BLOCKS 128
#define ORACLE_RTSP_BLOCKS 128
#define ORACLE_MQTT_PKTS   64

typedef struct {
    int           region_idx;  /* which request region the slot is in   */
    unsigned int  slot_pos;    /* byte offset of the line in the region */
    const char   *cmd;         /* command name if it is a command slot, else NULL */
    int           cum_slot;    /* global slot ordinal (0-based, before resp_offset) */
} oracle_slot_t;

static oracle_slot_t    g_slots[ORACLE_CMD_CAP];
static int              g_slot_count = 0;
static int              g_resp_codes[ORACLE_RESP_CAP];
static int              g_resp_code_count = 0;
static int              g_text_index_valid = 0;

typedef struct {
    unsigned int offset;       /* offset of the response block in response */
    unsigned int len;
    int          code;
} oracle_http_block_t;
static oracle_http_block_t g_http_blocks[ORACLE_HTTP_BLOCKS];
static int                 g_http_block_count = 0;
static int                 g_http_index_valid = 0;

typedef struct {
    unsigned int offset;
    unsigned int len;
    int          code;
    unsigned int cseq;
    int          has_cseq;
} oracle_rtsp_block_t;
static oracle_rtsp_block_t g_rtsp_blocks[ORACLE_RTSP_BLOCKS];
static int                 g_rtsp_block_count = 0;
static int                 g_rtsp_index_valid = 0;

typedef struct {
    unsigned int offset;       /* offset of the packet's fixed header */
    uint8_t      first_byte;
    uint8_t      pkt_type;     /* high nibble */
    int          rem_len;
} oracle_mqtt_pkt_t;
static oracle_mqtt_pkt_t g_mqtt_pkts[ORACLE_MQTT_PKTS];
static int               g_mqtt_pkt_count = 0;
static int               g_mqtt_index_valid = 0;

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

            char sep = (i + 3 < len) ? resp[i + 3] : '\0';

            if (in_multiline) {
                /* RFC-style multi-line replies (FTP/SMTP) are a single
                 * response slot.  The opening "250-" / "211-" line has
                 * already been counted; continuations and the terminating
                 * "250 " / "211 " line must not shift later mappings. */
                if (code == multiline_code && sep == ' ')
                    in_multiline = 0;
            } else if (in_data_xfer) {
                /* This is the completion response (2xx) of a data transfer.
                 * It belongs to the same request as the preceding 1xx.
                 * Consume it without incrementing count. */
                if (code >= 200 && code <= 599)
                    in_data_xfer = 0;
                /* Don't increment count — paired with the 1xx above */
            } else {
                /* Normal single-line response */
                if (count == n) return code;
                count++;
                if (sep == '-') {
                    in_multiline = 1;
                    multiline_code = code;
                }
                /* If this is a 1xx preliminary (data transfer start),
                 * the NEXT final response is its completion partner. */
                else if (code >= 100 && code < 200) {
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

static int http_style_response_code_at(const unsigned char *resp,
                                       unsigned int len,
                                       unsigned int off,
                                       int *code_out) {
    if (!resp || off + 8 >= len) return 0;
    if (!(off == 0 || resp[off - 1] == '\n')) return 0;

    if (!((off + 5 <= len && strncmp((const char *)resp + off, "HTTP/", 5) == 0) ||
          (off + 5 <= len && strncmp((const char *)resp + off, "RTSP/", 5) == 0) ||
          (off + 4 <= len && strncmp((const char *)resp + off, "SIP/", 4) == 0))) {
        return 0;
    }

    unsigned int j = off;
    while (j < len && resp[j] != ' ' && resp[j] != '\r' && resp[j] != '\n') j++;
    if (j >= len || resp[j] != ' ') return 0;
    j++;

    if (j + 2 >= len ||
        resp[j] < '1' || resp[j] > '5' ||
        resp[j + 1] < '0' || resp[j + 1] > '9' ||
        resp[j + 2] < '0' || resp[j + 2] > '9') {
        return 0;
    }

    if (code_out)
        *code_out = (resp[j] - '0') * 100 +
                    (resp[j + 1] - '0') * 10 +
                    (resp[j + 2] - '0');
    return 1;
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
    while (i < len) {
        int code = -1;
        if (http_style_response_code_at(resp, len, i, &code)) {
            if (count == n) return code;
            count++;
        }
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }
    return -1;
}

/* Slow reference: full response scan to find the Nth HTTP-style block.
 * Equivalent to the indexed fast path below. */
static int extract_http_style_nth_response_block_slow(const unsigned char *resp,
                                                      unsigned int len,
                                                      int n,
                                                      const unsigned char **block,
                                                      unsigned int *block_len,
                                                      int *code_out) {
    if (!resp || n < 0) return 0;

    int count = 0;
    unsigned int i = 0;
    while (i < len) {
        int code = -1;
        if (http_style_response_code_at(resp, len, i, &code)) {
            if (count == n) {
                unsigned int start = i;
                unsigned int end = len;
                unsigned int j = i;

                while (j < len && resp[j] != '\n') j++;
                if (j < len) j++;

                while (j < len) {
                    int next_code = -1;
                    if (http_style_response_code_at(resp, len, j, &next_code)) {
                        end = j;
                        break;
                    }
                    while (j < len && resp[j] != '\n') j++;
                    if (j < len) j++;
                }

                if (block) *block = resp + start;
                if (block_len) *block_len = end - start;
                if (code_out) *code_out = code;
                return 1;
            }
            count++;
        }

        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }

    return 0;
}

/* Fast path: consult the pre-built HTTP response-block index (one pass over
 * the response instead of one pass per request).  build_http_block_index()
 * records the same blocks that extract_http_style_nth_response_block_slow
 * would find. */
static int extract_http_style_nth_response_block(const unsigned char *resp,
                                                 unsigned int len,
                                                 int n,
                                                 const unsigned char **block,
                                                 unsigned int *block_len,
                                                 int *code_out) {
    (void)len;
    if (!resp || n < 0) return 0;

    if (g_http_index_valid) {
        if (n >= g_http_block_count) return 0;
        if (block) *block = resp + g_http_blocks[n].offset;
        if (block_len) *block_len = g_http_blocks[n].len;
        if (code_out) *code_out = g_http_blocks[n].code;
#ifdef ORACLE_SELF_TEST
        {
            const unsigned char *ref_block = NULL;
            unsigned int ref_len = 0;
            int ref_code = -1;
            int ref_ok = extract_http_style_nth_response_block_slow(resp, len, n,
                &ref_block, &ref_len, &ref_code);
            if (ref_ok != 1 || ref_code != g_http_blocks[n].code ||
                ref_len != g_http_blocks[n].len) {
                fprintf(stderr, "[oracle-selftest] http block mismatch n=%d "
                        "ref_code=%d idx_code=%d ref_len=%u idx_len=%u\n",
                        n, ref_code, g_http_blocks[n].code, ref_len,
                        g_http_blocks[n].len);
                abort();
            }
        }
#endif
        return 1;
    }
    return extract_http_style_nth_response_block_slow(resp, len, n, block, block_len, code_out);
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

static int text_is_line_break(unsigned char c) {
    return c == '\r' || c == '\n';
}

static unsigned int text_skip_line_breaks(const unsigned char *buf,
                                          unsigned int len,
                                          unsigned int pos) {
    while (pos < len && text_is_line_break(buf[pos])) pos++;
    return pos;
}

static unsigned int text_line_raw_end(const unsigned char *buf,
                                      unsigned int len,
                                      unsigned int pos) {
    while (pos < len && !text_is_line_break(buf[pos])) pos++;
    return pos;
}

static unsigned int text_next_line_start(const unsigned char *buf,
                                         unsigned int len,
                                         unsigned int raw_end) {
    if (raw_end < len && text_is_line_break(buf[raw_end])) {
        unsigned char first = buf[raw_end++];
        if (raw_end < len && text_is_line_break(buf[raw_end]) &&
            buf[raw_end] != first) {
            raw_end++;
        }
    }
    return raw_end;
}

static unsigned int text_skip_leading_controls(const unsigned char *buf,
                                               unsigned int len,
                                               unsigned int pos) {
    while (pos < len && buf[pos] < 0x20 &&
           buf[pos] != '\t' && !text_is_line_break(buf[pos])) {
        pos++;
    }
    return pos;
}

/* AFLNet can put multiple text-protocol commands in one request region.  These
 * helpers inspect command lines, not only the first bytes of the region. */
static int request_line_command_pos(const unsigned char *req, unsigned int len,
                                    const char *cmd, unsigned int *pos) {
    unsigned int i = 0;
    while (i < len) {
        i = text_skip_line_breaks(req, len, i);
        unsigned int line_start = i;
        if (command_boundary_ok(req, len, line_start, cmd)) {
            if (pos) *pos = line_start;
            return 1;
        }
        i = text_next_line_start(req, len, text_line_raw_end(req, len, i));
    }
    return 0;
}

static int request_has_line_command(const unsigned char *req, unsigned int len,
                                    const char *cmd) {
    return request_line_command_pos(req, len, cmd, NULL);
}

typedef enum {
    TEXT_PROTO_FTP = 1,
    TEXT_PROTO_SMTP = 2
} text_protocol_t;

/* Which text protocol the current execution's slot index was built for. */
static text_protocol_t g_text_index_proto = TEXT_PROTO_FTP;

static const char *ftp_command_at(const unsigned char *buf, unsigned int len,
                                  unsigned int off) {
    static const char *cmds[] = {
        "USER ", "PASS ", "ACCT ", "CWD ",  "SMNT ", "PORT ",
        "TYPE ", "STRU ", "MODE ", "RETR ", "STOR ", "STOU ",
        "APPE ", "ALLO ", "REST ", "RNFR ", "RNTO ", "DELE ",
        "RMD ",  "MKD ",  "SITE ", "OPTS ", "AUTH ", "PBSZ ",
        "PROT ", "MLSD ", "MLST ", "EPRT ", "EPSV",  "CDUP",
        "QUIT",  "REIN",  "PASV",  "ABOR",  "PWD",   "XPWD",
        "LIST",  "NLST",  "SYST",  "STAT",  "HELP",  "NOOP",
        "FEAT",  "USER",  "PASS",  NULL
    };

    for (int i = 0; cmds[i]; i++) {
        if (command_boundary_ok(buf, len, off, cmds[i])) return cmds[i];
    }
    return NULL;
}

static const char *smtp_command_at(const unsigned char *buf, unsigned int len,
                                   unsigned int off) {
    static const char *cmds[] = {
        "MAIL FROM:", "RCPT TO:", "STARTTLS", "HELO ", "EHLO ",
        "AUTH ",     "VRFY ",    "EXPN ",    "BDAT ", "ETRN ",
        "ATRN ",     "DATA",     "RSET",     "HELP",  "NOOP",
        "QUIT",      "HELO",     "EHLO",     "AUTH",  "VRFY",
        "EXPN",      NULL
    };

    for (int i = 0; cmds[i]; i++) {
        if (command_boundary_ok(buf, len, off, cmds[i])) return cmds[i];
    }
    return NULL;
}

static const char *text_protocol_command_at(const unsigned char *buf,
                                            unsigned int len,
                                            unsigned int off,
                                            text_protocol_t proto) {
    if (proto == TEXT_PROTO_FTP) return ftp_command_at(buf, len, off);
    if (proto == TEXT_PROTO_SMTP) return smtp_command_at(buf, len, off);
    return NULL;
}

static unsigned int text_line_content_end(const unsigned char *buf,
                                          unsigned int line_start,
                                          unsigned int raw_end) {
    unsigned int end = raw_end;
    while (end > line_start &&
           (buf[end - 1] == '\r' || buf[end - 1] == '\n')) {
        end--;
    }
    return end;
}

static int smtp_line_is_exact_data(const unsigned char *buf,
                                   unsigned int line_start,
                                   unsigned int content_end) {
    return content_end - line_start == 4 &&
           strncasecmp((const char *)buf + line_start, "DATA", 4) == 0;
}

static int smtp_line_is_dot_terminator(const unsigned char *buf,
                                       unsigned int line_start,
                                       unsigned int content_end) {
    return content_end - line_start == 1 && buf[line_start] == '.';
}

/* FTP and SMTP servers answer malformed/unknown command lines too (usually
 * 500/501/503).  Those lines must consume response slots; otherwise the oracle
 * can bind a later success code to the wrong command and manufacture a
 * vulnerability candidate.  For SMTP DATA bodies, message-body lines are not
 * command slots; the terminating "." is a slot for the final queue response. */
static int text_protocol_next_slot(const unsigned char *buf,
                                   unsigned int len,
                                   text_protocol_t proto,
                                   unsigned int *cursor,
                                   unsigned int *pos,
                                   const char **cmd) {
    unsigned int min_pos = cursor ? *cursor : 0;
    unsigned int i = 0;
    int smtp_in_data_body = 0;

    while (i < len) {
        i = text_skip_line_breaks(buf, len, i);
        if (i >= len) break;

        unsigned int line_start = i;
        unsigned int raw_end = text_line_raw_end(buf, len, i);
        unsigned int next = text_next_line_start(buf, len, raw_end);
        unsigned int content_end = text_line_content_end(buf, line_start, raw_end);

        if (proto == TEXT_PROTO_SMTP && smtp_in_data_body) {
            int is_dot = smtp_line_is_dot_terminator(buf, line_start, content_end);
            if (is_dot) {
                if (line_start >= min_pos) {
                    if (cursor) *cursor = next;
                    if (pos) *pos = line_start;
                    if (cmd) *cmd = NULL;
                    return 1;
                }
                smtp_in_data_body = 0;
            }
            i = next;
            continue;
        }

        const char *found = text_protocol_command_at(buf, len, line_start, proto);
        if (line_start >= min_pos) {
            if (cursor) *cursor = next;
            if (pos) *pos = line_start;
            if (cmd) *cmd = found;
            return 1;
        }

        if (proto == TEXT_PROTO_SMTP &&
            smtp_line_is_exact_data(buf, line_start, content_end)) {
            smtp_in_data_body = 1;
        }
        i = next;
    }

    if (cursor) *cursor = len;
    return 0;
}

static int text_protocol_next_command(const unsigned char *buf,
                                      unsigned int len,
                                      text_protocol_t proto,
                                      unsigned int *cursor,
                                      unsigned int *pos,
                                      const char **cmd) {
    unsigned int slot_pos = 0;
    const char *slot_cmd = NULL;

    while (text_protocol_next_slot(buf, len, proto, cursor,
                                   &slot_pos, &slot_cmd)) {
        if (slot_cmd) {
            if (pos) *pos = slot_pos;
            if (cmd) *cmd = slot_cmd;
            return 1;
        }
    }
    return 0;
}

static int text_protocol_response_slot_count(const unsigned char *buf,
                                             unsigned int len,
                                             text_protocol_t proto) {
    unsigned int cursor = 0, pos = 0;
    const char *cmd = NULL;
    int count = 0;

    /* Count only *command* lines, not every non-empty line.  Response codes
     * are produced per command (the AFLNet response buffer accumulates one
     * response per message the server processed); fuzzer-mutated garbage lines
     * that are glued into a single region do NOT each produce an independent
     * response.  Counting them (as text_protocol_next_slot does) shifts the
     * command->response ordinal mapping and makes the oracle bind a later
     * success code (e.g. a 250 from MKD) to the wrong command (e.g. RNTO),
     * manufacturing false state-violation candidates. */
    while (text_protocol_next_command(buf, len, proto, &cursor, &pos, &cmd)) {
        (void)pos;
        (void)cmd;
        count++;
    }
    return count;
}

static int text_response_slot_count_before_pos(const unsigned char **requests,
                                               const unsigned int *req_lens,
                                               int req_count,
                                               int region_idx,
                                               unsigned int cmd_pos,
                                               text_protocol_t proto) {
    int count = 0;

    if (!requests || !req_lens || region_idx < 0 || region_idx >= req_count)
        return 0;

    for (int i = 0; i < region_idx; i++)
        count += text_protocol_response_slot_count(requests[i], req_lens[i], proto);

    unsigned int cursor = 0, pos = 0;
    const char *cmd = NULL;
    while (text_protocol_next_command(requests[region_idx], req_lens[region_idx],
                                      proto, &cursor, &pos, &cmd)) {
        (void)cmd;
        if (pos >= cmd_pos) break;
        count++;
    }

    return count;
}

static int text_protocol_command_is_active_slot(const unsigned char *buf,
                                                unsigned int len,
                                                unsigned int cmd_pos,
                                                text_protocol_t proto,
                                                const char **cmd_out) {
    unsigned int cursor = 0, pos = 0;
    const char *cmd = NULL;

    while (text_protocol_next_command(buf, len, proto, &cursor, &pos, &cmd)) {
        if (pos == cmd_pos) {
            if (cmd_out) *cmd_out = cmd;
            return 1;
        }
        if (pos > cmd_pos) break;
    }
    return 0;
}

/* Slow reference implementation: re-scans all prior regions + the response.
 * Used as the fallback when the index is not built, and for ORACLE_SELF_TEST
 * cross-checking (see the fast versions below). */
static int text_response_code_for_command_slow(const unsigned char **requests,
                                               const unsigned int *req_lens,
                                               int req_count,
                                               const unsigned char *response,
                                               unsigned int resp_len,
                                               int region_idx,
                                               unsigned int cmd_pos,
                                               text_protocol_t proto,
                                               int resp_offset) {
    if (!requests || !req_lens || !response ||
        region_idx < 0 || region_idx >= req_count)
        return -1;

    if (!text_protocol_command_is_active_slot(requests[region_idx],
                                             req_lens[region_idx],
                                             cmd_pos, proto, NULL))
        return -1;

    int command_ordinal = text_response_slot_count_before_pos(requests, req_lens,
        req_count, region_idx, cmd_pos, proto);
    return extract_nth_response_code(response, resp_len,
                                     resp_offset + command_ordinal);
}

/* Fast path: look up the pre-built slot index (cumulative slot ordinal) and
 * the pre-extracted response-code array.  Equivalent to the slow version
 * because build_text_index() walks the same text_protocol_next_slot() ordering
 * and extract_all_response_codes() produces extract_nth_response_code() values. */
static int text_response_code_for_command(const unsigned char **requests,
                                          const unsigned int *req_lens,
                                          int req_count,
                                          const unsigned char *response,
                                          unsigned int resp_len,
                                          int region_idx,
                                          unsigned int cmd_pos,
                                          text_protocol_t proto,
                                          int resp_offset) {
    if (!requests || !req_lens || !response ||
        region_idx < 0 || region_idx >= req_count)
        return -1;

    if (g_text_index_valid && proto == g_text_index_proto) {
        for (int k = 0; k < g_slot_count; k++) {
            if (g_slots[k].region_idx == region_idx &&
                g_slots[k].slot_pos == cmd_pos) {
                if (!g_slots[k].cmd) return -1;  /* not an active command slot */
                int idx = resp_offset + g_slots[k].cum_slot;
                if (idx < 0 || idx >= g_resp_code_count) return -1;
#ifdef ORACLE_SELF_TEST
                {
                    int ref = text_response_code_for_command_slow(requests, req_lens,
                        req_count, response, resp_len, region_idx, cmd_pos,
                        proto, resp_offset);
                    if (ref != g_resp_codes[idx]) {
                        fprintf(stderr, "[oracle-selftest] code mismatch r=%d p=%u "
                                "ref=%d idx=%d\n", region_idx, cmd_pos, ref,
                                g_resp_codes[idx]);
                        abort();
                    }
                }
#endif
                return g_resp_codes[idx];
            }
        }
        return -1;  /* slot not found in index → not a valid response slot */
    }
    return text_response_code_for_command_slow(requests, req_lens, req_count,
        response, resp_len, region_idx, cmd_pos, proto, resp_offset);
}

static int text_prior_response_code_range_before_command_slow(
    const unsigned char **requests,
    const unsigned int *req_lens,
    int req_count,
    const unsigned char *response,
    unsigned int resp_len,
    int region_idx,
    unsigned int cmd_pos,
    text_protocol_t proto,
    int resp_offset,
    int min_code,
    int max_code) {
    if (!response || region_idx < 0 || region_idx >= req_count) return 0;

    int slots_before = text_response_slot_count_before_pos(requests, req_lens,
        req_count, region_idx, cmd_pos, proto);
    for (int n = 0; n < slots_before; n++) {
        int code = extract_nth_response_code(response, resp_len, resp_offset + n);
        if (code >= min_code && code <= max_code) return 1;
    }
    return 0;
}

static int text_prior_response_code_range_before_command(
    const unsigned char **requests,
    const unsigned int *req_lens,
    int req_count,
    const unsigned char *response,
    unsigned int resp_len,
    int region_idx,
    unsigned int cmd_pos,
    text_protocol_t proto,
    int resp_offset,
    int min_code,
    int max_code) {
    if (!response || region_idx < 0 || region_idx >= req_count) return 0;

    if (g_text_index_valid && proto == g_text_index_proto) {
        /* Find the target command's cumulative slot ordinal. */
        int target_slot = -1;
        for (int k = 0; k < g_slot_count; k++) {
            if (g_slots[k].region_idx == region_idx &&
                g_slots[k].slot_pos == cmd_pos) {
                target_slot = g_slots[k].cum_slot;
                break;
            }
        }
        if (target_slot < 0) return 0;
        for (int n = 0; n < target_slot; n++) {
            int idx = resp_offset + n;
            if (idx < 0 || idx >= g_resp_code_count) continue;
            int code = g_resp_codes[idx];
            if (code >= min_code && code <= max_code) return 1;
        }
        return 0;
    }
    return text_prior_response_code_range_before_command_slow(requests, req_lens,
        req_count, response, resp_len, region_idx, cmd_pos, proto, resp_offset,
        min_code, max_code);
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

static int content_length_values_conflict(const unsigned char *buf,
                                          unsigned int len) {
    const char *header_name = "Content-Length";
    size_t hlen = strlen(header_name);
    int seen = 0;
    int invalid = 0;
    unsigned long long first = 0;
    unsigned int last_cl_line_end = 0;
    int have_last = 0;
    unsigned int i = 0;

    while (i + hlen < len) {
        if ((i == 0 || buf[i - 1] == '\n') &&
            strncasecmp((const char *)buf + i, header_name, hlen) == 0) {
            unsigned int j = i + hlen;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
            if (j < len && buf[j] == ':') {
                /* A blank line (empty header line) separates one HTTP request
                 * from the next.  Content-Length headers straddling a blank
                 * line belong to DIFFERENT requests, not to a single request
                 * with conflicting CL values.  Fuzzer mutation often destroys
                 * the \r\n\r\n boundary and glues several requests into one
                 * region, which previously made the oracle count one CL from
                 * each glued request as a false "conflicting CL" smuggling hit.
                 * Reset the per-request state when we cross a blank line. */
                if (have_last) {
                    int has_blank = 0;
                    for (unsigned int k = last_cl_line_end; k + 2 < i; k++) {
                        if (buf[k] == '\n' &&
                            ((buf[k + 1] == '\n') ||
                             (buf[k + 1] == '\r' && buf[k + 2] == '\n'))) {
                            has_blank = 1;
                            break;
                        }
                    }
                    if (has_blank) {
                        seen = 0;
                        invalid = 0;
                        first = 0;
                    }
                }
                j++;
                while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
                if (j >= len || !isdigit(buf[j])) {
                    invalid = 1;
                } else {
                    unsigned long long val = 0;
                    while (j < len && isdigit(buf[j])) {
                        unsigned int digit = (unsigned int)(buf[j] - '0');
                        if (val > (ULLONG_MAX - digit) / 10) {
                            invalid = 1;
                            break;
                        }
                        val = val * 10 + digit;
                        j++;
                    }
                    while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
                    if (j < len && buf[j] != '\r' && buf[j] != '\n')
                        invalid = 1;
                    if (!seen) {
                        first = val;
                    } else if (val != first) {
                        return 1;
                    }
                    seen++;
                }
                /* Remember where this CL header's line ends, so the next CL
                 * can detect whether a blank line (request boundary) separates
                 * the two headers. */
                unsigned int line_end = i;
                while (line_end < len && buf[line_end] != '\n') line_end++;
                last_cl_line_end = line_end;
                have_last = 1;
            }
        }
        while (i < len && buf[i] != '\n') i++;
        if (i < len) i++;
    }

    return invalid && seen > 0;
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
        i = text_skip_line_breaks(buf, len, i);
        unsigned int line_start = text_skip_leading_controls(buf, len, i);
        if (line_start + hlen <= len &&
            strncasecmp((const char *)buf + line_start, header_name, hlen) == 0) {
            unsigned int j = line_start + hlen;
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
        i = text_next_line_start(buf, len, text_line_raw_end(buf, len, i));
    }
    return 0;
}

static int parse_header_token(const unsigned char *buf, unsigned int len,
                              const char *header_name,
                              const unsigned char **out,
                              unsigned int *out_len) {
    size_t hlen = strlen(header_name);
    unsigned int i = 0;

    while (i + hlen < len) {
        i = text_skip_line_breaks(buf, len, i);
        unsigned int line_start = text_skip_leading_controls(buf, len, i);
        if (line_start + hlen <= len &&
            strncasecmp((const char *)buf + line_start, header_name, hlen) == 0) {
            unsigned int j = line_start + hlen;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
            if (j >= len || buf[j] != ':') return 0;
            j++;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;

            unsigned int start = j;
            while (j < len && buf[j] != '\r' && buf[j] != '\n' &&
                   buf[j] != ';' && buf[j] != ' ' && buf[j] != '\t') {
                j++;
            }
            if (j <= start) return 0;
            if (out) *out = buf + start;
            if (out_len) *out_len = j - start;
            return 1;
        }
        i = text_next_line_start(buf, len, text_line_raw_end(buf, len, i));
    }
    return 0;
}

static int extract_rtsp_cseq(const unsigned char *req, unsigned int len,
                             unsigned int *cseq) {
    return parse_header_uint(req, len, "CSeq", cseq);
}

static int rtsp_line_starts_method(const unsigned char *buf, unsigned int len,
                                   unsigned int off) {
    return command_boundary_ok(buf, len, off, "OPTIONS ") ||
           command_boundary_ok(buf, len, off, "DESCRIBE ") ||
           command_boundary_ok(buf, len, off, "ANNOUNCE ") ||
           command_boundary_ok(buf, len, off, "SETUP ") ||
           command_boundary_ok(buf, len, off, "PLAY ") ||
           command_boundary_ok(buf, len, off, "PAUSE ") ||
           command_boundary_ok(buf, len, off, "TEARDOWN ") ||
           command_boundary_ok(buf, len, off, "GET_PARAMETER ") ||
           command_boundary_ok(buf, len, off, "SET_PARAMETER ") ||
           command_boundary_ok(buf, len, off, "RECORD ") ||
           command_boundary_ok(buf, len, off, "REGISTER ");
}

static unsigned int rtsp_method_block_end(const unsigned char *req,
                                          unsigned int len,
                                          unsigned int pos) {
    unsigned int end = len;
    unsigned int i = pos;
    while (i < len) {
        i = text_next_line_start(req, len, text_line_raw_end(req, len, i));
        unsigned int line_start = i;
        if (line_start > pos && line_start < len &&
            rtsp_line_starts_method(req, len, line_start)) {
            end = line_start;
            break;
        }
    }
    return end;
}

static int rtsp_next_method_cseq_pos(const unsigned char *req, unsigned int len,
                                     const char *method, unsigned int *cursor,
                                     unsigned int *cseq,
                                     unsigned int *method_pos) {
    unsigned int i = cursor ? *cursor : 0;

    while (i < len) {
        i = text_skip_line_breaks(req, len, i);
        if (i >= len) break;

        unsigned int line_start = i;
        unsigned int next = text_next_line_start(req, len,
            text_line_raw_end(req, len, i));

        if (command_boundary_ok(req, len, line_start, method)) {
            unsigned int block_end = rtsp_method_block_end(req, len, line_start);
            if (cursor) *cursor = (block_end > line_start) ? block_end : next;
            if (parse_header_uint(req + line_start, block_end - line_start,
                                  "CSeq", cseq)) {
                if (method_pos) *method_pos = line_start;
                return 1;
            }
            i = (block_end > line_start) ? block_end : next;
            continue;
        }

        i = next;
    }

    if (cursor) *cursor = len;
    return 0;
}

static int rtsp_next_any_method_cseq_pos(const unsigned char *req,
                                         unsigned int len,
                                         unsigned int *cursor,
                                         unsigned int *cseq,
                                         unsigned int *method_pos) {
    unsigned int i = cursor ? *cursor : 0;

    while (i < len) {
        i = text_skip_line_breaks(req, len, i);
        if (i >= len) break;

        unsigned int line_start = i;
        unsigned int next = text_next_line_start(req, len,
            text_line_raw_end(req, len, i));

        if (rtsp_line_starts_method(req, len, line_start)) {
            unsigned int block_end = rtsp_method_block_end(req, len, line_start);
            if (cursor) *cursor = (block_end > line_start) ? block_end : next;
            if (parse_header_uint(req + line_start, block_end - line_start,
                                  "CSeq", cseq)) {
                if (method_pos) *method_pos = line_start;
                return 1;
            }
            i = (block_end > line_start) ? block_end : next;
            continue;
        }

        i = next;
    }

    if (cursor) *cursor = len;
    return 0;
}

static int rtsp_method_cseq_pos(const unsigned char *req, unsigned int len,
                                const char *method, unsigned int *cseq,
                                unsigned int *method_pos) {
    unsigned int cursor = 0;
    return rtsp_next_method_cseq_pos(req, len, method, &cursor,
                                     cseq, method_pos);
}

static unsigned int rtsp_method_block_len(const unsigned char *req,
                                          unsigned int len,
                                          unsigned int method_pos) {
    return rtsp_method_block_end(req, len, method_pos) - method_pos;
}

static int rtsp_request_cseq_occurrences(const unsigned char **requests,
                                         const unsigned int *req_lens,
                                         int req_count,
                                         unsigned int want_cseq) {
    int count = 0;

    for (int i = 0; i < req_count; i++) {
        unsigned int cursor = 0, cseq = 0, pos = 0;
        while (rtsp_next_any_method_cseq_pos(requests[i], req_lens[i],
                                             &cursor, &cseq, &pos)) {
            (void)pos;
            if (cseq == want_cseq) count++;
        }
    }
    return count;
}

static int rtsp_method_session(const unsigned char *req, unsigned int len,
                               unsigned int method_pos,
                               const unsigned char **session,
                               unsigned int *session_len) {
    unsigned int block_len = rtsp_method_block_len(req, len, method_pos);
    return parse_header_token(req + method_pos, block_len, "Session",
                              session, session_len);
}

static int rtsp_method_line_is_valid_request(const unsigned char *req,
                                             unsigned int len,
                                             unsigned int method_pos,
                                             const char *method) {
    size_t method_len = strlen(method);
    unsigned int line_end = text_line_raw_end(req, len, method_pos);
    unsigned int uri_pos = method_pos + (unsigned int)method_len;

    if (!command_boundary_ok(req, len, method_pos, method)) return 0;
    if (line_end <= uri_pos + 7) return 0;

    for (unsigned int i = method_pos; i < line_end; i++) {
        if (req[i] < 0x20 && req[i] != '\t') return 0;
    }

    if (strncasecmp((const char *)req + uri_pos, "rtsp://", 7) != 0)
        return 0;

    for (unsigned int i = uri_pos + 7; i + 8 <= line_end; i++) {
        if (req[i] == ' ' &&
            strncasecmp((const char *)req + i + 1, "RTSP/1.", 7) == 0)
            return 1;
    }

    return 0;
}

static int rtsp_block_session_matches(const unsigned char *block,
                                      unsigned int block_len,
                                      const unsigned char *session,
                                      unsigned int session_len) {
    const unsigned char *block_session = NULL;
    unsigned int block_session_len = 0;

    if (!session || session_len == 0) return 1;
    if (!parse_header_token(block, block_len, "Session",
                            &block_session, &block_session_len))
        return 0;
    return block_session_len == session_len &&
           memcmp(block_session, session, session_len) == 0;
}

static int rtsp_block_has_session(const unsigned char *block,
                                  unsigned int block_len) {
    const unsigned char *session = NULL;
    unsigned int session_len = 0;
    return parse_header_token(block, block_len, "Session",
                              &session, &session_len);
}

static int rtsp_block_has_sdp_body(const unsigned char *block,
                                   unsigned int block_len) {
    return ci_memmem(block, block_len, "Content-Type: application/sdp", 29) ||
           ci_memmem(block, block_len, "\r\nv=0\r\n", 7) ||
           ci_memmem(block, block_len, "\nv=0\r\n", 6);
}

static int rtsp_block_is_setup_success(const unsigned char *block,
                                       unsigned int block_len,
                                       int code,
                                       const unsigned char *session,
                                       unsigned int session_len) {
    return code_is_2xx(code) &&
           ci_memmem(block, block_len, "Transport:", 10) &&
           ci_memmem(block, block_len, "Session:", 8) &&
           rtsp_block_session_matches(block, block_len, session, session_len);
}

static int rtsp_block_is_play_success(const unsigned char *block,
                                      unsigned int block_len,
                                      int code) {
    return code_is_2xx(code) &&
           !rtsp_block_has_sdp_body(block, block_len) &&
           rtsp_block_has_session(block, block_len) &&
           (ci_memmem(block, block_len, "RTP-Info:", 9) ||
            ci_memmem(block, block_len, "Range:", 6));
}

static int rtsp_block_is_record_success(const unsigned char *block,
                                        unsigned int block_len,
                                        int code) {
    return code_is_2xx(code) &&
           !rtsp_block_has_sdp_body(block, block_len) &&
           rtsp_block_has_session(block, block_len);
}

static int rtsp_response_block_by_cseq_unique_slow(const unsigned char *resp,
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

/* Fast path: consult the pre-built RTSP block index (single pass over the
 * response once, then O(#blocks) per CSeq lookup instead of one full response
 * scan per lookup).  build_rtsp_block_index() records the same blocks with the
 * same (cseq, code, len) that rtsp_response_block_by_cseq_unique_slow finds. */
static int rtsp_response_block_by_cseq_unique(const unsigned char *resp,
                                              unsigned int len,
                                              unsigned int want_cseq,
                                              const unsigned char **block,
                                              unsigned int *block_len,
                                              int *code_out) {
    (void)len;
    if (g_rtsp_index_valid) {
        int matches = 0;
        const unsigned char *found_block = NULL;
        unsigned int found_len = 0;
        int found_code = -1;
        for (int k = 0; k < g_rtsp_block_count; k++) {
            if (g_rtsp_blocks[k].has_cseq &&
                g_rtsp_blocks[k].cseq == want_cseq) {
                matches++;
                found_block = resp + g_rtsp_blocks[k].offset;
                found_len = g_rtsp_blocks[k].len;
                found_code = g_rtsp_blocks[k].code;
            }
        }
        if (matches == 1) {
            if (block) *block = found_block;
            if (block_len) *block_len = found_len;
            if (code_out) *code_out = found_code;
#ifdef ORACLE_SELF_TEST
            {
                const unsigned char *ref_block = NULL;
                unsigned int ref_len = 0;
                int ref_code = -1;
                int ref_ok = rtsp_response_block_by_cseq_unique_slow(resp, len,
                    want_cseq, &ref_block, &ref_len, &ref_code);
                if (ref_ok != 1 || ref_code != found_code || ref_len != found_len) {
                    fprintf(stderr, "[oracle-selftest] rtsp block mismatch "
                            "cseq=%u ref_code=%d idx_code=%d ref_len=%u idx_len=%u\n",
                            want_cseq, ref_code, found_code, ref_len, found_len);
                    abort();
                }
            }
#endif
            return 1;
        }
        return 0;
    }
    return rtsp_response_block_by_cseq_unique_slow(resp, len, want_cseq,
                                                   block, block_len, code_out);
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

static int rtsp_prior_setup_request_accepted(
    const unsigned char **requests,
    const unsigned int *req_lens,
    int req_count,
    const unsigned char *response,
    unsigned int resp_len,
    int target_region_idx,
    unsigned int target_method_pos,
    const unsigned char *session,
    unsigned int session_len) {

    if (!requests || !req_lens || !response) return 0;

    for (int i = 0; i < req_count; i++) {
        if (i > target_region_idx) break;

        unsigned int cursor = 0, setup_cseq = 0, setup_pos = 0;
        while (rtsp_next_method_cseq_pos(requests[i], req_lens[i], "SETUP ",
                                         &cursor, &setup_cseq, &setup_pos)) {
            if (i == target_region_idx && setup_pos >= target_method_pos)
                continue;

            const unsigned char *block = NULL;
            unsigned int block_len = 0;
            int code = -1;
            if (!rtsp_response_block_by_cseq_unique(response, resp_len,
                    setup_cseq, &block, &block_len, &code))
                continue;

            if (rtsp_block_is_setup_success(block, block_len, code,
                                            session, session_len))
                return 1;
        }
    }

    return 0;
}

static int rtsp_prior_setup_accepted_before_cseq(const unsigned char *resp,
                                                 unsigned int len,
                                                 unsigned int target_cseq,
                                                 const unsigned char *session,
                                                 unsigned int session_len) {
    unsigned int i = 0;

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
            int has_cseq = parse_header_uint(resp + block_start,
                block_end - block_start, "CSeq", &cseq);
            if (has_cseq && cseq == target_cseq)
                return 0;

            if (rtsp_block_is_setup_success(resp + block_start,
                                            block_end - block_start,
                                            code, session, session_len)) {
                return 1;
            }

            i = block_end;
            continue;
        }
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }

    return 0;
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

static int ftp_cmd_is_user(const char *cmd) {
    return cmd && (!strcmp(cmd, "USER ") || !strcmp(cmd, "USER"));
}

static int ftp_cmd_is_pass(const char *cmd) {
    return cmd && (!strcmp(cmd, "PASS ") || !strcmp(cmd, "PASS"));
}

static int ftp_cmd_is_rnfr(const char *cmd) {
    return cmd && !strcmp(cmd, "RNFR ");
}

static int ftp_cmd_is_rnto(const char *cmd) {
    return cmd && !strcmp(cmd, "RNTO ");
}

static int ftp_cmd_is_sensitive_data(const char *cmd) {
    return cmd &&
        (!strcmp(cmd, "RETR ") || !strcmp(cmd, "STOR ") ||
         !strcmp(cmd, "LIST")  || !strcmp(cmd, "NLST")  ||
         !strcmp(cmd, "MKD ")  || !strcmp(cmd, "RMD ")  ||
         !strcmp(cmd, "DELE ") || !strcmp(cmd, "APPE ") ||
         !strcmp(cmd, "SITE "));
}

static int ftp_cmd_is_filesystem(const char *cmd) {
    return cmd &&
        (!strcmp(cmd, "RETR ") || !strcmp(cmd, "STOR ") ||
         !strcmp(cmd, "DELE ") || !strcmp(cmd, "RMD ")  ||
         !strcmp(cmd, "RNFR ") || !strcmp(cmd, "RNTO ") ||
         !strcmp(cmd, "MKD ")  || !strcmp(cmd, "CWD ")  ||
         !strcmp(cmd, "CDUP")  || !strcmp(cmd, "LIST")  ||
         !strcmp(cmd, "NLST")  || !strcmp(cmd, "MLSD "));
}

static int text_command_line_is_clean(const unsigned char *buf,
                                      unsigned int len,
                                      unsigned int pos) {
    unsigned int end = text_line_raw_end(buf, len, pos);
    for (unsigned int i = pos; i < end; i++) {
        if (buf[i] < 0x20 && buf[i] != '\t') return 0;
    }
    return end > pos;
}

static int ftp_response_has_rnto_reject(const unsigned char *resp,
                                        unsigned int resp_len) {
    return response_has_phrase(resp, resp_len, "RNFR before RNTO") ||
           response_has_phrase(resp, resp_len, "Bad sequence of commands");
}

static int smtp_cmd_is_auth(const char *cmd) {
    return cmd && (!strcmp(cmd, "AUTH ") || !strcmp(cmd, "AUTH"));
}

static int smtp_cmd_is_mail(const char *cmd) {
    return cmd && !strcmp(cmd, "MAIL FROM:");
}

static int smtp_cmd_is_rcpt(const char *cmd) {
    return cmd && !strcmp(cmd, "RCPT TO:");
}

static int smtp_cmd_is_data(const char *cmd) {
    return cmd && !strcmp(cmd, "DATA");
}

static int smtp_cmd_is_vrfy(const char *cmd) {
    return cmd && (!strcmp(cmd, "VRFY ") || !strcmp(cmd, "VRFY"));
}

static int smtp_cmd_is_expn(const char *cmd) {
    return cmd && (!strcmp(cmd, "EXPN ") || !strcmp(cmd, "EXPN"));
}

static int smtp_cmd_is_starttls(const char *cmd) {
    return cmd && !strcmp(cmd, "STARTTLS");
}

static int smtp_response_has_state_rejection(const unsigned char *resp,
                                             unsigned int resp_len) {
    return response_has_phrase(resp, resp_len, "NUL characters are not allowed") ||
           response_has_phrase(resp, resp_len, "unrecognized command") ||
           response_has_phrase(resp, resp_len, "Too many syntax or protocol errors") ||
           response_has_phrase(resp, resp_len, "malformed address") ||
           response_has_phrase(resp, resp_len, "Syntactically invalid") ||
           response_has_phrase(resp, resp_len, "sender not yet given") ||
           response_has_phrase(resp, resp_len, "sender already given") ||
           response_has_phrase(resp, resp_len, "valid RCPT command must precede") ||
           response_has_phrase(resp, resp_len, "missing or malformed local part");
}

static unsigned int line_span_len(const unsigned char *buf, unsigned int len,
                                  unsigned int pos) {
    unsigned int end = text_line_raw_end(buf, len, pos);
    unsigned int next = text_next_line_start(buf, len, end);
    return next - pos;
}

static int span_has_traversal_syntax(const unsigned char *buf,
                                     unsigned int len) {
    return ci_memmem(buf, len, "../", 3) ||
           ci_memmem(buf, len, "..\\", 3) ||
           ci_memmem(buf, len, "%2e%2e", 6);
}

/* Reset protocol state for new execution */
static void reset_proto_state(void) {
    memset(&proto_state, 0, sizeof(proto_state));
}

/* ============================================
 * Per-Execution Index Builders
 * ============================================
 * These build the flat indexes in one linear pass over the requests and
 * the response, using the exact same tokenizer / extractor functions that
 * the old multi-pass scan used.  The hot helpers below (text_response_code_
 * for_command, text_prior_response_code_range_before_command,
 * extract_http_style_nth_response_block, rtsp_response_block_by_cseq_unique)
 * consult these indexes so a per-execution oracle check is O(total_bytes)
 * instead of O(N_commands * total_bytes). */

/* Single-pass response-code extractor.  Replicates extract_nth_response_code()
 * state machine exactly, but extracts ALL codes in one scan of the response.
 * codes[k] == extract_nth_response_code(resp,len,k) for every k produced.
 * Returns the number of response slots found (== number of codes). */
static int extract_all_response_codes(const unsigned char *resp, unsigned int len,
                                      int *codes, int cap) {
    int count = 0;
    unsigned int i = 0;
    int in_multiline = 0;
    int multiline_code = 0;
    int in_data_xfer = 0;

    while (i + 2 < len) {
        if ((i == 0 || (i > 0 && resp[i-1] == '\n')) &&
            resp[i] >= '1' && resp[i] <= '5' &&
            resp[i+1] >= '0' && resp[i+1] <= '9' &&
            resp[i+2] >= '0' && resp[i+2] <= '9') {

            int code = (resp[i] - '0') * 100 +
                       (resp[i+1] - '0') * 10 +
                       (resp[i+2] - '0');
            char sep = (i + 3 < len) ? resp[i + 3] : '\0';

            if (in_multiline) {
                if (code == multiline_code && sep == ' ')
                    in_multiline = 0;
            } else if (in_data_xfer) {
                if (code >= 200 && code <= 599)
                    in_data_xfer = 0;
            } else {
                if (count < cap) codes[count] = code;
                count++;
                if (sep == '-') {
                    in_multiline = 1;
                    multiline_code = code;
                } else if (code >= 100 && code < 200) {
                    in_data_xfer = 1;
                }
            }
        }
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }
    return count;
}

/* Build the text-protocol slot index (FTP/SMTP).  Walks text_protocol_next_slot
 * (which yields response-consuming slots, skipping SMTP DATA bodies) over every
 * region in order and records region/pos/cmd plus the cumulative slot ordinal.
 * Must be called before any text_response_code_for_command() lookup. */
static void build_text_index(const unsigned char **requests,
                             const unsigned int *req_lens,
                             int req_count,
                             text_protocol_t proto,
                             const unsigned char *response,
                             unsigned int resp_len,
                             int resp_offset) {
    g_slot_count = 0;
    int n = 0;
    for (int r = 0; r < req_count && n < ORACLE_CMD_CAP; r++) {
        unsigned int cursor = 0, pos = 0;
        const char *cmd = NULL;
        /* Index command lines only (see text_protocol_response_slot_count).
         * The cumulative ordinal must match the per-command response-code
         * ordering; counting garbage lines here shifts every later command's
         * response lookup and manufactures false violations. */
        while (n < ORACLE_CMD_CAP && text_protocol_next_command(requests[r], req_lens[r],
                                                                proto, &cursor, &pos, &cmd)) {
            g_slots[n].region_idx = r;
            g_slots[n].slot_pos = pos;
            g_slots[n].cmd = cmd;
            g_slots[n].cum_slot = n;
            n++;
        }
    }
    g_slot_count = n;

    /* Pre-extract all response codes in one pass.  We need resp_offset + g_slot_count
     * codes (the banner plus one code per response-consuming slot).  extract_all_
     * response_codes returns the number of slots actually present; entries beyond
     * that are padded with -1 so lookups return the same -1 that
     * extract_nth_response_code() would have returned. */
    int need = resp_offset + g_slot_count;
    if (need > ORACLE_RESP_CAP) need = ORACLE_RESP_CAP;
    int found = extract_all_response_codes(response, resp_len, g_resp_codes, need);
    for (int k = found; k < need; k++) g_resp_codes[k] = -1;
    g_resp_code_count = need;
    g_text_index_proto = proto;
    g_text_index_valid = 1;
}

/* Build the HTTP/DAAP response-block index in one pass. */
static void build_http_block_index(const unsigned char *resp, unsigned int len) {
    g_http_block_count = 0;
    unsigned int i = 0;
    while (i < len && g_http_block_count < ORACLE_HTTP_BLOCKS) {
        int code = -1;
        if (http_style_response_code_at(resp, len, i, &code)) {
            unsigned int start = i;
            unsigned int end = len;
            unsigned int j = i;
            while (j < len && resp[j] != '\n') j++;
            if (j < len) j++;
            while (j < len) {
                int next_code = -1;
                if (http_style_response_code_at(resp, len, j, &next_code)) {
                    end = j;
                    break;
                }
                while (j < len && resp[j] != '\n') j++;
                if (j < len) j++;
            }
            g_http_blocks[g_http_block_count].offset = start;
            g_http_blocks[g_http_block_count].len = end - start;
            g_http_blocks[g_http_block_count].code = code;
            g_http_block_count++;
        }
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }
    g_http_index_valid = 1;
}

/* Build the RTSP response-block index in one pass, keyed by CSeq. */
static void build_rtsp_block_index(const unsigned char *resp, unsigned int len) {
    g_rtsp_block_count = 0;
    unsigned int i = 0;
    while (i < len && g_rtsp_block_count < ORACLE_RTSP_BLOCKS) {
        if ((i == 0 || resp[i-1] == '\n') &&
            ci_memmem(resp + i, (len - i < 12) ? len - i : 12, "RTSP/", 5)) {
            unsigned int j = i;
            while (j < len && resp[j] != ' ') j++;
            if (++j + 2 >= len) {
                while (i < len && resp[i] != '\n') i++;
                if (i < len) i++;
                continue;
            }
            if (!isdigit(resp[j]) || !isdigit(resp[j+1]) || !isdigit(resp[j+2])) {
                while (i < len && resp[i] != '\n') i++;
                if (i < len) i++;
                continue;
            }
            int code = (resp[j] - '0') * 100 + (resp[j+1] - '0') * 10 + (resp[j+2] - '0');
            unsigned int block_start = i;
            unsigned int block_end = len;
            unsigned int k = i + 1;
            while (k + 5 < len) {
                while (k < len && resp[k] != '\n') k++;
                if (k < len) k++;
                if (k + 5 < len && ci_memmem(resp + k, (len - k < 12) ? len - k : 12, "RTSP/", 5)) {
                    block_end = k;
                    break;
                }
            }
            unsigned int cseq = 0;
            int has_cseq = parse_header_uint(resp + block_start, block_end - block_start,
                                             "CSeq", &cseq);
            g_rtsp_blocks[g_rtsp_block_count].offset = block_start;
            g_rtsp_blocks[g_rtsp_block_count].len = block_end - block_start;
            g_rtsp_blocks[g_rtsp_block_count].code = code;
            g_rtsp_blocks[g_rtsp_block_count].cseq = cseq;
            g_rtsp_blocks[g_rtsp_block_count].has_cseq = has_cseq;
            g_rtsp_block_count++;
            i = block_end;
            continue;
        }
        while (i < len && resp[i] != '\n') i++;
        if (i < len) i++;
    }
    g_rtsp_index_valid = 1;
}

/* Build the MQTT response packet index in one pass. */
static void build_mqtt_packet_index(const unsigned char *resp, unsigned int len) {
    g_mqtt_pkt_count = 0;
    unsigned int off = 0;
    while (off + 1 < len && g_mqtt_pkt_count < ORACLE_MQTT_PKTS) {
        unsigned int rl_b = 0;
        int rl = mqtt_decode_remaining_length(resp + off + 1, len - off - 1, &rl_b);
        if (rl < 0) break;
        unsigned int pkt_end = off + 1 + rl_b + (unsigned int)rl;
        if (pkt_end > len) break;
        g_mqtt_pkts[g_mqtt_pkt_count].offset = off;
        g_mqtt_pkts[g_mqtt_pkt_count].first_byte = resp[off];
        g_mqtt_pkts[g_mqtt_pkt_count].pkt_type = (resp[off] >> 4) & 0x0F;
        g_mqtt_pkts[g_mqtt_pkt_count].rem_len = rl;
        g_mqtt_pkt_count++;
        off = pkt_end;
    }
    g_mqtt_index_valid = 1;
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

    /* Build the single-pass slot+response-code index once so the per-command
     * text_response_code_for_command() lookups below are O(1). */
    build_text_index(requests, req_lens, req_count, TEXT_PROTO_FTP,
                     response, resp_len, resp_offset);

    /* Parse requests to build state, then check response */
    int has_user = 0, reported_data_bypass = 0;
    int has_path_traversal = 0, rnfr_pending = 0;
    int authenticated = 0;

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        /* Check path traversal attempts */
        if (ci_memmem(req, rlen, "../", 3) ||
            ci_memmem(req, rlen, "..\\", 3) ||
            ci_memmem(req, rlen, "%2e%2e", 6) ||
            ci_memmem(req, rlen, "%2e%2e%2f", 9)) {
            has_path_traversal = 1;
        }

        unsigned int cursor = 0, cmd_pos = 0;
        const char *cmd = NULL;
        while (text_protocol_next_command(req, rlen, TEXT_PROTO_FTP,
                                          &cursor, &cmd_pos, &cmd)) {
            int code = text_response_code_for_command(requests, req_lens,
                req_count, response, resp_len, i, cmd_pos, TEXT_PROTO_FTP,
                resp_offset);

            if (!ftp_cmd_is_rnto(cmd) && !ftp_cmd_is_rnfr(cmd) && rnfr_pending)
                rnfr_pending = 0;

            if (ftp_cmd_is_user(cmd)) {
                /* Only accept USER if the specific USER line received 331.
                 * Fuzz data may randomly match USER inside a larger region;
                 * blind state changes create false auth-bypass evidence. */
                if (code == 331) {
                    has_user = 1;
                    authenticated = 0;
                }
                continue;
            }

            if (ftp_cmd_is_pass(cmd)) {
                int prior_user_challenge = has_user ||
                    text_prior_response_code_range_before_command(
                        requests, req_lens, req_count, response, resp_len,
                        i, cmd_pos, TEXT_PROTO_FTP, resp_offset, 331, 331);
                if (prior_user_challenge) {
                    if (code >= 200 && code < 300)
                        authenticated = 1;
                } else {
                    if (code == 230) {
                        oracle_add_violation(result, ORACLE_SEV_HIGH,
                            ORACLE_CAT_STATE_VIOLATION | ORACLE_CAT_AUTH_BYPASS,
                            ORACLE_EVIDENCE_STRONG,
                            "FTP: PASS accepted without USER (auth state bypass)",
                            "CVE-2024-42644", i);
                    }
                }
                continue;
            }

            if (ftp_cmd_is_rnfr(cmd)) {
                rnfr_pending = (code == 350);
                continue;
            }

            if (ftp_cmd_is_rnto(cmd)) {
                int prior_rnfr_ready =
                    text_prior_response_code_range_before_command(
                        requests, req_lens, req_count, response, resp_len,
                        i, cmd_pos, TEXT_PROTO_FTP, resp_offset, 350, 350);
                if (!rnfr_pending && !prior_rnfr_ready &&
                    text_command_line_is_clean(req, rlen, cmd_pos) &&
                    !ftp_response_has_rnto_reject(response, resp_len) &&
                    code == 250) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_STATE_VIOLATION,
                        ORACLE_EVIDENCE_STRONG,
                        "FTP: RNTO without prior RNFR accepted by server",
                        NULL, i);
                }
                rnfr_pending = 0;
                continue;
            }

            /* Report only when the exact filesystem/data command received a
             * transfer-success code and no earlier response slot proved login
             * with 230.  This suppresses normal anonymous/default login flows
             * that reached 230 before LIST/RETR/STOR. */
            if (!reported_data_bypass && ftp_cmd_is_sensitive_data(cmd)) {
                int prior_login = authenticated ||
                    text_prior_response_code_range_before_command(
                        requests, req_lens, req_count, response, resp_len,
                        i, cmd_pos, TEXT_PROTO_FTP, resp_offset, 230, 230);
                if (!prior_login &&
                    (code == 150 || code == 225 || code == 226)) {
                    oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                        ORACLE_CAT_AUTH_BYPASS,
                        ORACLE_EVIDENCE_STRONG,
                        "FTP: Data command succeeded without authentication",
                        "CVE-2024-42645", i);
                    reported_data_bypass = 1;
                }
            }

            if (code == 230) authenticated = 1;
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
            unsigned int cursor = 0, cmd_pos = 0;
            const char *cmd = NULL;
            while (text_protocol_next_command(req, rlen, TEXT_PROTO_FTP,
                                              &cursor, &cmd_pos, &cmd)) {
                unsigned int span = line_span_len(req, rlen, cmd_pos);
                if (!ftp_cmd_is_filesystem(cmd) ||
                    !span_has_traversal_syntax(req + cmd_pos, span))
                    continue;

                int code = text_response_code_for_command(requests, req_lens,
                    req_count, response, resp_len, i, cmd_pos, TEXT_PROTO_FTP,
                    resp_offset);
                if (code == 150 || code == 226 || code == 250 || code == 257) {
                    oracle_add_violation(result, ORACLE_SEV_LOW,
                        ORACLE_CAT_PATH_TRAVERSAL,
                        ORACLE_EVIDENCE_HEURISTIC,
                        "FTP: Traversal syntax accepted by filesystem command (manual replay required)",
                        "N/A", i);
                    i = req_count;  /* One finding is enough */
                    break;
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

        /* REMOVED (2026-07-06): plain absolute-path disclosure such as
         * 257 "/home/ubuntu/test" from PWD/XPWD after login.  FTP servers
         * commonly return the current directory, and without a chroot policy
         * baseline this is configuration/normal behavior, not a vulnerability
         * candidate.  Sensitive file CONTENT checks above remain active. */
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
    {
        int tls_accepted = 0;
        int reported_tls = 0;
        for (int i = 0; i < req_count && !reported_tls; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            unsigned int cursor = 0, cmd_pos = 0;
            const char *cmd = NULL;

            while (text_protocol_next_command(req, rlen, TEXT_PROTO_FTP,
                                              &cursor, &cmd_pos, &cmd)) {
                int code = text_response_code_for_command(requests, req_lens,
                    req_count, response, resp_len, i, cmd_pos, TEXT_PROTO_FTP,
                    resp_offset);

                if (!strcmp(cmd, "AUTH ") &&
                    (command_boundary_ok(req, rlen, cmd_pos, "AUTH TLS") ||
                     command_boundary_ok(req, rlen, cmd_pos, "AUTH SSL"))) {
                    if (code == 234) tls_accepted = 1;
                    continue;
                }

                if (tls_accepted &&
                    (!strcmp(cmd, "RETR ") || !strcmp(cmd, "STOR ")) &&
                    code >= 150 && code <= 250) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_STATE_VIOLATION,
                        ORACLE_EVIDENCE_STRONG,
                        "FTP: Cleartext data transfer after AUTH TLS (TLS downgrade risk)",
                        "N/A", i);
                    reported_tls = 1;
                    break;
                }
            }
        }
    }

    /* Resource exhaustion via repeated failed auth attempts (CVE-2026-41324).
     * Many failed PASS commands without USER reset = potential resource drain. */
    {
        int failed_auth = 0;
        for (int i = 0; i < req_count; i++) {
            const unsigned char *req = requests[i];
            unsigned int rlen = req_lens[i];
            unsigned int cursor = 0, cmd_pos = 0;
            const char *cmd = NULL;
            while (text_protocol_next_command(req, rlen, TEXT_PROTO_FTP,
                                              &cursor, &cmd_pos, &cmd)) {
                if (!ftp_cmd_is_pass(cmd)) continue;
                int code = text_response_code_for_command(requests, req_lens,
                    req_count, response, resp_len, i, cmd_pos, TEXT_PROTO_FTP,
                    resp_offset);
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

    /* Build the single-pass slot+response-code index once. */
    build_text_index(requests, req_lens, req_count, TEXT_PROTO_SMTP,
                     response, resp_len, resp_offset);

    int has_auth = 0, has_mail = 0, has_rcpt = 0;
    int has_vrfy = 0, has_expn = 0;
    int smtp_state_rejected = smtp_response_has_state_rejection(response, resp_len);

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        unsigned int cursor = 0, cmd_pos = 0;
        const char *cmd = NULL;

        while (text_protocol_next_command(req, rlen, TEXT_PROTO_SMTP,
                                          &cursor, &cmd_pos, &cmd)) {
            int code = text_response_code_for_command(requests, req_lens,
                req_count, response, resp_len, i, cmd_pos, TEXT_PROTO_SMTP,
                resp_offset);

            /* State violation: DATA before RCPT.  SMTP acceptance of DATA is
             * specifically 354; generic 2xx greetings/NOOP replies are not
             * evidence for this command. */
            if (smtp_cmd_is_data(cmd)) {
                if (!has_rcpt && code == 354 &&
                    !smtp_state_rejected &&
                    text_command_line_is_clean(req, rlen, cmd_pos) &&
                    !response_has_phrase(response, resp_len,
                                         "RCPT command must precede DATA")) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_STATE_VIOLATION,
                        ORACLE_EVIDENCE_STRONG,
                        "SMTP: DATA before RCPT TO accepted by server",
                        NULL, i);
                }
                continue;
            }

            /* State violation: RCPT before MAIL FROM.  Require the RCPT line's
             * own 250/251 response.  A 250 from EHLO or an earlier command in
             * the same AFLNet region is not valid evidence. */
            if (smtp_cmd_is_rcpt(cmd)) {
                if (!has_mail && (code == 250 || code == 251) &&
                    !smtp_state_rejected &&
                    text_command_line_is_clean(req, rlen, cmd_pos) &&
                    !response_has_phrase(response, resp_len,
                                         "sender not yet given")) {
                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                        ORACLE_CAT_STATE_VIOLATION,
                        ORACLE_EVIDENCE_STRONG,
                        "SMTP: RCPT TO before MAIL FROM accepted by server",
                        NULL, i);
                }

                unsigned int span = line_span_len(req, rlen, cmd_pos);
                if (smtp_path_has_bare_crlf(req + cmd_pos, span) &&
                    (code == 250 || code == 251) &&
                    !response_has_phrase(response, resp_len,
                                         "NUL characters are not allowed") &&
                    !response_has_phrase(response, resp_len,
                                         "sender not yet given") &&
                    !response_has_phrase(response, resp_len,
                                         "missing or malformed local part") &&
                    !response_has_phrase(response, resp_len,
                                         "syntax error")) {
                    oracle_add_violation(result, ORACLE_SEV_LOW,
                        ORACLE_CAT_SMUGGLING | ORACLE_CAT_INJECTION,
                        ORACLE_EVIDENCE_HEURISTIC,
                        "SMTP: Bare CR/LF inside address path observed (manual smuggling context only)",
                        "N/A", i);
                }

                if (code == 250 || code == 251)
                    has_rcpt = 1;
                continue;
            }

            if (smtp_cmd_is_mail(cmd)) {
                unsigned int span = line_span_len(req, rlen, cmd_pos);
                if (smtp_path_has_bare_crlf(req + cmd_pos, span) &&
                    code == 250 &&
                    !response_has_phrase(response, resp_len,
                                         "NUL characters are not allowed") &&
                    !response_has_phrase(response, resp_len,
                                         "missing or malformed local part") &&
                    !response_has_phrase(response, resp_len,
                                         "syntax error")) {
                    oracle_add_violation(result, ORACLE_SEV_LOW,
                        ORACLE_CAT_SMUGGLING | ORACLE_CAT_INJECTION,
                        ORACLE_EVIDENCE_HEURISTIC,
                        "SMTP: Bare CR/LF inside address path observed (manual smuggling context only)",
                        "N/A", i);
                }

                if (code == 250)
                    has_mail = 1;
                continue;
            }

            if (smtp_cmd_is_auth(cmd)) {
                if (code == 235)
                    has_auth = 1;
                continue;
            }

            if (smtp_cmd_is_vrfy(cmd)) {
                has_vrfy = 1;
                continue;
            }

            if (smtp_cmd_is_expn(cmd)) {
                has_expn = 1;
                continue;
            }
        }
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
        unsigned int rcpt_pos = 0;
        for (int i = req_count - 1; i >= 0; i--) {
            unsigned int cursor = 0, cmd_pos = 0;
            const char *cmd = NULL;
            while (text_protocol_next_command(requests[i], req_lens[i],
                                              TEXT_PROTO_SMTP, &cursor,
                                              &cmd_pos, &cmd)) {
                if (smtp_cmd_is_rcpt(cmd) &&
                    smtp_rcpt_domain_is_external(requests[i] + cmd_pos,
                                                 req_lens[i] - cmd_pos)) {
                    rcpt_idx = i;
                    rcpt_pos = cmd_pos;
                }
            }
            if (rcpt_idx >= 0) break;
        }
        if (rcpt_idx >= 0) {
            int rcpt_code = text_response_code_for_command(requests, req_lens,
                req_count, response, resp_len, rcpt_idx, rcpt_pos,
                TEXT_PROTO_SMTP, resp_offset);
            int data_accepted = 0;
            for (int i = rcpt_idx; i < req_count; i++) {
                unsigned int cursor = 0, cmd_pos = 0;
                const char *cmd = NULL;
                while (text_protocol_next_command(requests[i], req_lens[i],
                                                  TEXT_PROTO_SMTP, &cursor,
                                                  &cmd_pos, &cmd)) {
                    if (i == rcpt_idx && cmd_pos <= rcpt_pos) continue;
                    if (!smtp_cmd_is_data(cmd)) continue;
                    int data_code = text_response_code_for_command(requests,
                        req_lens, req_count, response, resp_len, i, cmd_pos,
                        TEXT_PROTO_SMTP, resp_offset);
                    if (data_code == 354) data_accepted = 1;
                    break;
                }
                if (data_accepted) break;
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
            unsigned int cursor = 0, cmd_pos = 0;
            const char *cmd = NULL;
            while (text_protocol_next_command(requests[i], req_lens[i],
                                              TEXT_PROTO_SMTP, &cursor,
                                              &cmd_pos, &cmd)) {
                if (!smtp_cmd_is_vrfy(cmd) && !smtp_cmd_is_expn(cmd))
                    continue;
                int code = text_response_code_for_command(requests, req_lens,
                    req_count, response, resp_len, i, cmd_pos,
                    TEXT_PROTO_SMTP, resp_offset);
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
        int reported_starttls = 0;
        for (int i = 0; i < req_count && !reported_starttls; i++) {
            unsigned int cursor = 0, cmd_pos = 0;
            const char *cmd = NULL;
            while (text_protocol_next_command(requests[i], req_lens[i],
                                              TEXT_PROTO_SMTP, &cursor,
                                              &cmd_pos, &cmd)) {
                int code = text_response_code_for_command(requests, req_lens,
                    req_count, response, resp_len, i, cmd_pos,
                    TEXT_PROTO_SMTP, resp_offset);

                if (smtp_cmd_is_starttls(cmd)) {
                    if (code == 220) starttls_accepted = 1;
                    continue;
                }

                /* Check for cleartext sensitive commands after STARTTLS was
                 * accepted.  Exim's "554 Security failure" is an objective
                 * rejection, so it must not be reported as STRIPTLS evidence. */
                if (starttls_accepted &&
                    (smtp_cmd_is_mail(cmd) || smtp_cmd_is_auth(cmd)) &&
                    code >= 200 && code < 400 &&
                    !response_has_phrase(response, resp_len,
                                         "Security failure")) {
                    oracle_add_violation(result, ORACLE_SEV_HIGH,
                        ORACLE_CAT_STATE_VIOLATION,
                        ORACLE_EVIDENCE_STRONG,
                        "SMTP: Cleartext command after STARTTLS (STRIPTLS downgrade risk)",
                        "N/A", i);
                    reported_starttls = 1;
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
            unsigned int cursor = 0, cmd_pos = 0;
            const char *cmd = NULL;
            while (text_protocol_next_command(requests[i], req_lens[i],
                                              TEXT_PROTO_SMTP, &cursor,
                                              &cmd_pos, &cmd)) {
                if (!smtp_cmd_is_auth(cmd)) continue;
                int code = text_response_code_for_command(requests, req_lens,
                    req_count, response, resp_len, i, cmd_pos,
                    TEXT_PROTO_SMTP, resp_offset);
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

    /* Build the RTSP response-block index once so CSeq-based lookups are O(1). */
    build_rtsp_block_index(response, resp_len);

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        /* State machine: PLAY before SETUP.  This is reportable only when the
         * PLAY request itself is a syntactically valid RTSP request without a
         * Session header and its CSeq response has PLAY-specific evidence
         * (Session + RTP-Info/Range, not an SDP/DESCRIBE body).  A PLAY that
         * already carries Session is a session-reuse/hijack hypothesis, not a
         * wire-level proof of "before SETUP" in the current conversation. */
        unsigned int play_cursor = 0, play_cseq = 0, play_pos = 0;
        while (rtsp_next_method_cseq_pos(req, rlen, "PLAY ",
                                         &play_cursor, &play_cseq, &play_pos)) {
            if (rtsp_request_cseq_occurrences(requests, req_lens,
                                              req_count, play_cseq) != 1)
                continue;

            const unsigned char *play_block = NULL;
            unsigned int play_block_len = 0;
            int play_code = -1;
            if (!rtsp_response_block_by_cseq_unique(response, resp_len,
                    play_cseq, &play_block, &play_block_len, &play_code))
                continue;

            const unsigned char *play_session = NULL;
            unsigned int play_session_len = 0;
            if (rtsp_method_session(req, rlen, play_pos,
                                    &play_session, &play_session_len))
                continue;

            int prior_setup = rtsp_prior_setup_accepted_before_cseq(response,
                resp_len, play_cseq, play_session, play_session_len);
            int any_prior_setup = rtsp_prior_setup_accepted_before_cseq(response,
                resp_len, play_cseq, NULL, 0);
            int prior_setup_request = rtsp_prior_setup_request_accepted(
                requests, req_lens, req_count, response, resp_len,
                i, play_pos, NULL, 0);
            if (!prior_setup && !any_prior_setup &&
                !prior_setup_request &&
                rtsp_method_line_is_valid_request(req, rlen, play_pos, "PLAY ") &&
                rtsp_block_is_play_success(play_block, play_block_len, play_code)) {
                oracle_add_violation(result, ORACLE_SEV_HIGH,
                    ORACLE_CAT_STATE_VIOLATION,
                    ORACLE_EVIDENCE_STRONG,
                    "RTSP: PLAY before SETUP accepted by server",
                    "CVE-2021-38382", i);
                /* oracle_state_violation_count auto-derived by dispatcher */
            }
        }

        /* State machine: RECORD before SETUP.  As with PLAY, require a valid
         * request line with no Session header and a RECORD-shaped success
         * response; SDP bodies are DESCRIBE evidence, not RECORD acceptance. */
        unsigned int record_cursor = 0, record_cseq = 0, record_pos = 0;
        while (rtsp_next_method_cseq_pos(req, rlen, "RECORD ",
                                         &record_cursor, &record_cseq,
                                         &record_pos)) {
            if (rtsp_request_cseq_occurrences(requests, req_lens,
                                              req_count, record_cseq) != 1)
                continue;

            const unsigned char *record_block = NULL;
            unsigned int record_block_len = 0;
            int record_code = -1;
            if (!rtsp_response_block_by_cseq_unique(response, resp_len,
                    record_cseq, &record_block, &record_block_len, &record_code))
                continue;

            const unsigned char *record_session = NULL;
            unsigned int record_session_len = 0;
            if (rtsp_method_session(req, rlen, record_pos,
                                    &record_session, &record_session_len))
                continue;

            int prior_setup = rtsp_prior_setup_accepted_before_cseq(response,
                resp_len, record_cseq, record_session, record_session_len);
            int any_prior_setup = rtsp_prior_setup_accepted_before_cseq(response,
                resp_len, record_cseq, NULL, 0);
            int prior_setup_request = rtsp_prior_setup_request_accepted(
                requests, req_lens, req_count, response, resp_len,
                i, record_pos, NULL, 0);
            if (!prior_setup && !any_prior_setup &&
                !prior_setup_request &&
                rtsp_method_line_is_valid_request(req, rlen, record_pos, "RECORD ") &&
                rtsp_block_is_record_success(record_block, record_block_len,
                                             record_code)) {
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
        if (cseq_hdr) {
            unsigned int cseq = 0;
            int has_cseq = extract_rtsp_cseq(req, rlen, &cseq);
            int code = has_cseq ?
                extract_rtsp_response_code_by_cseq(response, resp_len, cseq) : -1;
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

    /* PLAY/RECORD-without-SETUP checks are integrated in the per-request loop
     * above using method-local CSeq extraction and response-side SETUP proof. */

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

    /* Build the HTTP-style response-block index once (DAAP is HTTP-based). */
    build_http_block_index(response, resp_len);

    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];

        /* DAAP is HTTP-based, check for protected resource access without session */
        int has_session = (ci_memmem(req, rlen, "session-id", 10) != NULL);

        /* Accessing databases without session */
        if ((ci_memmem(req, rlen, "/databases/", 11) ||
             ci_memmem(req, rlen, "/databases?", 11)) && !has_session) {
            /* Check the specific response block for this request.  A 200 code
             * from one response plus a DAAP body from another response is not
             * objective auth-bypass evidence. */
            if (resp_len > 0) {
                const unsigned char *resp_block = NULL;
                unsigned int resp_block_len = 0;
                int code = -1;
                int has_block = extract_http_style_nth_response_block(response,
                    resp_len, i, &resp_block, &resp_block_len, &code);
                int has_db_body = has_block &&
                                  (ci_memmem(resp_block, resp_block_len, "avdb", 4) ||
                                   ci_memmem(resp_block, resp_block_len, "dmap.listing", 12) ||
                                   ci_memmem(resp_block, resp_block_len, "mlcl", 4));
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
                const unsigned char *resp_block = NULL;
                unsigned int resp_block_len = 0;
                int code = -1;
                int has_block = extract_http_style_nth_response_block(response,
                    resp_len, i, &resp_block, &resp_block_len, &code);
                int leaked_sensitive = has_block &&
                    (ci_memmem(resp_block, resp_block_len, "root:x:0:0:", 11) ||
                     ci_memmem(resp_block, resp_block_len, "PRIVATE KEY-----", 16) ||
                     ci_memmem(resp_block, resp_block_len, "BEGIN OPENSSH PRIVATE KEY", 25));
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

    /* Info leak: server-info response contains unusual field names.
     * Field-name exposure alone has no demonstrated security impact, so keep
     * it as LOW context unless a future rule proves a concrete secret value. */
    if (resp_len > 0) {
        int reported_server_info = 0;
        for (int i = 0; i < req_count && !reported_server_info; i++) {
            if (!ci_memmem(requests[i], req_lens[i], "/server-info", 12))
                continue;

            const unsigned char *resp_block = NULL;
            unsigned int resp_block_len = 0;
            int code = -1;
            if (!extract_http_style_nth_response_block(response, resp_len, i,
                    &resp_block, &resp_block_len, &code))
                continue;

            if (code == 200 &&
                ci_memmem(resp_block, resp_block_len, "dmap.serverinforesponse", 23) &&
                (ci_memmem(resp_block, resp_block_len, "password", 8) ||
                 ci_memmem(resp_block, resp_block_len, "adminurl", 8))) {
                oracle_add_violation(result, ORACLE_SEV_LOW,
                    ORACLE_CAT_INFO_LEAK,
                    ORACLE_EVIDENCE_MODERATE,
                    "DAAP: Server-info response exposes sensitive-looking field names (context only)",
                    NULL, i);
                reported_server_info = 1;
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

    /* Build the HTTP response-block index once so block lookups are O(1). */
    build_http_block_index(response, resp_len);

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
                const unsigned char *resp_block = NULL;
                unsigned int resp_block_len = 0;
                int code = -1;
                int has_block = extract_http_style_nth_response_block(response,
                    resp_len, i, &resp_block, &resp_block_len, &code);
                int leaked_sensitive = has_block &&
                    (ci_memmem(resp_block, resp_block_len, "root:x:0:0:", 11) ||
                     ci_memmem(resp_block, resp_block_len, "PRIVATE KEY-----", 16) ||
                     ci_memmem(resp_block, resp_block_len, "BEGIN OPENSSH PRIVATE KEY", 25));
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
         * RFC 7230/9112 forbid ambiguous message framing.  A single origin
         * server's 2xx response is enough for a MEDIUM candidate, but not a
         * HIGH finding: practical smuggling impact still requires proxy or
         * differential parser validation. */
        int has_cl = count_header_lines(req, rlen, "Content-Length") > 0;
        int has_te = count_header_lines(req, rlen, "Transfer-Encoding") > 0;
        if (has_cl && has_te) {
            const unsigned char *resp_block = NULL;
            unsigned int resp_block_len = 0;
            int code = -1;
            extract_http_style_nth_response_block(response, resp_len, i,
                &resp_block, &resp_block_len, &code);
            if (code >= 200 && code < 300 &&
                !response_has_phrase(resp_block, resp_block_len, "400 Bad Request")) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_SMUGGLING,
                    ORACLE_EVIDENCE_MODERATE,
                    "HTTP: CL/TE ambiguous framing accepted (candidate; needs proxy/differential validation)",
                    NULL, i);
            }
        }

        /* Multiple Content-Length headers.  Identical decimal values are not
         * enough evidence for CL desync: many parsers normalize duplicate
         * identical values safely.  Report only conflicting or malformed CL
         * values that the server still processed with a 2xx response. */
        int cl_count = count_header_lines(req, rlen, "Content-Length");
        if (cl_count > 1 && content_length_values_conflict(req, rlen)) {
            const unsigned char *resp_block = NULL;
            unsigned int resp_block_len = 0;
            int code = -1;
            extract_http_style_nth_response_block(response, resp_len, i,
                &resp_block, &resp_block_len, &code);
            if (code >= 200 && code < 300 &&
                !response_has_phrase(resp_block, resp_block_len, "400 Bad Request")) {
                oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                    ORACLE_CAT_SMUGGLING,
                    ORACLE_EVIDENCE_MODERATE,
                    "HTTP: Conflicting Content-Length headers accepted (candidate; needs desync validation)",
                    NULL, i);
            }
        }
    }

    /* Response checks */
    if (resp_len > 0) {
        /* Info leak: sensitive file content */
        if ((ci_memmem(response, resp_len, "root:x:0:0:", 11) &&
             !request_contains_any(requests, req_lens, req_count, "root:x:0:0:")) ||
            (ci_memmem(response, resp_len, "PRIVATE KEY-----", 16) &&
             !request_contains_any(requests, req_lens, req_count, "PRIVATE KEY-----")) ||
            (ci_memmem(response, resp_len, "BEGIN OPENSSH PRIVATE KEY", 25) &&
             !request_contains_any(requests, req_lens, req_count, "BEGIN OPENSSH PRIVATE KEY"))) {
            oracle_add_violation(result, ORACLE_SEV_CRITICAL,
                ORACLE_CAT_INFO_LEAK,
                ORACLE_EVIDENCE_WEAK,
                "HTTP: Sensitive file content leaked in response",
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
                const unsigned char *resp_block = NULL;
                unsigned int resp_block_len = 0;
                int code = -1;
                int has_block = extract_http_style_nth_response_block(response,
                    resp_len, i, &resp_block, &resp_block_len, &code);
                int leaked_sensitive = has_block &&
                    (ci_memmem(resp_block, resp_block_len, "root:x:0:0:", 11) ||
                     ci_memmem(resp_block, resp_block_len, "PRIVATE KEY-----", 16) ||
                     ci_memmem(resp_block, resp_block_len, "BEGIN OPENSSH PRIVATE KEY", 25));
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
     * CRLF followed by HTTP/1.x inside request bytes is only a parser-stress
     * observation unless the response itself proves an injected/split response.
     * Keep it LOW so normal request bodies containing these bytes are not saved
     * as vulnerability candidates. */
    for (int i = 0; i < req_count; i++) {
        const unsigned char *req = requests[i];
        unsigned int rlen = req_lens[i];
        const unsigned char *crlf_http = ci_memmem(req, rlen, "\r\nHTTP/1.", 9);
        if (crlf_http) {
            const unsigned char *resp_block = NULL;
            unsigned int resp_block_len = 0;
            int code = -1;
            extract_http_style_nth_response_block(response, resp_len, i,
                &resp_block, &resp_block_len, &code);
            if (code >= 200 && code < 300 &&
                !response_has_phrase(resp_block, resp_block_len, "400 Bad Request")) {
                oracle_add_violation(result, ORACLE_SEV_LOW,
                    ORACLE_CAT_SMUGGLING | ORACLE_CAT_INJECTION,
                    ORACLE_EVIDENCE_HEURISTIC,
                    "HTTP: CRLF+HTTP marker accepted in request bytes (context only; no split-response proof)",
                    NULL, i);
            }
        }
    }

    /* Chunk extension abuse — chunked transfer encoding with oversized
     * chunk-size values (>16 hex digits exceeds uint64 range).
     * A 2xx response only proves parser acceptance; without crash/hang/resource
     * telemetry it is LOW context, not a DoS vulnerability candidate. */
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
                        const unsigned char *resp_block = NULL;
                        unsigned int resp_block_len = 0;
                        int code = -1;
                        extract_http_style_nth_response_block(response, resp_len, i,
                            &resp_block, &resp_block_len, &code);
                        if (code >= 200 && code < 300 &&
                            !response_has_phrase(resp_block, resp_block_len, "400 Bad Request")) {
                            oracle_add_violation(result, ORACLE_SEV_LOW,
                                ORACLE_CAT_RESOURCE_EXHAUST,
                                ORACLE_EVIDENCE_HEURISTIC,
                                "HTTP: Oversized chunk-size value accepted (parser-stress context only)",
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

    /* Build the MQTT response packet index once so per-request packet lookups
     * (PUBLISH→PUBACK, SUBSCRIBE→SUBACK) are O(1) instead of re-walking the
     * response from offset 0 for every request. */
    build_mqtt_packet_index(response, resp_len);

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
                     * (type=0x40, remaining_len=0x02).  Consult the pre-built
                     * packet index instead of re-walking the response. */
                    int publish_accepted = 0;
                    if (g_mqtt_index_valid && i < g_mqtt_pkt_count &&
                        g_mqtt_pkts[i].first_byte == 0x40 &&
                        g_mqtt_pkts[i].rem_len == 2) {
                        publish_accepted = 1;
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
                    if (req[0] != 0x82) break; /* MQTT SUBSCRIBE flags MUST be 0010 */
                    /* Only flag if the response packet at THIS request's position
                     * is a valid SUBACK (0x90).  Consult the pre-built packet
                     * index; the i-th response packet corresponds to the i-th
                     * request.  Verify it is 0x90 with remaining length >= 3.
                     * This avoids false positives from SUBACK bytes appearing
                     * later in the buffer (after a CONNECT that we haven't
                     * seen yet in the request stream). */
                    int sub_accepted = 0;
                    if (g_mqtt_index_valid && i < g_mqtt_pkt_count &&
                        g_mqtt_pkts[i].first_byte == 0x90 &&
                        g_mqtt_pkts[i].rem_len >= 3) {
                        sub_accepted = 1;
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
     * malformed SUBSCRIBE causes broker crash in affected parsers).
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
     * If a broker returns a matching SUBACK, the objective finding is a
     * protocol/state violation.  Do NOT label it DoS without independent
     * crash, hang, or resource-exhaustion evidence from AFL/AFLNet. */
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
                if (pkt_type == 8 && req[0] == 0x82) { /* SUBSCRIBE */
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
                        if (pkt_id == 0) continue;
                        unsigned int payload_off = hdr_size + 2;
                        unsigned int scan = payload_off;
                        while (scan + 2 <= pkt_end) {
                            uint16_t topic_len = (req[scan] << 8) | req[scan + 1];
                            if (topic_len == 0) {
                                if (scan + 2 >= pkt_end || req[scan + 2] > 2) break;
                                /* Verify: did broker send SUBACK for this packet?
                                 * Scan the pre-built packet index for SUBACK
                                 * (type 9) with matching packet ID.  Without both
                                 * CONNACK success AND matching SUBACK, the broker
                                 * never processed the zero-length filter. */
                                int suback_confirmed = 0;
                                if (g_mqtt_index_valid) {
                                    for (int pk = 0; pk < g_mqtt_pkt_count; pk++) {
                                        if (g_mqtt_pkts[pk].pkt_type != 9) continue; /* SUBACK */
                                        unsigned int off = g_mqtt_pkts[pk].offset;
                                        unsigned int rl_b = 0;
                                        int srl = mqtt_decode_remaining_length(
                                            response + off + 1, resp_len - off - 1, &rl_b);
                                        if (srl < 0) break;
                                        unsigned int vh = off + 1 + rl_b;
                                        if (srl >= 2 && vh + 2 <= resp_len) {
                                            uint16_t spid = (response[vh] << 8)
                                                          | response[vh + 1];
                                            unsigned int rc_off = vh + 2;
                                            int granted = (rc_off < resp_len &&
                                                           response[rc_off] <= 2);
                                            if (spid == pkt_id && granted) {
                                                suback_confirmed = 1; break;
                                            }
                                        }
                                    }
                                }
                                if (suback_confirmed) {
                                    oracle_add_violation(result, ORACLE_SEV_MEDIUM,
                                        ORACLE_CAT_STATE_VIOLATION,
                                        ORACLE_EVIDENCE_STRONG,
                                        "MQTT: SUBSCRIBE with zero-length topic "
                                        "filter accepted by broker (protocol violation)",
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

    /* MQTT v5 user-property abuse.
     * Count PROP_USER (0x26) only inside the MQTT v5 CONNECT properties
     * section.  MQTT v5 properties are in the CONNECT variable header after
     * keepalive and before payload; scanning payload/random bytes is noise.
     * A large accepted property list alone is not resource-exhaustion proof:
     * without crash, hang, timeout, memory telemetry, or broker-side error, it
     * remains LOW context rather than a reportable DoS candidate. */
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
            oracle_add_violation(result, ORACLE_SEV_LOW,
                ORACLE_CAT_RESOURCE_EXHAUST,
                ORACLE_EVIDENCE_HEURISTIC,
                "MQTT: Large v5 user-property list accepted in CONNECT (resource context only)",
                "N/A", -1);
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
    oracle_saved_reports = 0;
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

static int oracle_write_binary_blob(const char *fn,
                                    const unsigned char *data,
                                    unsigned int len) {
    if (len > 0 && !data) return 0;

    FILE *fp = fopen(fn, "wb");
    if (!fp) return 0;

    int ok = 1;
    if (data && len > 0) {
        size_t written = fwrite(data, 1, len, fp);
        ok = (written == len);
    }

    fclose(fp);
    return ok;
}

/* Write the triggering message sequence in the AFLNet length-prefixed
 * replay format ([u32 size][payload]...), byte-for-byte compatible with
 * `save_kl_messages_to_file(..., replay_enabled=1, ...)` and therefore
 * directly consumable by `aflnet-replay`.  The size prefix is written in
 * native byte order (little-endian on x86-64), matching how aflnet-replay
 * reads it via `fread(&size, sizeof(unsigned int), 1, fp)`. */
static int oracle_write_replay_messages(const char *fn,
                                        const unsigned char **requests,
                                        const unsigned int *req_lens,
                                        int req_count) {
    if (!fn || !requests || !req_lens || req_count <= 0) return 0;

    FILE *fp = fopen(fn, "wb");
    if (!fp) return 0;

    int ok = 1;
    for (int i = 0; i < req_count; i++) {
        unsigned int sz = req_lens[i];
        if (fwrite(&sz, sizeof(sz), 1, fp) != 1) { ok = 0; break; }
        if (sz > 0 && requests[i] &&
            fwrite(requests[i], 1, sz, fp) != sz) { ok = 0; break; }
    }

    fclose(fp);
    return ok;
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
    unsigned int response_len,
    const unsigned char **requests,
    const unsigned int *req_lens,
    int req_count) {

    if (!out_dir || !result || result->violation_count == 0) return;

    int reportable_count = 0;
    uint8_t report_max_severity = ORACLE_SEV_NONE;
    uint16_t report_categories = ORACLE_CAT_NONE;
    for (int i = 0; i < result->violation_count; i++) {
        const oracle_violation_t *v = &result->violations[i];
        if (v->severity < ORACLE_SEV_MEDIUM) continue;
        reportable_count++;
        if (v->severity > report_max_severity)
            report_max_severity = v->severity;
        report_categories |= v->category;
    }
    if (reportable_count == 0) return;

    /* Create violations directory */
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/replayable-violations", out_dir);
    mkdir(dir_path, 0755);

    /* Generate report filename.  Do not use oracle_unique_violations here:
     * repeated occurrences of the same semantic pattern are still distinct
     * triage artifacts and must not overwrite the first saved candidate. */
    uint64_t report_id = ++oracle_saved_reports;
    char fn[1024];
    snprintf(fn, sizeof(fn), "%s/id:%06llu,sev:%d,cat:%04x",
             dir_path, (unsigned long long)report_id,
             report_max_severity, report_categories);

    char req_fn[1100];
    char resp_fn[1100];
    char replay_fn[1100];
    snprintf(req_fn, sizeof(req_fn), "%s.request.bin", fn);
    snprintf(resp_fn, sizeof(resp_fn), "%s.response.bin", fn);
    snprintf(replay_fn, sizeof(replay_fn), "%s.request.replay", fn);

    int req_saved = oracle_write_binary_blob(req_fn, request_data, request_len);
    int resp_saved = oracle_write_binary_blob(resp_fn, response_data, response_len);
    int replay_saved = oracle_write_replay_messages(replay_fn, requests, req_lens, req_count);

    FILE *fp = fopen(fn, "w");
    if (!fp) return;

    fprintf(fp, "=== PROTOCOL ORACLE DEVIATION REPORT ===\n");
    fprintf(fp, "NOTE: This is a candidate for manual triage, NOT a confirmed finding.\n");
    fprintf(fp, "The oracle detects protocol-level behavioural deviations;\n");
    fprintf(fp, "exploitability depends on server configuration and deployment context.\n");
    fprintf(fp, "Time: %ld\n", (long)time(NULL));
    fprintf(fp, "Report ID: %llu\n", (unsigned long long)report_id);
    fprintf(fp, "Unique Pattern Count At Save: %llu\n",
            (unsigned long long)oracle_unique_violations);
    fprintf(fp, "Violations: %d\n", reportable_count);
    fprintf(fp, "Max Severity: %d\n", report_max_severity);
    fprintf(fp, "Categories: 0x%04x\n", report_categories);
    fprintf(fp, "Full Request File: %s (%s)\n", req_fn,
            req_saved ? "saved" : "not saved");
    fprintf(fp, "Full Replay File: %s (%s)\n", replay_fn,
            replay_saved ? "saved" : "not saved");
    fprintf(fp, "Full Request Messages: %d\n", req_count);
    fprintf(fp, "Full Request Bytes: %u\n", request_len);
    fprintf(fp, "Full Request FNV1a32: 0x%08x\n",
            (request_data && request_len > 0) ?
            oracle_hash(request_data, request_len) : 0);
    fprintf(fp, "Full Response File: %s (%s)\n", resp_fn,
            resp_saved ? "saved" : "not saved");
    fprintf(fp, "Full Response Bytes: %u\n", response_len);
    fprintf(fp, "Full Response FNV1a32: 0x%08x\n\n",
            (response_data && response_len > 0) ?
            oracle_hash(response_data, response_len) : 0);

    int printed = 0;
    for (int i = 0; i < result->violation_count; i++) {
        const oracle_violation_t *v = &result->violations[i];
        if (v->severity < ORACLE_SEV_MEDIUM) continue;
        printed++;
        fprintf(fp, "--- Violation %d ---\n", printed);
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

    /* Write a bounded text preview for quick inspection.  The full binary
     * request/response bytes are saved in sidecar files above. */
    if (request_data && request_len > 0) {
        unsigned int preview_len = request_len > 4096 ? 4096 : request_len;
        fprintf(fp, "=== REQUEST DATA PREVIEW (%u/%u bytes) ===\n",
                preview_len, request_len);
        fwrite(request_data, 1, request_len > 4096 ? 4096 : request_len, fp);
        fprintf(fp, "\n");
    }

    if (response_data && response_len > 0) {
        unsigned int preview_len = response_len > 4096 ? 4096 : response_len;
        fprintf(fp, "=== RESPONSE DATA PREVIEW (%u/%u bytes) ===\n",
                preview_len, response_len);
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
