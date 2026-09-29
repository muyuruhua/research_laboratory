/* mutation-ops.c — Protocol-Aware Mutation Engine implementation.
 * Extracted verbatim from afl-fuzz.c on 2026-09-07 (behavior-preserving
 * for S1-S4 + auth_prefix_protect) with six new version-valid strategies
 * (S5-S10). See mutation-ops.h for the strategy/CVE map. */

#include "mutation-ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

uint64_t auth_prefix_restores_havoc = 0;
uint64_t auth_prefix_calls = 0;
uint64_t auth_prefix_found = 0;
uint32_t cve_mutations_applied = 0;

/* S2c escape-amplifier ablation switch (CHATAFL_NO_ESCAPE_AMP) + counter */
int mut_no_escape_amp = 0;
uint64_t escape_amp_applied = 0;

/* S12 lexer-killer ablation switch (CHATAFL_NO_LEXKILL) + counter */
int mut_no_lexkill = 0;
uint64_t lexkill_applied = 0;

/* S13 nesting-imbalance ablation switch (CHATAFL_NO_NESTIMB) + counter */
int mut_no_nestimb = 0;
uint64_t nestimb_applied = 0;

/* S1b Transport saturation (CHATAFL_NO_TRANSPORTSAT) + counter */
int mut_no_transportsat = 0;
uint64_t transportsat_applied = 0;

/* S15 tunnel-switch (CHATAFL_NO_TUNNELSWITCH) + counter */
int mut_no_tunnelswitch = 0;
uint64_t tunnelswitch_applied = 0;

/* Weak default RNG; afl-fuzz.c and tests override with strong defs. */
__attribute__((weak)) uint32_t mut_ur(uint32_t bound) {
  return bound ? (uint32_t)(rand() % bound) : 0;
}

/* ══════════════════════════════════════════════════════════════════
 * Auth-prefix protection (moved from afl-fuzz.c unchanged)
 * ══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *prefix;       /* the command itself (e.g., "USER ") */
    uint8_t max_protect_len;  /* max bytes to protect after the prefix */
} auth_prefix_t;

static const auth_prefix_t ftp_auth_prefixes[] = {
    {"USER ", 32},     /* protect username (up to 32 chars) */
    {"PASS ", 32},     /* protect password */
    {"ACCT ", 16},
};
static const auth_prefix_t smtp_auth_prefixes[] = {
    {"EHLO ", 64},     /* protect hostname */
    {"HELO ", 64},
    {"AUTH ", 128},    /* protect auth mechanism + initial response */
};
static const auth_prefix_t rtsp_auth_prefixes[] = {
    {"DESCRIBE ", 0},  /* protect URL portion */
    {"SETUP ", 0},
};

static const auth_prefix_t *prefixes_for(const char *proto, uint32_t *count) {
    if (!proto) return NULL;
    if (strcasecmp(proto, "FTP") == 0) {
        *count = sizeof(ftp_auth_prefixes) / sizeof(ftp_auth_prefixes[0]);
        return ftp_auth_prefixes;
    }
    if (strcasecmp(proto, "SMTP") == 0) {
        *count = sizeof(smtp_auth_prefixes) / sizeof(smtp_auth_prefixes[0]);
        return smtp_auth_prefixes;
    }
    if (strcasecmp(proto, "RTSP") == 0) {
        *count = sizeof(rtsp_auth_prefixes) / sizeof(rtsp_auth_prefixes[0]);
        return rtsp_auth_prefixes;
    }
    return NULL;
}

uint32_t count_auth_prefixes(const uint8_t *buf, uint32_t len,
                             const char *proto) {
    uint32_t n_prefixes = 0;
    const auth_prefix_t *prefixes = prefixes_for(proto, &n_prefixes);
    if (!buf || !len || !prefixes) return 0;

    uint32_t count = 0;
    for (uint32_t i = 0; i < len; i++) {
        /* Check for prefix match at line start */
        if (i == 0 || buf[i-1] == '\n') {
            for (uint32_t p = 0; p < n_prefixes; p++) {
                uint32_t plen = strlen(prefixes[p].prefix);
                if (i + plen <= len &&
                    strncasecmp((const char *)buf + i, prefixes[p].prefix,
                                plen) == 0) {
                    count++;
                    break;
                }
            }
        }
    }
    return count;
}

uint32_t auth_prefix_protect(uint8_t *mutated_buf, const uint8_t *orig_buf,
                             uint32_t mutated_len, uint32_t orig_len,
                             const char *proto) {
    if (!mutated_buf || !orig_buf || !proto) return 0;
    auth_prefix_calls++;

    uint32_t n_prefixes = 0;
    const auth_prefix_t *prefixes = prefixes_for(proto, &n_prefixes);
    if (!prefixes) return 0;

    uint32_t restored = 0;
    /* 2026-09-07 v3: Direct offset restore — don't search in mutated.
     * Previous search approach never fired because havoc often corrupts
     * the prefix itself → search finds nothing → nothing restored.
     * This version restores auth content at the ORIGINAL offset directly. */
    for (uint32_t oi = 0; oi < orig_len; oi++) {
        if (oi == 0 || orig_buf[oi-1] == '\n' || orig_buf[oi-1] == '\0') {
            for (uint32_t p = 0; p < n_prefixes; p++) {
                uint32_t plen = strlen(prefixes[p].prefix);
                if (oi + plen <= orig_len &&
                    strncasecmp((const char *)orig_buf + oi,
                                prefixes[p].prefix, plen) == 0) {
                    auth_prefix_found++;
                    uint32_t eol = oi;
                    while (eol < orig_len && orig_buf[eol] != '\n') eol++;
                    uint32_t protect_len = eol - oi;
                    if (protect_len > (uint32_t)prefixes[p].max_protect_len + plen)
                        protect_len = prefixes[p].max_protect_len + plen;
                    if (eol + 1 < orig_len && orig_buf[eol] == '\r' &&
                        orig_buf[eol+1] == '\n')
                        protect_len += 2;
                    else if (eol < orig_len && orig_buf[eol] == '\n')
                        protect_len += 1;
                    if (oi + protect_len > orig_len) break;

                    /* Restore at same offset if still valid in mutated */
                    if (oi + protect_len <= mutated_len) {
                        if (memcmp(mutated_buf + oi, orig_buf + oi,
                                   protect_len) != 0) {
                            memcpy(mutated_buf + oi, orig_buf + oi,
                                   protect_len);
                            restored += protect_len;
                        }
                    }
                    break;
                }
            }
        }
    }
    return restored;
}

/* ══════════════════════════════════════════════════════════════════
 * CVE-targeted mutations
 * ══════════════════════════════════════════════════════════════════ */

static int line_starts_with(const uint8_t *buf, uint32_t len, uint32_t i,
                             const char *cmd) {
    uint32_t cl = strlen(cmd);
    if (i != 0 && buf[i-1] != '\n') return 0;
    if (i + cl > len) return 0;
    return strncasecmp((const char *)buf + i, cmd, cl) == 0;
}

/* ── Adaptive-gate marker scan (2026-09-08) ──
 * Mirrors the strategies' real preconditions so the havoc hook can
 * raise the trigger probability only on buffers where a strategy can
 * actually fire. Deliberately narrow: HTTP/SIP only mark Content-Length
 * (S1) — S9/S10 qualify on any request line and already saturate the
 * base 1/32 lottery, so boosting them would crowd out generic havoc. */
int mut_marker_scan(const uint8_t *buf, uint32_t len, const char *proto) {
    if (!buf || !proto || len < 8) return 0;

    if (strcasecmp(proto, "FTP") == 0) {
        for (uint32_t i = 0; i < len; i++) {
            if (i != 0 && buf[i-1] != '\n') continue;
            if (strncasecmp((const char *)buf + i, "RNTO ", 5) == 0 ||
                strncasecmp((const char *)buf + i, "MLSD ", 5) == 0 ||
                strncasecmp((const char *)buf + i, "MLST ", 5) == 0)
                return 1;
            /* S8 shape: quoted/escaped arg on a path-command line */
            static const char *s8[] = {"RNFR ", "MKD ", "XMKD ", "CWD "};
            for (int c = 0; c < 4; c++) {
                uint32_t cl = strlen(s8[c]);
                if (i + cl > len) continue;
                if (strncasecmp((const char *)buf + i, s8[c], cl) != 0)
                    continue;
                uint32_t eol = i + cl;
                while (eol < len && buf[eol] != '\r' && buf[eol] != '\n')
                    eol++;
                if (memchr(buf + i + cl, '"', eol - (i + cl)) ||
                    memchr(buf + i + cl, '\\', eol - (i + cl)))
                    return 1;
            }
        }
        return 0;
    }

    if (strcasecmp(proto, "SMTP") == 0) {
        for (uint32_t i = 0; i < len; i++) {
            if (i != 0 && buf[i-1] != '\n') continue;
            if (strncasecmp((const char *)buf + i, "AUTH ", 5) == 0)
                return 1;
        }
        return memmem(buf, len, "RCPT TO:<", 9) != NULL;
    }

    if (strcasecmp(proto, "RTSP") == 0)
        return memmem(buf, len, "Session:", 8) != NULL;

    if (strcasecmp(proto, "SIP") == 0 || strcasecmp(proto, "HTTP") == 0 ||
        strcasecmp(proto, "DAAP") == 0)
        return memmem(buf, len, "Content-Length:", 15) != NULL;

    return 0;
}

/* S2c/S11 shared body: quote-internal escape-run amplification.
 * Escape-decode-mismatch bug class — parsers that consume "\X" as two
 * bytes but store one keep consumed >> strlen(word), so lengths derived
 * from (buflen - strlen(word)) overshoot the buffer on read (proftpd
 * CVE-2023-51713, make_ftp_cmd OOB read). Amplification target
 * [30KB, 60KB) is calibrated so the overshoot crosses an ASAN pool
 * block boundary under CommandBufferSize 65535 (empirically 30000
 * escapes fire, ~250 stay pool-invisible). Class-generic: random
 * escape letters, no verb or buffer size hardcoded. Auth-prefixed
 * lines (USER/PASS/ACCT/AUTH) are skipped — auth_prefix_protect would
 * restore them, wasting the fire. */
static uint8_t escape_amplify_apply(uint8_t *buf, uint32_t *len_ref,
                                    uint32_t buf_cap) {
    uint32_t len = *len_ref;
    uint32_t cand_start[64], cand_stop[64];
    int n_cand = 0;
    uint32_t ls = 0;
    while (ls < len && n_cand < 64) {
        uint32_t le = ls;
        while (le < len && buf[le] != '\n') le++;
        uint32_t body_end = (le > ls && buf[le - 1] == '\r') ? le - 1 : le;
        if (body_end > ls &&
            !line_starts_with(buf, len, ls, "USER ") &&
            !line_starts_with(buf, len, ls, "PASS ") &&
            !line_starts_with(buf, len, ls, "ACCT ") &&
            !line_starts_with(buf, len, ls, "AUTH ") &&
            !line_starts_with(buf, len, ls, "EHLO ") &&
            !line_starts_with(buf, len, ls, "HELO ")) {
            cand_start[n_cand] = ls;
            cand_stop[n_cand] = (le < len) ? le + 1 : len;
            n_cand++;
        }
        ls = (le < len) ? le + 1 : len;
    }
    if (n_cand == 0) return 0;
    {
        int c = mut_ur(n_cand);
        uint32_t line_start = cand_start[c];
        uint32_t line_stop = cand_stop[c];
        uint32_t target = 30720 + mut_ur(30720); /* [30K, 60K) */
        uint32_t n_esc = (target > 6) ? (target - 6) / 2 : 0;
        uint32_t new_len = len - (line_stop - line_start) + (n_esc * 2 + 6);
        if (n_esc < 4096 || new_len >= buf_cap) return 0;
        /* rebuild: prefix | '"' ('\X')*n '"' SP X CRLF | suffix */
        uint8_t *tmp = (uint8_t *)malloc(new_len);
        if (!tmp) return 0;
        {
            uint32_t o = 0, i;
            memcpy(tmp + o, buf, line_start);
            o += line_start;
            tmp[o++] = '"';
            for (i = 0; i < n_esc; i++) {
                tmp[o++] = '\\';
                tmp[o++] = (uint8_t)('A' + mut_ur(26));
            }
            tmp[o++] = '"';
            tmp[o++] = ' ';
            tmp[o++] = 'X';
            tmp[o++] = '\r';
            tmp[o++] = '\n';
            memcpy(tmp + o, buf + line_stop, len - line_stop);
            o += len - line_stop;
            memcpy(buf, tmp, o);
            free(tmp);
            *len_ref = o;
            cve_mutations_applied++;
            escape_amp_applied++;
            return 1;
        }
    }
}

/* S1b (2026-09-25): Transport parameter saturation.  Numeric fields in
 * the RTSP/SIP Transport header (interleaved=, client_port=) are driven
 * to type boundaries — negative values (the CVE-2026-38998 trigger uses
 * interleaved=-1), zero, and 16/32-bit limits.  If no numeric param is
 * present, ";interleaved=-1" is appended.  Bug class: signed/unsigned
 * parameter validation gaps in transport parameter parsers
 * (live555 CVE-2026-38998 heap-UAF, tcpReadHandler1). */
static uint8_t transport_saturate(uint8_t *buf, uint32_t *len_ref,
                                  uint32_t buf_cap) {
    uint32_t len = *len_ref;
    static const char *sat_values[] = {
        "-1", "0", "65535", "65536", "2147483647", "4294967295"
    };
    const char *new_val = sat_values[mut_ur(6)];
    uint32_t new_vlen = strlen(new_val);

    /* find first Transport: header line */
    uint32_t ls = 0;
    while (ls < len) {
        uint32_t le = ls;
        while (le < len && buf[le] != '\n') le++;
        uint32_t body_end = (le > ls && buf[le-1] == '\r') ? le - 1 : le;
        if (body_end > ls + 10 &&
            strncasecmp((char *)buf + ls, "Transport:", 10) == 0) {
            uint32_t v = ls + 10;
            while (v < body_end && buf[v] == ' ') v++;
            /* scan for param=NUM inside the value */
            uint32_t p = v;
            while (p < body_end) {
                if ((p == v || buf[p-1] == ';' || buf[p-1] == ' ') &&
                    buf[p] != ';' && buf[p] != ' ' && buf[p] != '\r') {
                    /* start of a param name; look for '=' */
                    uint32_t q = p;
                    while (q < body_end && buf[q] != '=' && buf[q] != ';')
                        q++;
                    if (q < body_end && buf[q] == '=') {
                        /* found param=value; saturate the value */
                        uint32_t vs = q + 1;
                        uint32_t ve = vs;
                        while (ve < body_end && buf[ve] != ';' &&
                               buf[ve] != ' ' && buf[ve] != '\r')
                            ve++;
                        if (ve > vs) {
                            /* replace [vs, ve) with new_val */
                            uint32_t old_len = ve - vs;
                            uint32_t new_len = len - old_len + new_vlen;
                            if (new_len >= buf_cap) return 0;
                            memmove(buf + vs + new_vlen, buf + ve,
                                    len - ve);
                            memcpy(buf + vs, new_val, new_vlen);
                            *len_ref = new_len;
                            cve_mutations_applied++;
                            transportsat_applied++;
                            return 1;
                        }
                    }
                    p = q;
                } else {
                    p++;
                }
            }
            /* no numeric param found — append ;interleaved=<sat> */
            {
                uint32_t add = 1 + 11 + new_vlen; /* ";interleaved=" + val */
                uint32_t new_len = len + add;
                if (new_len >= buf_cap) return 0;
                uint32_t ins = body_end;
                memmove(buf + ins + add, buf + ins, len - ins);
                buf[ins] = ';';
                memcpy(buf + ins + 1, "interleaved=", 12);
                memcpy(buf + ins + 13, new_val, new_vlen);
                *len_ref = new_len;
                cve_mutations_applied++;
                transportsat_applied++;
                return 1;
            }
        }
        ls = (le < len) ? le + 1 : len;
    }
    return 0;
}

/* S15 (2026-09-25): RTSP-over-HTTP tunnel-switch probe.  After an RTSP
 * session is established (buffer contains Session: header), appends a
 * POST request with x-sessioncookie — the HTTP-tunnel path that
 * live555's testOnDemandRTSPServer accepts on the same TCP port.  This
 * protocol-switch message is the final trigger component for
 * CVE-2026-38998 (heap-UAF in tcpReadHandler1 via the alternative-byte
 * handler when RTP-over-TCP data races the HTTP-tunnel POST). */
static uint8_t tunnel_switch_append(uint8_t *buf, uint32_t *len_ref,
                                    uint32_t buf_cap) {
    uint32_t len = *len_ref;

    /* precondition: buffer must contain a Session: header */
    if (!memmem(buf, len, "Session:", 8)) return 0;

    /* generate a random 16-hex cookie */
    char cookie[17];
    uint32_t i;
    for (i = 0; i < 16; i++)
        cookie[i] = "0123456789ABCDEF"[mut_ur(16)];
    cookie[16] = 0;

    static const char *paths[] = { "/index.html", "/x", "/", "/api" };
    const char *path = paths[mut_ur(4)];

    uint32_t add = snprintf(NULL, 0,
        "POST %s HTTP/1.1\r\nx-sessioncookie: %s\r\n\r\n",
        path, cookie);
    uint32_t new_len = len + add;
    if (new_len >= buf_cap) return 0;

    snprintf((char *)buf + len, add + 1,
             "POST %s HTTP/1.1\r\nx-sessioncookie: %s\r\n\r\n",
             path, cookie);
    *len_ref = new_len;
    cve_mutations_applied++;
    tunnelswitch_applied++;
    return 1;
}

/* Expression-parameter-aware URI bounds for S12 (2026-09-26, option B):
 * When the URI contains an "expression=" style query parameter (a parameter
 * whose value feeds a secondary parser — SMARTPL, SPARQL, regex, filter),
 * return the VALUE region of that parameter as the injection target.
 * This targets secondary-parser endpoints without hardcoding any specific
 * target: "expression-like parameters invoke deeper parsers" is a
 * class-level property of web APIs.  Falls back to full URI bounds when
 * no such parameter exists (original S12 behavior). */
static int expression_param_bounds(const uint8_t *buf, uint32_t len,
                                   uint32_t uri_lo, uint32_t uri_hi,
                                   uint32_t *lo, uint32_t *hi) {
    static const char *expr_keys[] = {
        "expression=", "query=", "search=", "filter=", "where=", "match="
    };
    uint32_t n_keys = sizeof(expr_keys) / sizeof(expr_keys[0]);
    uint32_t k;

    for (k = 0; k < n_keys; k++) {
        uint32_t klen = strlen(expr_keys[k]);
        const uint8_t *hit = memmem(buf + uri_lo, uri_hi - uri_lo,
                                    expr_keys[k], klen);
        if (hit && hit + klen < buf + uri_hi) {
            uint32_t v = (uint32_t)(hit - buf) + klen;
            uint32_t ve = v;
            while (ve < uri_hi && buf[ve] != '&' && buf[ve] != ' ' &&
                   buf[ve] != '\r' && buf[ve] != '\n')
                ve++;
            if (ve > v + 4) {           /* value >= 5 bytes to be interesting */
                *lo = v;
                *hi = ve;
                return 1;
            }
        }
    }
    return 0;
}

/* S12 (2026-09-24): lexer-killer token injection.  Bug class: lexer
 * error-recovery recursion — lexers/parsers that enter recursive error
 * recovery on malformed tokens never return and permanently wedge the
 * worker (forked-daapd/owntone SMARTPL ANTLRv3 deadlock, verified 5/5
 * single-request global DoS on the benchmark mirror; advisory draft
 * 2026-09-20).  Poison injected at a random position of the request
 * URI: a bare '?' mid-token, a non-ASCII byte (0x81), a long same-char
 * run defeating bounded lookahead, and a trailing '?'. */
static uint8_t lexkill_apply_uri(uint8_t *buf, uint32_t *len_ref,
                                 uint32_t buf_cap,
                                 uint32_t uri_lo, uint32_t uri_hi) {
    uint32_t len = *len_ref;
    uint32_t n_run, n_ins, new_len, pos, o;
    uint8_t *tmp;

    if (uri_hi <= uri_lo + 4 || uri_hi > len) return 0;
    n_run = 24 + mut_ur(40);
    n_ins = 2 + n_run + 1;                    /* '?' 0x81 i*n '?' */
    new_len = len + n_ins;
    if (new_len >= buf_cap) return 0;

    pos = uri_lo + mut_ur(uri_hi - uri_lo);
    tmp = (uint8_t *)malloc(new_len);
    if (!tmp) return 0;
    memcpy(tmp, buf, pos);
    o = pos;
    tmp[o++] = '?';
    tmp[o++] = 0x81;
    { uint32_t i; for (i = 0; i < n_run; i++) tmp[o++] = 'i'; }
    tmp[o++] = '?';
    memcpy(tmp + o, buf + pos, len - pos);
    o += len - pos;
    memcpy(buf, tmp, o);
    free(tmp);
    *len_ref = o;
    cve_mutations_applied++;
    lexkill_applied++;
    return 1;
}

/* First request line's URI bounds: between space #1 and space #2 of the
 * first line ("METHOD uri VER").  Returns 0 if not found/too short. */
static int first_uri_bounds(const uint8_t *buf, uint32_t len,
                            uint32_t *lo, uint32_t *hi) {
    uint32_t le = 0, s1, s2;
    while (le < len && buf[le] != '\n') le++;
    if (le == 0) return 0;
    s1 = 0;
    while (s1 < le && buf[s1] != ' ') s1++;
    if (s1 >= le) return 0;
    s2 = s1 + 1;
    while (s2 < le && buf[s2] != ' ' && buf[s2] != '\r') s2++;
    if (s2 <= s1 + 5) return 0;
    *lo = s1 + 1;
    *hi = s2;
    return 1;
}

/* Header-value bounds: first "Name: value" line with value >= 8 bytes
 * (value runs from after ": " to EOL, CR stripped).  Feeds the same
 * poison injector as URIs — quoted param values (Transport mode=),
 * display names, address local-parts all live here. */
static int header_value_bounds(const uint8_t *buf, uint32_t len,
                               uint32_t *lo, uint32_t *hi) {
    uint32_t ls = 0;
    while (ls < len) {
        uint32_t le = ls;
        while (le < len && buf[le] != '\n') le++;
        const uint8_t *colon = memchr(buf + ls, ':', le - ls);
        if (colon && colon > buf + ls && colon < buf + le - 1) {
            uint32_t v = (uint32_t)(colon - buf) + 1;
            while (v < le && buf[v] == ' ') v++;
            uint32_t vend = le;
            if (vend > ls && buf[vend - 1] == '\r') vend--;
            if (vend >= v + 8) { *lo = v; *hi = vend; return 1; }
        }
        ls = (le < len) ? le + 1 : len;
    }
    return 0;
}

/* S13 (2026-09-25): nesting-imbalance injection.  Bug class: parsers
 * that recurse per nesting level or toggle quote-parity per escape —
 * deep unbalanced structures drive stack overflow / state confusion.
 * Shapes: '\"' x N (escape-parity attack), '"' x N (quote-parity),
 * '([{' cycled x N (bracket ladder for recursive descent).  Aims at
 * header values first, then request URIs, then any line >= 16 bytes. */
static uint8_t nest_imbalance_apply(uint8_t *buf, uint32_t *len_ref,
                                    uint32_t buf_cap) {
    uint32_t len = *len_ref;
    uint32_t lo = 0, hi = 0;
    uint32_t n, new_len, pos, o, i, shape;
    uint8_t *tmp;

    if (!header_value_bounds(buf, len, &lo, &hi) &&
        !first_uri_bounds(buf, len, &lo, &hi)) {
        /* fallback: first line >= 16 bytes */
        uint32_t ls = 0;
        while (ls < len) {
            uint32_t le = ls;
            while (le < len && buf[le] != '\n') le++;
            uint32_t vend = le;
            if (vend > ls && buf[vend - 1] == '\r') vend--;
            if (vend - ls >= 16) { lo = ls; hi = vend; break; }
            ls = (le < len) ? le + 1 : len;
        }
    }
    if (hi <= lo + 8) return 0;

    n = 64 + mut_ur(448);                 /* [64, 512) */
    shape = mut_ur(3);                    /* 0='\"'xN  1='"'xN  2='([{'xN */
    new_len = len + 3 * n + 8;
    if (new_len >= buf_cap) return 0;

    pos = lo + mut_ur(hi - lo);
    tmp = (uint8_t *)malloc(new_len);
    if (!tmp) return 0;
    memcpy(tmp, buf, pos);
    o = pos;
    if (shape == 0) {
        for (i = 0; i < n; i++) { tmp[o++] = '\\'; tmp[o++] = '"'; }
    } else if (shape == 1) {
        for (i = 0; i < n; i++) tmp[o++] = '"';
    } else {
        for (i = 0; i < n; i++) {
            tmp[o++] = '('; tmp[o++] = '['; tmp[o++] = '{';
        }
    }
    memcpy(tmp + o, buf + pos, len - pos);
    o += len - pos;
    memcpy(buf, tmp, o);
    free(tmp);
    *len_ref = o;
    cve_mutations_applied++;
    nestimb_applied++;
    return 1;
}

uint8_t cve_targeted_mutate(uint8_t *buf, uint32_t *len_ref,
                            uint32_t buf_cap, const char *proto) {
    if (!buf || !len_ref || !proto || *len_ref < 8) return 0;
    uint32_t len = *len_ref;

    /* ── S1: Content-Length overflow (kamailio CVE-2026-39863) ── */
    if (strcasecmp(proto, "SIP") == 0 || strcasecmp(proto, "HTTP") == 0 ||
        strcasecmp(proto, "DAAP") == 0) {
        const char *cl_marker = "Content-Length:";
        for (uint32_t i = 0; i + 15 < len; i++) {
            if (strncasecmp((char *)buf + i, cl_marker, 15) == 0) {
                uint32_t val_start = i + 15;
                while (val_start < len &&
                       (buf[val_start] == ' ' || buf[val_start] == '\t'))
                    val_start++;
                uint32_t val_end = val_start;
                while (val_end < len && buf[val_end] != '\r' &&
                       buf[val_end] != '\n')
                    val_end++;

                if (val_end > val_start && val_end - val_start < 20) {
                    static const char *overflow_vals[] = {
                        "2147483647",     /* INT_MAX */
                        "2147483648",     /* INT_MAX + 1 */
                        "99999999999999", /* > 2^32 */
                        "4294967295",     /* UINT_MAX */
                    };
                    const char *new_val = overflow_vals[mut_ur(4)];
                    uint32_t new_len = strlen(new_val);
                    uint32_t old_len = val_end - val_start;
                    if (new_len <= old_len) {
                        memcpy(buf + val_start, new_val, new_len);
                        for (uint32_t k = val_start + new_len; k < val_end; k++)
                            buf[k] = ' ';
                        cve_mutations_applied++;
                        return 1;
                    } else if (len - old_len + new_len < buf_cap) {
                        memmove(buf + val_start + new_len, buf + val_end,
                                len - val_end);
                        memcpy(buf + val_start, new_val, new_len);
                        *len_ref = len - old_len + new_len;
                        cve_mutations_applied++;
                        return 1;
                    }
                }
                break; /* Only mutate first CL found */
            }
        }
    }

    /* ── FTP strategies ── */
    if (strcasecmp(proto, "FTP") == 0) {
        /* S2a: RNTO trailing backslash/quote (proftpd CVE-2023-51713) */
        for (uint32_t i = 0; i + 5 < len; i++) {
            if (line_starts_with(buf, len, i, "RNTO ")) {
                uint32_t eol = i + 5;
                while (eol < len && buf[eol] != '\r' && buf[eol] != '\n')
                    eol++;
                /* Guard is on the WRITE extent (max index len), not on
                 * eol+1 — the memmove touches up to index len. */
                if (eol > i + 5 && eol < len && len + 1 <= buf_cap) {
                    uint8_t insert_char = mut_ur(2) ? '\\' : '"';
                    memmove(buf + eol + 1, buf + eol, len - eol);
                    buf[eol] = insert_char;
                    (*len_ref)++;
                    cve_mutations_applied++;
                    return 1;
                }
            }
        }

        /* S2b: MLSD/MLST argument extension (pure-ftpd CVE-2024-48208) */
        static const char *mlsd_cmds[] = {"MLSD ", "MLST "};
        for (int cmd_idx = 0; cmd_idx < 2; cmd_idx++) {
            uint32_t cmd_len = strlen(mlsd_cmds[cmd_idx]);
            for (uint32_t i = 0; i + cmd_len < len; i++) {
                if (line_starts_with(buf, len, i, mlsd_cmds[cmd_idx])) {
                    uint32_t arg_start = i + cmd_len;
                    uint32_t eol = arg_start;
                    while (eol < len && buf[eol] != '\r' && buf[eol] != '\n')
                        eol++;
                    uint32_t arg_len = eol - arg_start;
                    uint32_t extend = 100 + mut_ur(100);
                    if (len + extend < buf_cap && arg_len > 0) {
                        memmove(buf + arg_start + extend, buf + arg_start,
                                len - arg_start);
                        memset(buf + arg_start, 'A', extend);
                        *len_ref = len + extend;
                        cve_mutations_applied++;
                        return 1;
                    }
                }
            }
        }

        /* S8: line-end/quote structure (proftpd CVE-2023-51713 — OOB read
         * in make_ftp_cmd on quoted/escaped args at line end). Two shapes:
         * (a) strip the CR so the arg ends with a bare LF;
         * (b) duplicate a closing quote so the arg looks unclosed. */
        static const char *quote_cmds[] = {"RNFR ", "RNTO ", "MKD ", "XMKD ",
                                           "CWD "};
        for (int ci = 0; ci < 5; ci++) {
            uint32_t cl = strlen(quote_cmds[ci]);
            for (uint32_t i = 0; i + cl < len; i++) {
                if (!line_starts_with(buf, len, i, quote_cmds[ci])) continue;
                uint32_t eol = i + cl;
                while (eol < len && buf[eol] != '\r' && buf[eol] != '\n')
                    eol++;
                uint32_t arg_len = eol - (i + cl);
                if (arg_len == 0) continue;
                int has_quote = memchr(buf + i + cl, '"', arg_len) != NULL;
                int has_bslash = memchr(buf + i + cl, '\\', arg_len) != NULL;
                if (!has_quote && !has_bslash) continue;
                if (eol >= len) continue;

                if (buf[eol] == '\r' && eol + 1 < len && buf[eol+1] == '\n' &&
                    mut_ur(2) == 0) {
                    /* (a) bare-LF: drop the CR */
                    memmove(buf + eol, buf + eol + 1, len - eol - 1);
                    (*len_ref)--;
                    cve_mutations_applied++;
                    return 1;
                }
                /* (b) duplicate the byte before EOL — the memmove writes
                 * up to index len, so guard on the full extent. */
                if (len + 1 <= buf_cap) {
                    memmove(buf + eol + 1, buf + eol, len - eol);
                    buf[eol] = has_quote ? '"' : '\\';
                    (*len_ref)++;
                    cve_mutations_applied++;
                    return 1;
                }
            }
        }

        /* ── S2c: quote-internal escape-run amplification ──────────
         * Escape-decode-mismatch bug class: parsers that consume "\X"
         * as two bytes but store one keep consumed >> strlen(word), so
         * lengths derived from (buflen - strlen(word)) overshoot the
         * buffer on read (proftpd CVE-2023-51713, make_ftp_cmd OOB
         * read). See escape_amplify_apply() for the shared body. */
        if (!mut_no_escape_amp &&
            escape_amplify_apply(buf, len_ref, buf_cap))
            return 1;
    }

    /* ── SMTP strategies ── */
    if (strcasecmp(proto, "SMTP") == 0) {
        /* S3: AUTH base64 boundary (exim CVE-2018-6789/2023-42115) */
        for (uint32_t i = 0; i + 5 < len; i++) {
            if (line_starts_with(buf, len, i, "AUTH ")) {
                uint32_t j = i + 5;
                while (j < len && buf[j] != ' ' && buf[j] != '\r' &&
                       buf[j] != '\n')
                    j++;
                if (j < len && buf[j] == ' ') {
                    j++; /* skip space to base64 start */
                    uint32_t b64_start = j;
                    while (j < len && buf[j] != '\r' && buf[j] != '\n') j++;
                    uint32_t b64_len = j - b64_start;
                    if (b64_len > 0 && b64_len < 200) {
                        uint8_t choice = mut_ur(3);
                        if (choice == 0 && b64_len + 3 < buf_cap - (len - j)) {
                            static const char *pads[] = {"=", "==", "==="};
                            uint32_t pad_count = 1 + mut_ur(3);
                            uint32_t pad_len = strlen(pads[pad_count - 1]);
                            memmove(buf + j + pad_len, buf + j, len - j);
                            memcpy(buf + j, pads[pad_count - 1], pad_len);
                            *len_ref = len + pad_len;
                            cve_mutations_applied++;
                            return 1;
                        } else if (choice == 1 && b64_len > 1) {
                            /* Truncate to length mod 4 == 1 */
                            uint32_t new_len = b64_len - (b64_len % 4) + 1;
                            if (new_len < b64_len) {
                                memmove(buf + b64_start + new_len, buf + j,
                                        len - j);
                                *len_ref = len - (b64_len - new_len);
                                cve_mutations_applied++;
                                return 1;
                            }
                        } else if (choice == 2) {
                            /* Sequenced draws: C leaves LHS/RHS eval order
                             * unspecified, so pin index before value. */
                            uint32_t pos = mut_ur(b64_len);
                            uint8_t ch = (mut_ur(2)) ? '+' : '/';
                            buf[b64_start + pos] = ch;
                            cve_mutations_applied++;
                            return 1;
                        }
                    }
                }
                break;
            }
        }

        /* S5: AUTH SPA/NTLM malformed blob (exim CVE-2023-42114 —
         * OOB read past the decoded challenge when the blob is
         * truncated/non-ASCII). High-bit byte or hard truncation. */
        static const char *ntlm_marks[] = {"AUTH SPA ", "AUTH NTLM "};
        for (int mi = 0; mi < 2; mi++) {
            uint32_t ml = strlen(ntlm_marks[mi]);
            for (uint32_t i = 0; i + ml < len; i++) {
                if (!line_starts_with(buf, len, i, ntlm_marks[mi])) continue;
                uint32_t p = i + ml;
                uint32_t eol = p;
                while (eol < len && buf[eol] != '\r' && buf[eol] != '\n')
                    eol++;
                uint32_t plen = eol - p;
                if (plen < 2) continue;
                if (mut_ur(2) == 0) {
                    /* invalid high-bit byte inside the b64 blob — draws
                     * sequenced (index before value) for determinism */
                    uint32_t pos = mut_ur(plen);
                    uint8_t val = (mut_ur(2)) ? 0xFF : 0x80;
                    buf[p + pos] = val;
                    cve_mutations_applied++;
                    return 1;
                }
                /* hard-truncate to a 4-char fragment */
                memmove(buf + p + 4, buf + eol, len - eol);
                *len_ref = len - (plen - 4);
                cve_mutations_applied++;
                return 1;
            }
        }

        /* S6: RCPT TO address extension (exim CVE-2023-42116 — transport
         * OOB with over-long addresses). Pad localpart by 200-400 chars. */
        for (uint32_t i = 0; i + 9 < len; i++) {
            if (!line_starts_with(buf, len, i, "RCPT TO:<")) continue;
            uint32_t addr = i + 9;
            uint32_t aend = addr;
            while (aend < len && buf[aend] != '>') aend++;
            if (aend >= len || aend == addr) continue;
            uint32_t extend = 200 + mut_ur(200);
            if (len + extend >= buf_cap) continue;
            memmove(buf + addr + extend, buf + addr, len - addr);
            memset(buf + addr, 'A', extend);
            *len_ref = len + extend;
            cve_mutations_applied++;
            return 1;
        }

        /* S7: AUTH base64 NUL-field absence (exim CVE-2023-42115 — OOB
         * write when the decoded blob exceeds the 64KB read buffer).
         * Replace the b64 RESPONSE (after the mechanism token) with valid
         * base64 of 65540 'A' bytes: decodes to one >64KB field with no
         * NUL separators. */
        for (uint32_t i = 0; i + 5 < len; i++) {
            if (!line_starts_with(buf, len, i, "AUTH ")) continue;
            uint32_t p = i + 5;
            while (p < len && buf[p] == ' ') p++;
            /* skip the mechanism token */
            while (p < len && buf[p] != ' ' && buf[p] != '\r' &&
                   buf[p] != '\n')
                p++;
            if (p >= len || buf[p] != ' ') continue; /* no b64 response */
            p++; /* first byte of the b64 response */
            uint32_t eol = p;
            while (eol < len && buf[eol] != '\r' && buf[eol] != '\n') eol++;
            if (eol <= p) continue;
            /* b64("AAA")="QUFB"; 65540 = 3*21846 + 2 leftover bytes whose
             * encoding is "QUA=". Payload = "QUFB"*21846 + "QUA=" =
             * 87388 chars decoding to 'A'*65540. */
            uint32_t groups = 65540 / 3;      /* 21846 */
            uint32_t b64_len = groups * 4 + 4; /* 87388 */
            uint32_t tail = len - eol;
            uint32_t new_len = p + b64_len + tail;
            if (new_len >= buf_cap) continue;
            memmove(buf + p + b64_len, buf + eol, tail);
            uint32_t w = p;
            for (uint32_t g = 0; g < groups; g++) {
                memcpy(buf + w, "QUFB", 4);
                w += 4;
            }
            memcpy(buf + w, "QUA=", 4);
            *len_ref = new_len;
            cve_mutations_applied++;
            return 1;
        }
    }

    /* ── RTSP strategy ── */
    if (strcasecmp(proto, "RTSP") == 0) {
        /* S1b: Transport parameter saturation (live555 CVE-2026-38998) */
        if (!mut_no_transportsat && mut_ur(4) == 0) {
            if (transport_saturate(buf, len_ref, buf_cap))
                return 1;
        }

        /* S15: tunnel-switch append after session established */
        if (!mut_no_tunnelswitch && mut_ur(4) == 0) {
            if (tunnel_switch_append(buf, len_ref, buf_cap))
                return 1;
        }

        /* S4: Session token mutation (live555 CVE-2026-41470) */
        const char *sess_marker = "Session: ";
        for (uint32_t i = 0; i + 9 < len; i++) {
            if (strncasecmp((char *)buf + i, sess_marker, 9) == 0) {
                static const char *session_ids[] = {
                    "000022B8",       /* live555 deterministic counter */
                    "DEADBEEF",       /* random guess */
                    "00000001",       /* first possible value */
                };
                const char *new_sid = session_ids[mut_ur(3)];
                uint32_t sid_len = strlen(new_sid);
                uint32_t old_start = i + 9;
                uint32_t old_end = old_start;
                while (old_end < len && buf[old_end] != '\r' &&
                       buf[old_end] != '\n')
                    old_end++;
                uint32_t old_len = old_end - old_start;
                if (old_len > 0 && sid_len <= old_len) {
                    memcpy(buf + old_start, new_sid, sid_len);
                    for (uint32_t k = old_start + sid_len; k < old_end; k++)
                        buf[k] = ' ';
                    cve_mutations_applied++;
                    return 1;
                }
                break;
            }
        }
    }

    /* ── HTTP/DAAP strategies (forked-daapd HTTP API) ── */
    if (strcasecmp(proto, "HTTP") == 0 || strcasecmp(proto, "DAAP") == 0) {
        static const char *methods[] = {"GET ", "PUT ", "POST ", "DELETE ",
                                        "HEAD "};
        for (int mi = 0; mi < 5; mi++) {
            uint32_t ml = strlen(methods[mi]);
            for (uint32_t i = 0; i + ml + 1 < len; i++) {
                if (!line_starts_with(buf, len, i, methods[mi])) continue;
                uint32_t path_start = i + ml;
                uint32_t path_end = path_start;
                while (path_end < len && buf[path_end] != ' ' &&
                       buf[path_end] != '\r' && buf[path_end] != '\n')
                    path_end++;
                if (path_end <= path_start || path_end >= len) continue;

                /* S12 (lexer-killer): 25% split ahead of S10/S9 — those
                 * strategies intercept every request-line engine hit
                 * unconditionally, which would make a tail-positioned
                 * S12 dead code for request-bearing buffers. */
                if (!mut_no_lexkill && mut_ur(4) == 0) {
                    /* Option B: prefer expression-param value region when
                     * present, else full URI (original behavior) */
                    uint32_t elo, ehi;
                    if (expression_param_bounds(buf, len, path_start,
                                                path_end, &elo, &ehi)) {
                        if (lexkill_apply_uri(buf, len_ref, buf_cap,
                                              elo, ehi))
                            return 1;
                    }
                    if (lexkill_apply_uri(buf, len_ref, buf_cap,
                                          path_start, path_end))
                        return 1;
                }

                /* S10: query parameter omission (owntone CVE-2026-26829 —
                 * NULL-deref when a required query parameter is absent). */
                uint8_t *qmark = memchr(buf + path_start, '?',
                                        path_end - path_start);
                if (qmark && mut_ur(2) == 0) {
                    uint32_t cut = qmark - buf;
                    memmove(buf + cut, buf + path_end, len - path_end);
                    *len_ref = len - (path_end - cut);
                    cve_mutations_applied++;
                    return 1;
                }

                /* S9: consecutive-separator path (owntone CVE-2026-26828 —
                 * NULL-deref on double-slash paths at library endpoints). */
                static const char *sep_paths[] = {
                    "/databases/1//playlists",
                    "/databases/1//containers",
                    "/databases/1//browse/genre",
                    "/api//playlists",
                    "/api///",
                };
                const char *new_path = sep_paths[mut_ur(5)];
                uint32_t new_plen = strlen(new_path);
                uint32_t old_plen = path_end - path_start;
                if (len - old_plen + new_plen >= buf_cap) continue;
                memmove(buf + path_start + new_plen, buf + path_end,
                        len - path_end);
                memcpy(buf + path_start, new_path, new_plen);
                *len_ref = len - old_plen + new_plen;
                cve_mutations_applied++;
                return 1;
            }
        }
    }

    /* ── S11 (2026-09-24): generalized escape-run amplification ────
     * Extends the S2c bug-class operator (verified on proftpd
     * CVE-2023-51713) to every text protocol with quoted-string
     * grammar — SMTP (address/param quoting), RTSP (Transport/session
     * params), SIP (display names), HTTP (header values), DAAP
     * (query params). Exploratory: no known in-window target on these
     * mirrors yet; the operator covers the class wherever a parser
     * mis-accounts escape-decoded lengths. FTP is excluded here — its
     * in-branch S2c already ran (ordered after S2a/S8). MQTT is a
     * binary protocol with no quoted-string grammar. Shares the
     * CHATAFL_NO_ESCAPE_AMP ablation switch and the
     * escape_amp_applied counter with S2c. */
    /* Tail strategies for text protocols (no MQTT).  S11 has no
     * probability gate, so a fair 1/3 dice orders the three arms and
     * each declines through to the next: S12-URI (SIP only, the
     * HTTP/DAAP URIs already had their in-block chance) -> S12b
     * header-value scope (Transport mode=, display names, address
     * local-parts) -> S13 nesting imbalance -> S11 escape flood. */
    if (strcasecmp(proto, "MQTT") != 0) {
        int arm = (int)mut_ur(4);
        int k;
        for (k = 0; k < 4; k++) {
            int a = (arm + k) % 4;
            if (a == 0 && !mut_no_lexkill &&
                strcasecmp(proto, "SIP") == 0) {
                uint32_t ulo, uhi;
                if (first_uri_bounds(buf, len, &ulo, &uhi)) {
                    uint32_t elo, ehi;
                    if (expression_param_bounds(buf, len, ulo, uhi,
                                                &elo, &ehi)) {
                        if (lexkill_apply_uri(buf, len_ref, buf_cap,
                                              elo, ehi))
                            return 1;
                    }
                    if (lexkill_apply_uri(buf, len_ref, buf_cap,
                                          ulo, uhi))
                        return 1;
                }
            } else if (a == 1 && !mut_no_lexkill) {
                uint32_t hlo, hhi;
                if (header_value_bounds(buf, len, &hlo, &hhi) &&
                    lexkill_apply_uri(buf, len_ref, buf_cap, hlo, hhi))
                    return 1;
            } else if (a == 2 && !mut_no_nestimb) {
                if (nest_imbalance_apply(buf, len_ref, buf_cap))
                    return 1;
            } else {
                if (!mut_no_escape_amp &&
                    strcasecmp(proto, "FTP") != 0 &&
                    escape_amplify_apply(buf, len_ref, buf_cap))
                    return 1;
            }
        }
    }

    return 0;
}
