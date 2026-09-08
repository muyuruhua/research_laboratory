/* mutation-ops.c — Protocol-Aware Mutation Engine implementation.
 * Extracted verbatim from afl-fuzz.c on 2026-09-07 (behavior-preserving
 * for S1-S4 + auth_prefix_protect) with six new version-valid strategies
 * (S5-S10). See mutation-ops.h for the strategy/CVE map. */

#include "mutation-ops.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

uint64_t auth_prefix_restores_havoc = 0;
uint64_t auth_prefix_calls = 0;
uint64_t auth_prefix_found = 0;
uint32_t cve_mutations_applied = 0;

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

    return 0;
}
