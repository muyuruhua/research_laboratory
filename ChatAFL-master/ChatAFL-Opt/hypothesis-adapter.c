/*
 * hypothesis-adapter.c
 * Adapter to integrate grammar hypotheses into AFL pattern structures.
 *
 * For MQTT (binary protocol):
 *   Creates binary header patterns based on the MQTT packet-type byte.
 * For text protocols (SIP, FTP, HTTP, …):
 *   Creates text regex patterns (original behaviour, unchanged).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <unistd.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "chat-llm.h"
#include <fcntl.h>

#include "hypothesis-adapter.h"
#include "alloc-inl.h"
#include "hash.h"

/* ============================================
 * MQTT binary helpers
 * ============================================ */

/* MQTT v3.1.1 packet type nibbles (upper 4 bits of first byte) */
static const struct {
    unsigned char nibble;   /* upper nibble value */
    const char   *name;     /* canonical name used by LLM hypotheses */
} mqtt_type_table[] = {
    { 1,  "CONNECT"     },
    { 2,  "CONNACK"     },
    { 3,  "PUBLISH"     },
    { 4,  "PUBACK"      },
    { 5,  "PUBREC"      },
    { 6,  "PUBREL"      },
    { 7,  "PUBCOMP"     },
    { 8,  "SUBSCRIBE"   },
    { 9,  "SUBACK"      },
    { 10, "UNSUBSCRIBE" },
    { 11, "UNSUBACK"    },
    { 12, "PINGREQ"     },
    { 13, "PINGRESP"    },
    { 14, "DISCONNECT"  },
    { 0,  NULL          }   /* sentinel */
};

const char *mqtt_type_nibble_to_name(unsigned char nibble) {
    for (int i = 0; mqtt_type_table[i].name; i++) {
        if (mqtt_type_table[i].nibble == nibble)
            return mqtt_type_table[i].name;
    }
    return NULL;
}

/* Return the upper-nibble value for a given MQTT message-type name,
 * or 0 if not found. */
static unsigned char mqtt_name_to_nibble(const char *name) {
    for (int i = 0; mqtt_type_table[i].name; i++) {
        if (strcasecmp(mqtt_type_table[i].name, name) == 0)
            return mqtt_type_table[i].nibble;
    }
    return 0;
}

int is_binary_protocol(const char *protocol_name) {
    if (!protocol_name) return 0;
    return (strcasecmp(protocol_name, "MQTT")   == 0 ||
            strcasecmp(protocol_name, "DNS")    == 0 ||
            strcasecmp(protocol_name, "DTLS12") == 0 ||
            strcasecmp(protocol_name, "TLS")    == 0 ||
            strcasecmp(protocol_name, "SSH")    == 0 ||
            strcasecmp(protocol_name, "DICOM")  == 0);
}

/* Extract the first token from a text protocol message region
 * as the message type keyword (e.g., "USER", "GET", "INVITE").
 * Returns a newly allocated string via ck_alloc, or NULL.
 * Caller must free with ck_free(). */
char* extract_text_message_type(const unsigned char *buf, size_t len) {
    if (!buf || len == 0) return NULL;

    /* Skip leading whitespace / CRLF */
    size_t start = 0;
    while (start < len && (buf[start] == ' '  || buf[start] == '\t' ||
                           buf[start] == '\r' || buf[start] == '\n'))
        start++;

    if (start >= len) return NULL;

    /* Find end of first token (delimited by space, tab, or CRLF) */
    size_t end = start;
    while (end < len && buf[end] != ' '  && buf[end] != '\t' &&
                        buf[end] != '\r' && buf[end] != '\n')
        end++;

    size_t token_len = end - start;
    if (token_len == 0 || token_len > 64) return NULL;  /* sanity check */

    char *type = ck_alloc(token_len + 1);
    memcpy(type, buf + start, token_len);
    type[token_len] = '\0';

    return type;
}

/* ============================================
 * Text protocol helpers (unchanged)
 * ============================================ */

/* Escape regex-special chars in a basic way */
static char *escape_for_regex(const char *s) {
    size_t len = strlen(s);
    char *out = ck_alloc(len * 2 + 1);
    char *p = out;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '.' || c == '^' || c == '$' || c == '*' || c == '+' ||
            c == '?' || c == '(' || c == ')' || c == '[' || c == ']' ||
            c == '{' || c == '}' || c == '|' || c == '\\') {
            *p++ = '\\';
        }
        *p++ = c;
    }
    *p = '\0';
    return out;
}

/* ============================================
 * Integration entry point
 * ============================================ */

int integrate_hypotheses_into_protocol_patterns(hypothesis_context_t *ctx,
                                                klist_t(rang) *protocol_patterns,
                                                khash_t(strSet) *message_types_set,
                                                const char *out_dir,
                                                const char *protocol_name) {
    if (!ctx || !protocol_patterns || !message_types_set) return 0;

    int binary = is_binary_protocol(protocol_name);
    int integrated = 0;

    for (size_t i = 0; i < ctx->hypothesis_count; i++) {
        grammar_hypothesis_t *hyp = ctx->hypotheses[i];
        if (!hyp || !hyp->message_type) continue;

        char header_pattern[512];
        char fields_pattern[128];

        if (binary && protocol_name &&
            strcasecmp(protocol_name, "MQTT") == 0) {
            /* ------- MQTT binary pattern ------- */
            unsigned char nibble = mqtt_name_to_nibble(hyp->message_type);
            if (nibble == 0) {
                fprintf(stderr,
                        "[hyp-adapter] Unknown MQTT type '%s', skipping\n",
                        hyp->message_type);
                continue;
            }
            /* Match first byte whose upper nibble equals the type.
             * PCRE2 character class: [\xT0-\xTF] where T = nibble.
             * For CONNECT (nibble 1): [\x10-\x1f]
             * The second byte onward is remaining-length + payload;
             * capture everything after the first byte as fields. */
            unsigned char lo = (unsigned char)(nibble << 4);
            unsigned char hi = (unsigned char)(lo | 0x0F);
            snprintf(header_pattern, sizeof(header_pattern),
                     "^[\\x%02x-\\x%02x]", lo, hi);
            snprintf(fields_pattern, sizeof(fields_pattern),
                     "(?s)(.+)");
        } else {
            /* ------- Text protocol pattern (SIP / FTP / HTTP …) ------- */
            char *escaped = escape_for_regex(hyp->message_type);
            snprintf(header_pattern, sizeof(header_pattern),
                     "^%s(?:[ \\t].*)?\\r?\\n", escaped);
            ck_free(escaped);
            snprintf(fields_pattern, sizeof(fields_pattern),
                     "(?s)(.*)");
        }

        int errornumber;
        size_t erroroffset;

        pcre2_code *p_header = pcre2_compile(
            (PCRE2_SPTR)header_pattern, PCRE2_ZERO_TERMINATED,
            0, &errornumber, &erroroffset, NULL);
        if (!p_header) {
            fprintf(stderr,
                    "[hyp-adapter] Failed to compile header regex for %s "
                    "pattern=\"%s\" (err %d offset %zu)\n",
                    hyp->message_type, header_pattern,
                    errornumber, erroroffset);
            continue;
        }
        pcre2_jit_compile(p_header, PCRE2_JIT_COMPLETE);

        pcre2_code *p_fields = pcre2_compile(
            (PCRE2_SPTR)fields_pattern, PCRE2_ZERO_TERMINATED,
            PCRE2_DOTALL, &errornumber, &erroroffset, NULL);
        if (!p_fields) {
            fprintf(stderr,
                    "[hyp-adapter] Failed to compile fields regex for %s "
                    "(err %d offset %zu)\n",
                    hyp->message_type, errornumber, erroroffset);
            pcre2_code_free(p_header);
            continue;
        }
        pcre2_jit_compile(p_fields, PCRE2_JIT_COMPLETE);

        pcre2_code **patterns = ck_alloc(2 * sizeof(pcre2_code *));
        patterns[0] = p_header;
        patterns[1] = p_fields;

        int discard;
        kh_put(strSet, message_types_set, hyp->message_type, &discard);
        *kl_pushp(rang, protocol_patterns) = patterns;

        fprintf(stderr,
                "[hyp-adapter] Integrated hypothesis '%s' as %s pattern "
                "(header=\"%s\")\n",
                hyp->message_type,
                binary ? "binary" : "text",
                header_pattern);

        /* Write pattern to out_dir for debugging */
        if (out_dir) {
            char *path = alloc_printf("%s/protocol-grammars/hyp-pattern-%zu",
                                      out_dir, i);
            int fd = open(path, O_WRONLY | O_CREAT, 0600);
            if (fd != -1) {
                ck_write(fd, header_pattern, strlen(header_pattern), path);
                ck_write(fd, "\n", 1, path);
                ck_write(fd, fields_pattern, strlen(fields_pattern), path);
                close(fd);
            }
            ck_free(path);
        }

        integrated++;
    }

    fprintf(stderr, "[hyp-adapter] Total integrated hypotheses: %d (%s mode)\n",
            integrated, binary ? "binary" : "text");
    return integrated;
}
