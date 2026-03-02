/* mqtt-builder.c
 * Fix-13: MQTT binary packet builder for seed enrichment.
 *
 * Generates valid MQTT v3.1.1 packets programmatically, bypassing the
 * LLM-based grammar pipeline which cannot handle binary protocols.
 *
 * Design principles:
 *   - Each builder allocates and returns a complete packet buffer
 *   - Remaining Length uses proper variable-length encoding (§2.2.3)
 *   - Client IDs, topics, and payloads are parameterizable for diversity
 *   - Integration functions provide drop-in replacements for the
 *     LLM grammar/enrichment paths
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "mqtt-builder.h"
#include "hypothesis-adapter.h"
#include "alloc-inl.h"

/* ============================================
 * Internal helpers
 * ============================================ */

/* Encode MQTT Remaining Length (variable-length, up to 4 bytes).
 * Writes to buf, returns number of bytes written (1-4). */
static int encode_remaining_length(unsigned char *buf, uint32_t length) {
    int i = 0;
    do {
        unsigned char encoded_byte = length % 128;
        length = length / 128;
        if (length > 0)
            encoded_byte |= 0x80;
        buf[i++] = encoded_byte;
    } while (length > 0 && i < 4);
    return i;
}

/* Write a UTF-8 string with 2-byte length prefix (MQTT §1.5.3).
 * Returns total bytes written (2 + string_len). */
static int write_mqtt_string(unsigned char *buf, const char *str) {
    size_t len = str ? strlen(str) : 0;
    if (len > 65535) len = 65535;
    buf[0] = (unsigned char)((len >> 8) & 0xFF);
    buf[1] = (unsigned char)(len & 0xFF);
    if (len > 0)
        memcpy(buf + 2, str, len);
    return 2 + (int)len;
}

/* Allocate a packet from fixed header + variable content.
 * type_flags = first byte (type nibble | flags).
 * payload/payload_len = everything after the fixed header.
 * Returns malloc'd buffer; sets *out_len. */
static unsigned char *build_packet(unsigned char type_flags,
                                    const unsigned char *payload,
                                    size_t payload_len,
                                    size_t *out_len) {
    unsigned char rem_buf[4];
    int rem_len = encode_remaining_length(rem_buf, (uint32_t)payload_len);

    size_t total = 1 + rem_len + payload_len;
    unsigned char *pkt = malloc(total);
    if (!pkt) { *out_len = 0; return NULL; }

    pkt[0] = type_flags;
    memcpy(pkt + 1, rem_buf, rem_len);
    if (payload_len > 0)
        memcpy(pkt + 1 + rem_len, payload, payload_len);

    *out_len = total;
    return pkt;
}

/* ============================================
 * Individual Packet Builders
 * ============================================ */

unsigned char *mqtt_build_connect(const char *client_id,
                                  int clean_session,
                                  uint16_t keepalive,
                                  const char *will_topic,
                                  const char *will_message,
                                  const char *username,
                                  const char *password,
                                  size_t *out_len) {
    unsigned char var_buf[MQTT_MAX_PACKET_SIZE];
    int pos = 0;

    /* Variable header: Protocol Name */
    var_buf[pos++] = 0x00; var_buf[pos++] = 0x04; /* length = 4 */
    var_buf[pos++] = 'M'; var_buf[pos++] = 'Q';
    var_buf[pos++] = 'T'; var_buf[pos++] = 'T';

    /* Protocol Level: 4 = MQTT 3.1.1 */
    var_buf[pos++] = 0x04;

    /* Connect Flags */
    unsigned char flags = 0;
    if (clean_session) flags |= 0x02;
    if (will_topic && will_message) {
        flags |= 0x04; /* Will Flag */
        /* Will QoS = 0 (bits 4-3 = 00) */
    }
    if (username) flags |= 0x80;
    if (password) flags |= 0x40;
    var_buf[pos++] = flags;

    /* Keep Alive */
    var_buf[pos++] = (unsigned char)((keepalive >> 8) & 0xFF);
    var_buf[pos++] = (unsigned char)(keepalive & 0xFF);

    /* Payload: Client Identifier */
    pos += write_mqtt_string(var_buf + pos, client_id ? client_id : "fuzz_client");

    /* Payload: Will Topic + Will Message (if set) */
    if (will_topic && will_message) {
        pos += write_mqtt_string(var_buf + pos, will_topic);
        pos += write_mqtt_string(var_buf + pos, will_message);
    }

    /* Payload: Username */
    if (username) {
        pos += write_mqtt_string(var_buf + pos, username);
    }

    /* Payload: Password */
    if (password) {
        pos += write_mqtt_string(var_buf + pos, password);
    }

    return build_packet(MQTT_CONNECT, var_buf, pos, out_len);
}

unsigned char *mqtt_build_publish(const char *topic,
                                  const unsigned char *payload,
                                  size_t payload_len,
                                  int qos,
                                  int retain,
                                  uint16_t packet_id,
                                  size_t *out_len) {
    unsigned char var_buf[MQTT_MAX_PACKET_SIZE];
    int pos = 0;

    /* Variable header: Topic Name */
    pos += write_mqtt_string(var_buf + pos, topic ? topic : "test/topic");

    /* Packet Identifier (QoS 1 or 2 only) */
    if (qos > 0) {
        var_buf[pos++] = (unsigned char)((packet_id >> 8) & 0xFF);
        var_buf[pos++] = (unsigned char)(packet_id & 0xFF);
    }

    /* Payload */
    if (payload && payload_len > 0) {
        if (pos + payload_len > MQTT_MAX_PACKET_SIZE)
            payload_len = MQTT_MAX_PACKET_SIZE - pos;
        memcpy(var_buf + pos, payload, payload_len);
        pos += payload_len;
    }

    /* First byte flags: DUP=0, QoS, RETAIN */
    unsigned char type_flags = MQTT_PUBLISH;
    type_flags |= ((qos & 0x03) << 1);
    if (retain) type_flags |= 0x01;

    return build_packet(type_flags, var_buf, pos, out_len);
}

unsigned char *mqtt_build_subscribe(const char *topic_filter,
                                     int qos,
                                     uint16_t packet_id,
                                     size_t *out_len) {
    unsigned char var_buf[MQTT_MAX_PACKET_SIZE];
    int pos = 0;

    /* Variable header: Packet Identifier */
    var_buf[pos++] = (unsigned char)((packet_id >> 8) & 0xFF);
    var_buf[pos++] = (unsigned char)(packet_id & 0xFF);

    /* Payload: Topic Filter + Requested QoS */
    pos += write_mqtt_string(var_buf + pos, topic_filter ? topic_filter : "test/#");
    var_buf[pos++] = (unsigned char)(qos & 0x03);

    /* SUBSCRIBE has fixed flags = 0x02 → 0x82 */
    return build_packet(MQTT_SUBSCRIBE, var_buf, pos, out_len);
}

unsigned char *mqtt_build_unsubscribe(const char *topic_filter,
                                       uint16_t packet_id,
                                       size_t *out_len) {
    unsigned char var_buf[MQTT_MAX_PACKET_SIZE];
    int pos = 0;

    /* Variable header: Packet Identifier */
    var_buf[pos++] = (unsigned char)((packet_id >> 8) & 0xFF);
    var_buf[pos++] = (unsigned char)(packet_id & 0xFF);

    /* Payload: Topic Filter */
    pos += write_mqtt_string(var_buf + pos, topic_filter ? topic_filter : "test/#");

    /* UNSUBSCRIBE has fixed flags = 0x02 → 0xA2 */
    return build_packet(MQTT_UNSUBSCRIBE, var_buf, pos, out_len);
}

unsigned char *mqtt_build_pingreq(size_t *out_len) {
    return build_packet(MQTT_PINGREQ, NULL, 0, out_len);
}

unsigned char *mqtt_build_disconnect(size_t *out_len) {
    return build_packet(MQTT_DISCONNECT, NULL, 0, out_len);
}

/* Simple 2-byte-packet-id response packets */
static unsigned char *build_ack_packet(unsigned char type_flags,
                                        uint16_t packet_id,
                                        size_t *out_len) {
    unsigned char var_buf[2];
    var_buf[0] = (unsigned char)((packet_id >> 8) & 0xFF);
    var_buf[1] = (unsigned char)(packet_id & 0xFF);
    return build_packet(type_flags, var_buf, 2, out_len);
}

unsigned char *mqtt_build_puback(uint16_t packet_id, size_t *out_len) {
    return build_ack_packet(MQTT_PUBACK, packet_id, out_len);
}
unsigned char *mqtt_build_pubrec(uint16_t packet_id, size_t *out_len) {
    return build_ack_packet(MQTT_PUBREC, packet_id, out_len);
}
unsigned char *mqtt_build_pubrel(uint16_t packet_id, size_t *out_len) {
    return build_ack_packet(MQTT_PUBREL, packet_id, out_len);
}
unsigned char *mqtt_build_pubcomp(uint16_t packet_id, size_t *out_len) {
    return build_ack_packet(MQTT_PUBCOMP, packet_id, out_len);
}

/* ============================================
 * Seed Template Definitions
 *
 * Each template is a named sequence of MQTT packet types that
 * exercises a particular protocol interaction pattern.
 * ============================================ */

typedef struct {
    const char *name;          /* human-readable name for logging */
    int         n_types;       /* number of packet type names */
    const char *types[12];     /* array of MQTT type names */
} mqtt_seed_template_t;

static const mqtt_seed_template_t MQTT_SEED_TEMPLATES[] = {
    /* Template 0: Basic connect + subscribe + publish QoS 0 */
    {"connect_sub_pub_q0", 5,
     {"CONNECT", "SUBSCRIBE", "PUBLISH", "PINGREQ", "DISCONNECT"}},

    /* Template 1: Connect + multi-subscribe + unsubscribe */
    {"connect_multi_sub_unsub", 6,
     {"CONNECT", "SUBSCRIBE", "SUBSCRIBE", "UNSUBSCRIBE", "PINGREQ", "DISCONNECT"}},

    /* Template 2: Connect + publish QoS 1 flow (PUBACK) */
    {"connect_pub_q1", 5,
     {"CONNECT", "PUBLISH", "PUBACK", "PINGREQ", "DISCONNECT"}},

    /* Template 3: Connect + publish QoS 2 flow (PUBREC/PUBREL/PUBCOMP) */
    {"connect_pub_q2", 7,
     {"CONNECT", "PUBLISH", "PUBREC", "PUBREL", "PUBCOMP", "PINGREQ", "DISCONNECT"}},

    /* Template 4: Will message scenario */
    {"connect_will", 4,
     {"CONNECT", "SUBSCRIBE", "PUBLISH", "DISCONNECT"}},

    /* Template 5: Auth + rapid reconnect */
    {"connect_auth_reconnect", 6,
     {"CONNECT", "DISCONNECT", "CONNECT", "SUBSCRIBE", "PUBLISH", "DISCONNECT"}},

    /* Template 6: Subscribe-heavy (many topics) */
    {"subscribe_heavy", 8,
     {"CONNECT", "SUBSCRIBE", "SUBSCRIBE", "SUBSCRIBE", "SUBSCRIBE", "PUBLISH", "PINGREQ", "DISCONNECT"}},

    /* Template 7: Publish-heavy (many messages) */
    {"publish_heavy", 8,
     {"CONNECT", "SUBSCRIBE", "PUBLISH", "PUBLISH", "PUBLISH", "PUBLISH", "PINGREQ", "DISCONNECT"}},

    /* Template 8: Ping-heavy (keepalive stress) */
    {"ping_heavy", 6,
     {"CONNECT", "PINGREQ", "PINGREQ", "PINGREQ", "PINGREQ", "DISCONNECT"}},

    /* Template 9: Minimal connect-disconnect */
    {"minimal", 2,
     {"CONNECT", "DISCONNECT"}},

    /* Template 10: Username/password auth */
    {"connect_auth", 5,
     {"CONNECT", "SUBSCRIBE", "PUBLISH", "PINGREQ", "DISCONNECT"}},

    /* Template 11: Mixed QoS levels */
    {"mixed_qos", 8,
     {"CONNECT", "SUBSCRIBE", "PUBLISH", "PUBLISH", "PUBLISH", "PUBACK", "PINGREQ", "DISCONNECT"}},

    {NULL, 0, {NULL}}
};

/* Diverse topic names for fuzzing exploration */
static const char *MQTT_TOPICS[] = {
    "test/#",
    "test/topic",
    "$SYS/broker/uptime",
    "$SYS/#",
    "sensor/temp/room1",
    "home/+/status",
    "device/+/telemetry/#",
    "/",
    "",                          /* empty topic — edge case */
    "a/b/c/d/e/f/g/h/i/j",     /* deep nesting */
    "+/+/+",                     /* multi-level wildcard */
    "#",                         /* root wildcard */
    NULL
};

/* Diverse client IDs */
static const char *MQTT_CLIENT_IDS[] = {
    "aflnet_fuzz",
    "client_01",
    "",                          /* zero-length client ID → broker assigns */
    "AAAAAAAAAAAAAAAAAAAAAAAA",  /* long but valid (23 chars) */
    "test-client-with-special!@#$%",
    "c",                         /* minimal */
    NULL
};

/* Sample payloads for PUBLISH */
static const struct {
    const unsigned char *data;
    size_t len;
} MQTT_PAYLOADS[] = {
    {(const unsigned char *)"hello", 5},
    {(const unsigned char *)"{\"temp\":22.5}", 13},
    {(const unsigned char *)"\x00\x01\x02\x03", 4},   /* binary */
    {(const unsigned char *)"", 0},                     /* empty */
    {(const unsigned char *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 104}, /* large */
    {NULL, 0}
};

/* Build a single MQTT packet by type name with parameterized variation.
 * variant_idx controls which client_id/topic/payload variant to use. */
static unsigned char *build_packet_by_type(const char *type_name,
                                            int variant_idx,
                                            int has_will,
                                            int has_auth,
                                            size_t *out_len) {
    /* Count arrays for modular indexing */
    int n_topics = 0;
    while (MQTT_TOPICS[n_topics]) n_topics++;
    int n_clients = 0;
    while (MQTT_CLIENT_IDS[n_clients]) n_clients++;
    int n_payloads = 0;
    /* Count entries: sentinel is {NULL, 0}. Note: {(u8*)"", 0} is a valid
     * empty-payload entry (data != NULL), so we stop only when data == NULL. */
    while (MQTT_PAYLOADS[n_payloads].data != NULL) {
        n_payloads++;
    }
    /* Safety: ensure counts are reasonable */
    if (n_topics < 1) n_topics = 1;
    if (n_clients < 1) n_clients = 1;
    if (n_payloads < 1) n_payloads = 1;

    const char *topic    = MQTT_TOPICS[variant_idx % n_topics];
    const char *client   = MQTT_CLIENT_IDS[variant_idx % n_clients];
    uint16_t   pkt_id    = (uint16_t)(variant_idx + 1); /* 1-based packet ID */
    int        qos       = variant_idx % 3;              /* rotate 0, 1, 2 */

    if (strcasecmp(type_name, "CONNECT") == 0) {
        return mqtt_build_connect(
            client,
            1,       /* clean_session */
            60,      /* keepalive */
            has_will ? "will/topic" : NULL,
            has_will ? "will_msg" : NULL,
            has_auth ? "fuzz_user" : NULL,
            has_auth ? "fuzz_pass" : NULL,
            out_len);
    }
    if (strcasecmp(type_name, "PUBLISH") == 0) {
        int pi = variant_idx % n_payloads;
        return mqtt_build_publish(
            topic,
            MQTT_PAYLOADS[pi].data,
            MQTT_PAYLOADS[pi].len,
            qos,
            variant_idx % 2,  /* retain */
            pkt_id,
            out_len);
    }
    if (strcasecmp(type_name, "SUBSCRIBE") == 0) {
        return mqtt_build_subscribe(topic, qos, pkt_id, out_len);
    }
    if (strcasecmp(type_name, "UNSUBSCRIBE") == 0) {
        return mqtt_build_unsubscribe(topic, pkt_id, out_len);
    }
    if (strcasecmp(type_name, "PINGREQ") == 0) {
        return mqtt_build_pingreq(out_len);
    }
    if (strcasecmp(type_name, "DISCONNECT") == 0) {
        return mqtt_build_disconnect(out_len);
    }
    if (strcasecmp(type_name, "PUBACK") == 0) {
        return mqtt_build_puback(pkt_id, out_len);
    }
    if (strcasecmp(type_name, "PUBREC") == 0) {
        return mqtt_build_pubrec(pkt_id, out_len);
    }
    if (strcasecmp(type_name, "PUBREL") == 0) {
        return mqtt_build_pubrel(pkt_id, out_len);
    }
    if (strcasecmp(type_name, "PUBCOMP") == 0) {
        return mqtt_build_pubcomp(pkt_id, out_len);
    }

    /* Unknown type — return a PINGREQ as fallback */
    fprintf(stderr, "[mqtt-builder] Unknown type '%s', using PINGREQ\n", type_name);
    return mqtt_build_pingreq(out_len);
}

/* ============================================
 * High-Level: Hardcoded Grammar Setup
 * ============================================ */

/* MQTT client-side message type names for IPSM grammar/pattern system.
 * These are the types we inject into message_types_set so the enrichment
 * pipeline knows what message types exist. */
static const char *MQTT_CLIENT_TYPES[] = {
    "CONNECT", "PUBLISH", "SUBSCRIBE", "UNSUBSCRIBE",
    "PINGREQ", "DISCONNECT",
    "PUBACK", "PUBREC", "PUBREL", "PUBCOMP",
    NULL
};

int mqtt_setup_hardcoded_grammars(klist_t(rang) *protocol_patterns,
                                   khash_t(strSet) *message_types_set,
                                   const char *out_dir) {
    int count = 0;

    /*
     * For MQTT, we do NOT create pcre2 text patterns (the text regex
     * approach is meaningless for binary packets).  Instead we populate
     * message_types_set so that:
     *   (a) The enrichment pipeline has types to work with
     *   (b) The hypothesis-adapter can create binary patterns later
     *
     * The protocol_patterns list stays empty for MQTT — the base
     * parse_buffer() will fall through to its "whole buffer = 1 region"
     * graceful degradation, and extract_requests_mqtt() handles the
     * actual region parsing.
     *
     * NOTE: We create one null-pattern entry so protocol_patterns
     * isn't completely empty (prevents potential null-list issues).
     */

    for (int i = 0; MQTT_CLIENT_TYPES[i]; i++) {
        int absent;
        /* kh_put needs a non-const key; strdup it */
        char *type_copy = strdup(MQTT_CLIENT_TYPES[i]);
        kh_put(strSet, message_types_set, type_copy, &absent);
        count++;
    }

    /* Log the grammar output for consistency with text protocol path */
    if (out_dir) {
        char *grammar_path = NULL;
        asprintf(&grammar_path, "%s/protocol-grammars/llm-grammar-output-mqtt", out_dir);
        if (grammar_path) {
            int fd = open(grammar_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
                const char *header = "# MQTT hardcoded grammars (Fix-13)\n"
                                     "# Binary protocol — LLM grammar generation bypassed\n"
                                     "# Client message types:\n";
                write(fd, header, strlen(header));
                for (int i = 0; MQTT_CLIENT_TYPES[i]; i++) {
                    write(fd, "  ", 2);
                    write(fd, MQTT_CLIENT_TYPES[i], strlen(MQTT_CLIENT_TYPES[i]));
                    write(fd, "\n", 1);
                }
                close(fd);
            }
            free(grammar_path);
        }
    }

    fprintf(stderr, "[mqtt-builder] Injected %d MQTT message types (LLM grammar bypassed)\n", count);
    return count;
}

/* ============================================
 * High-Level: MQTT Seed Enrichment
 * ============================================ */

/* Build a complete enriched seed from a template.
 * Returns malloc'd binary buffer; sets *out_len. */
static unsigned char *build_seed_from_template(const mqtt_seed_template_t *tmpl,
                                                int variant_idx,
                                                size_t *out_len) {
    unsigned char *seed_buf = malloc(MQTT_MAX_PACKET_SIZE * tmpl->n_types);
    if (!seed_buf) { *out_len = 0; return NULL; }

    size_t total = 0;
    int has_will = (variant_idx % 3 == 1);   /* 1/3 of variants have will */
    int has_auth = (variant_idx % 4 == 2);   /* 1/4 of variants have auth */

    for (int i = 0; i < tmpl->n_types; i++) {
        size_t pkt_len = 0;
        /* Use different variant for each packet in the sequence */
        unsigned char *pkt = build_packet_by_type(
            tmpl->types[i], variant_idx + i, has_will, has_auth, &pkt_len);

        if (pkt && pkt_len > 0) {
            memcpy(seed_buf + total, pkt, pkt_len);
            total += pkt_len;
            free(pkt);
        }
    }

    *out_len = total;
    return seed_buf;
}

int mqtt_enrich_seeds(const char *in_dir,
                      khash_t(strSet) *message_types_set) {
    int total_enriched = 0;

    /* Count available templates */
    int n_templates = 0;
    while (MQTT_SEED_TEMPLATES[n_templates].name) n_templates++;

    /*
     * Strategy: Generate multiple variants of each template.
     * Each variant uses different client IDs, topics, payloads, QoS levels.
     * This gives the fuzzer diverse starting points for mutation.
     *
     * We generate variants_per_template variants of each template.
     * Total seeds = n_templates × variants_per_template.
     */
    int variants_per_template = 3;  /* 3 variants × 12 templates = 36 seeds */

    for (int t = 0; t < n_templates; t++) {
        const mqtt_seed_template_t *tmpl = &MQTT_SEED_TEMPLATES[t];

        for (int v = 0; v < variants_per_template; v++) {
            size_t seed_len = 0;
            unsigned char *seed = build_seed_from_template(tmpl, v * 7 + t, &seed_len);

            if (!seed || seed_len == 0) {
                free(seed);
                continue;
            }

            /* Write enriched seed file */
            char *file_path = NULL;
            asprintf(&file_path, "%s/enriched_mqtt_%s_v%d.raw",
                     in_dir, tmpl->name, v);
            if (!file_path) {
                free(seed);
                continue;
            }

            int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
                ssize_t written = write(fd, seed, seed_len);
                close(fd);

                if (written == (ssize_t)seed_len) {
                    total_enriched++;
                    fprintf(stderr, "[+] MQTT enriched seed: %s (%zu bytes, %d packets)\n",
                            file_path, seed_len, tmpl->n_types);
                }
            } else {
                fprintf(stderr, "[!] Failed to write MQTT seed: %s\n", file_path);
            }

            free(file_path);
            free(seed);
        }
    }

    fprintf(stderr, "[+] MQTT enrichment complete: generated %d binary seeds "
            "from %d templates × %d variants\n",
            total_enriched, n_templates, variants_per_template);

    return total_enriched;
}

/* ============================================
 * Binary → Text Conversion
 *
 * Decode binary MQTT packets into human-readable text so that
 * the LLM can reason about them.
 * ============================================ */

/* Read a 2-byte length-prefixed UTF-8 string from buf at *pos.
 * Advances *pos.  Returns malloc'd string or NULL. */
static char *read_mqtt_string(const unsigned char *buf, size_t buf_len, size_t *pos) {
    if (*pos + 2 > buf_len) return NULL;
    uint16_t slen = ((uint16_t)buf[*pos] << 8) | buf[*pos + 1];
    *pos += 2;
    if (*pos + slen > buf_len) return NULL;
    char *s = malloc(slen + 1);
    if (!s) return NULL;
    memcpy(s, buf + *pos, slen);
    s[slen] = '\0';
    *pos += slen;
    return s;
}

/* Decode remaining-length at *pos; advance *pos. Returns length, or -1 on error. */
static int decode_remaining_length(const unsigned char *buf, size_t buf_len, size_t *pos) {
    int value = 0, multiplier = 1;
    for (int i = 0; i < 4; i++) {
        if (*pos >= buf_len) return -1;
        unsigned char encoded = buf[(*pos)++];
        value += (encoded & 0x7F) * multiplier;
        if ((encoded & 0x80) == 0) return value;
        multiplier *= 128;
    }
    return -1;  /* malformed */
}

/* Append formatted text to a dynamic buffer. */
static void text_appendf(char **buf, size_t *len, size_t *cap, const char *fmt, ...) {
    va_list ap;
    while (1) {
        va_start(ap, fmt);
        int n = vsnprintf(*buf + *len, *cap - *len, fmt, ap);
        va_end(ap);
        if (n >= 0 && (size_t)n < *cap - *len) {
            *len += n;
            return;
        }
        *cap = (*cap + n + 64) * 2;
        *buf = realloc(*buf, *cap);
        if (!*buf) return;
    }
}

char *mqtt_binary_to_text(const unsigned char *buf, size_t buf_len) {
    size_t cap = 1024, out_len = 0;
    char *out = malloc(cap);
    if (!out) return NULL;
    out[0] = '\0';

    size_t pos = 0;
    while (pos < buf_len) {
        if (pos + 2 > buf_len) break;

        unsigned char byte0 = buf[pos];
        unsigned char type_nibble = byte0 >> 4;
        unsigned char flags = byte0 & 0x0F;
        pos++;

        int rem = decode_remaining_length(buf, buf_len, &pos);
        if (rem < 0) break;

        size_t pkt_end = pos + rem;
        if (pkt_end > buf_len) pkt_end = buf_len;

        const char *type_name = mqtt_type_nibble_to_name(type_nibble);
        if (!type_name) {
            text_appendf(&out, &out_len, &cap, "UNKNOWN_0x%02X\n", byte0);
            pos = pkt_end;
            continue;
        }

        switch (type_nibble) {
        case 1: { /* CONNECT */
            text_appendf(&out, &out_len, &cap, "CONNECT");
            /* Skip protocol name (2+4), protocol level (1) */
            if (pos + 7 <= pkt_end) {
                pos += 6;  /* 00 04 M Q T T */
                pos++;     /* protocol level */
                unsigned char conn_flags = (pos < pkt_end) ? buf[pos++] : 0;
                uint16_t keepalive = 0;
                if (pos + 2 <= pkt_end) {
                    keepalive = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
                    pos += 2;
                }
                int clean  = (conn_flags & 0x02) ? 1 : 0;
                int has_will = (conn_flags & 0x04) ? 1 : 0;
                int has_user = (conn_flags & 0x80) ? 1 : 0;
                int has_pass = (conn_flags & 0x40) ? 1 : 0;

                char *client_id = read_mqtt_string(buf, pkt_end, &pos);
                text_appendf(&out, &out_len, &cap, " ClientId=%s CleanSession=%d KeepAlive=%u",
                             client_id ? client_id : "", clean, keepalive);
                free(client_id);

                if (has_will) {
                    char *will_topic = read_mqtt_string(buf, pkt_end, &pos);
                    char *will_msg   = read_mqtt_string(buf, pkt_end, &pos);
                    text_appendf(&out, &out_len, &cap, " WillTopic=%s WillMsg=%s",
                                 will_topic ? will_topic : "", will_msg ? will_msg : "");
                    free(will_topic); free(will_msg);
                }
                if (has_user) {
                    char *username = read_mqtt_string(buf, pkt_end, &pos);
                    text_appendf(&out, &out_len, &cap, " User=%s", username ? username : "");
                    free(username);
                }
                if (has_pass) {
                    char *password = read_mqtt_string(buf, pkt_end, &pos);
                    text_appendf(&out, &out_len, &cap, " Pass=%s", password ? password : "");
                    free(password);
                }
            }
            text_appendf(&out, &out_len, &cap, "\n");
            break;
        }
        case 3: { /* PUBLISH */
            int qos = (flags >> 1) & 0x03;
            int retain = flags & 0x01;
            char *topic = read_mqtt_string(buf, pkt_end, &pos);
            uint16_t pkt_id = 0;
            if (qos > 0 && pos + 2 <= pkt_end) {
                pkt_id = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
                pos += 2;
            }
            /* Remaining bytes = payload */
            size_t payload_len = (pkt_end > pos) ? pkt_end - pos : 0;
            /* Represent payload: if printable use text, else hex */
            int printable = 1;
            for (size_t i = 0; i < payload_len && i < 128; i++) {
                if (buf[pos + i] < 0x20 && buf[pos + i] != '\t') { printable = 0; break; }
            }
            text_appendf(&out, &out_len, &cap, "PUBLISH Topic=%s QoS=%d Retain=%d",
                         topic ? topic : "", qos, retain);
            if (pkt_id) text_appendf(&out, &out_len, &cap, " PacketId=%u", pkt_id);
            if (payload_len > 0) {
                if (printable) {
                    /* Safe: limit display to 200 chars */
                    int show = payload_len > 200 ? 200 : (int)payload_len;
                    text_appendf(&out, &out_len, &cap, " Payload=%.*s", show, buf + pos);
                } else {
                    text_appendf(&out, &out_len, &cap, " PayloadHex=");
                    int show = payload_len > 32 ? 32 : (int)payload_len;
                    for (int i = 0; i < show; i++)
                        text_appendf(&out, &out_len, &cap, "%02x", buf[pos + i]);
                }
            }
            text_appendf(&out, &out_len, &cap, "\n");
            free(topic);
            break;
        }
        case 8: { /* SUBSCRIBE */
            uint16_t pkt_id = 0;
            if (pos + 2 <= pkt_end) {
                pkt_id = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
                pos += 2;
            }
            char *topic = read_mqtt_string(buf, pkt_end, &pos);
            int qos = (pos < pkt_end) ? buf[pos++] & 0x03 : 0;
            text_appendf(&out, &out_len, &cap, "SUBSCRIBE PacketId=%u Topic=%s QoS=%d\n",
                         pkt_id, topic ? topic : "", qos);
            free(topic);
            break;
        }
        case 10: { /* UNSUBSCRIBE */
            uint16_t pkt_id = 0;
            if (pos + 2 <= pkt_end) {
                pkt_id = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
                pos += 2;
            }
            char *topic = read_mqtt_string(buf, pkt_end, &pos);
            text_appendf(&out, &out_len, &cap, "UNSUBSCRIBE PacketId=%u Topic=%s\n",
                         pkt_id, topic ? topic : "");
            free(topic);
            break;
        }
        case 4: case 5: case 6: case 7: { /* PUBACK/PUBREC/PUBREL/PUBCOMP */
            uint16_t pkt_id = 0;
            if (pos + 2 <= pkt_end) {
                pkt_id = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
                pos += 2;
            }
            text_appendf(&out, &out_len, &cap, "%s PacketId=%u\n", type_name, pkt_id);
            break;
        }
        case 12: /* PINGREQ */
            text_appendf(&out, &out_len, &cap, "PINGREQ\n");
            break;
        case 14: /* DISCONNECT */
            text_appendf(&out, &out_len, &cap, "DISCONNECT\n");
            break;
        default:
            text_appendf(&out, &out_len, &cap, "%s\n", type_name);
            break;
        }
        pos = pkt_end;
    }
    out[out_len] = '\0';
    return out;
}

/* ============================================
 * Text → Binary Conversion
 *
 * Parse the LLM's text output and build binary MQTT packets.
 * ============================================ */

/* Helper: parse key=value from a line, return value for given key.
 * Returns pointer into line (not a copy), or NULL. */
static const char *find_kv(const char *line, const char *key) {
    size_t klen = strlen(key);
    const char *p = line;
    while ((p = strstr(p, key)) != NULL) {
        /* Check that key is preceded by space/tab/start-of-line */
        if (p != line && p[-1] != ' ' && p[-1] != '\t') { p += klen; continue; }
        if (p[klen] == '=') return p + klen + 1;
        p += klen;
    }
    return NULL;
}

/* Extract value string from "Key=value" up to next space or end of line.
 * Returns malloc'd copy. */
static char *extract_kv_str(const char *line, const char *key) {
    const char *v = find_kv(line, key);
    if (!v) return NULL;
    const char *end = v;
    while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n')
        end++;
    size_t len = end - v;
    char *s = malloc(len + 1);
    memcpy(s, v, len);
    s[len] = '\0';
    return s;
}

/* Extract integer value for "Key=123". Returns default_val if not found. */
static int extract_kv_int(const char *line, const char *key, int default_val) {
    const char *v = find_kv(line, key);
    if (!v) return default_val;
    return atoi(v);
}

unsigned char *mqtt_text_to_binary(const char *text, size_t *out_len) {
    if (!text || !*text) { *out_len = 0; return NULL; }

    size_t cap = 4096;
    unsigned char *out = malloc(cap);
    if (!out) { *out_len = 0; return NULL; }
    size_t total = 0;

    const char *line = text;
    int pkt_id_counter = 1;

    while (*line) {
        /* Skip blank lines */
        while (*line == '\r' || *line == '\n') line++;
        if (!*line) break;

        /* Find end of line */
        const char *eol = line;
        while (*eol && *eol != '\r' && *eol != '\n') eol++;
        size_t line_len = eol - line;

        /* Make a NUL-terminated copy for easier parsing */
        char *lcopy = malloc(line_len + 1);
        memcpy(lcopy, line, line_len);
        lcopy[line_len] = '\0';

        unsigned char *pkt = NULL;
        size_t pkt_len = 0;

        if (strncasecmp(lcopy, "CONNECT", 7) == 0) {
            char *cid   = extract_kv_str(lcopy, "ClientId");
            int   clean = extract_kv_int(lcopy, "CleanSession", 1);
            int   ka    = extract_kv_int(lcopy, "KeepAlive", 60);
            char *wt    = extract_kv_str(lcopy, "WillTopic");
            char *wm    = extract_kv_str(lcopy, "WillMsg");
            char *user  = extract_kv_str(lcopy, "User");
            char *pass  = extract_kv_str(lcopy, "Pass");
            pkt = mqtt_build_connect(cid, clean, (uint16_t)ka, wt, wm, user, pass, &pkt_len);
            free(cid); free(wt); free(wm); free(user); free(pass);
        }
        else if (strncasecmp(lcopy, "PUBLISH", 7) == 0) {
            char *topic    = extract_kv_str(lcopy, "Topic");
            int   qos      = extract_kv_int(lcopy, "QoS", 0);
            int   retain   = extract_kv_int(lcopy, "Retain", 0);
            int   pid      = extract_kv_int(lcopy, "PacketId", pkt_id_counter++);
            char *payload  = extract_kv_str(lcopy, "Payload");
            const unsigned char *pdata = (const unsigned char *)(payload ? payload : "");
            size_t plen = payload ? strlen(payload) : 0;
            pkt = mqtt_build_publish(topic, pdata, plen, qos, retain, (uint16_t)pid, &pkt_len);
            free(topic); free(payload);
        }
        else if (strncasecmp(lcopy, "SUBSCRIBE", 9) == 0) {
            char *topic = extract_kv_str(lcopy, "Topic");
            int   qos   = extract_kv_int(lcopy, "QoS", 0);
            int   pid   = extract_kv_int(lcopy, "PacketId", pkt_id_counter++);
            pkt = mqtt_build_subscribe(topic, qos, (uint16_t)pid, &pkt_len);
            free(topic);
        }
        else if (strncasecmp(lcopy, "UNSUBSCRIBE", 11) == 0) {
            char *topic = extract_kv_str(lcopy, "Topic");
            int   pid   = extract_kv_int(lcopy, "PacketId", pkt_id_counter++);
            pkt = mqtt_build_unsubscribe(topic, (uint16_t)pid, &pkt_len);
            free(topic);
        }
        else if (strncasecmp(lcopy, "PUBACK", 6) == 0) {
            int pid = extract_kv_int(lcopy, "PacketId", pkt_id_counter++);
            pkt = mqtt_build_puback((uint16_t)pid, &pkt_len);
        }
        else if (strncasecmp(lcopy, "PUBREC", 6) == 0) {
            int pid = extract_kv_int(lcopy, "PacketId", pkt_id_counter++);
            pkt = mqtt_build_pubrec((uint16_t)pid, &pkt_len);
        }
        else if (strncasecmp(lcopy, "PUBREL", 6) == 0) {
            int pid = extract_kv_int(lcopy, "PacketId", pkt_id_counter++);
            pkt = mqtt_build_pubrel((uint16_t)pid, &pkt_len);
        }
        else if (strncasecmp(lcopy, "PUBCOMP", 7) == 0) {
            int pid = extract_kv_int(lcopy, "PacketId", pkt_id_counter++);
            pkt = mqtt_build_pubcomp((uint16_t)pid, &pkt_len);
        }
        else if (strncasecmp(lcopy, "PINGREQ", 7) == 0) {
            pkt = mqtt_build_pingreq(&pkt_len);
        }
        else if (strncasecmp(lcopy, "DISCONNECT", 10) == 0) {
            pkt = mqtt_build_disconnect(&pkt_len);
        }
        /* else: skip unrecognized lines (LLM commentary, etc.) */

        if (pkt && pkt_len > 0) {
            if (total + pkt_len > cap) {
                cap = (total + pkt_len + 1024) * 2;
                out = realloc(out, cap);
            }
            memcpy(out + total, pkt, pkt_len);
            total += pkt_len;
            free(pkt);
        }

        free(lcopy);
        line = eol;
    }

    *out_len = total;
    if (total == 0) { free(out); return NULL; }
    return out;
}

/* ============================================
 * Helper: extract MQTT type name from binary region
 * ============================================ */
char *mqtt_extract_type_from_region(const unsigned char *buf, unsigned int start_byte) {
    unsigned char type_nibble = buf[start_byte] >> 4;
    const char *name = mqtt_type_nibble_to_name(type_nibble);
    if (!name) return NULL;
    char *copy = ck_alloc(strlen(name) + 1);
    strcpy(copy, name);
    return copy;
}
