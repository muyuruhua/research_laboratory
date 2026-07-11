/* mqtt-builder.c
 * Fix-13: MQTT binary packet builder for seed enrichment.
 *
 * Generates valid MQTT v3.1.1 and v5 packets programmatically, bypassing the
 * LLM-based grammar pipeline which cannot handle binary protocols.
 *
 * Sync MBFuzzer: Added MQTT v5 support (AUTH, Properties, enhanced DISCONNECT,
 * subscription options) to match MBFuzzer's protocol coverage.
 *
 * Design principles:
 *   - Each builder allocates and returns a complete packet buffer
 *   - Remaining Length uses proper variable-length encoding (§2.2.3)
 *   - Client IDs, topics, and payloads are parameterizable for diversity
 *   - Integration functions provide drop-in replacements for the
 *     LLM grammar/enrichment paths
 *   - v5 properties follow MQTT §2.2.2 (Property Length + Properties)
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
#include <ctype.h>

#include "mqtt-builder.h"
#include "hypothesis-adapter.h"
#include "alloc-inl.h"
#include "rfc-knowledge.h"

/* Forward declarations for helpers defined later in this file. */
static int decode_remaining_length(const unsigned char *buf, size_t buf_len, size_t *pos);
static unsigned char *build_packet_by_type(const char *type_name,
                                           int variant_idx,
                                           int has_will,
                                           int has_auth,
                                           size_t *out_len);

/* ============================================
 * MQTT official-spec-derived state model
 * ============================================ */

static int g_mqtt_spec_model_ready = 0;
static unsigned char g_mqtt_type_known[16];
static unsigned char g_mqtt_role_map[16];          /* 0=ctrl,1=sub,2=pub */
static unsigned char g_mqtt_transition[16][16];

static void mqtt_model_add_transition(unsigned char from_t, unsigned char to_t) {
    g_mqtt_transition[from_t & 0x0F][to_t & 0x0F] = 1;
}

static unsigned char mqtt_name_to_type_nibble(const char *name) {
    if (!name) return 0;
    if (strcasecmp(name, "CONNECT") == 0) return 1;
    if (strcasecmp(name, "CONNACK") == 0) return 2;
    if (strcasecmp(name, "PUBLISH") == 0) return 3;
    if (strcasecmp(name, "PUBACK") == 0) return 4;
    if (strcasecmp(name, "PUBREC") == 0) return 5;
    if (strcasecmp(name, "PUBREL") == 0) return 6;
    if (strcasecmp(name, "PUBCOMP") == 0) return 7;
    if (strcasecmp(name, "SUBSCRIBE") == 0) return 8;
    if (strcasecmp(name, "SUBACK") == 0) return 9;
    if (strcasecmp(name, "UNSUBSCRIBE") == 0) return 10;
    if (strcasecmp(name, "UNSUBACK") == 0) return 11;
    if (strcasecmp(name, "PINGREQ") == 0) return 12;
    if (strcasecmp(name, "PINGRESP") == 0) return 13;
    if (strcasecmp(name, "DISCONNECT") == 0) return 14;
    if (strcasecmp(name, "AUTH") == 0) return 15;
    return 0;
}

static void mqtt_apply_structured_state_machine(const char *sm_text) {
    char *copy;
    char *line;
    char *saveptr = NULL;

    if (!sm_text || !*sm_text) return;

    copy = strdup(sm_text);
    if (!copy) return;

    for (line = strtok_r(copy, "\n", &saveptr);
         line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        while (*line && isspace((unsigned char)*line)) line++;
        if (!*line) continue;

        if (strncmp(line, "ROLE ", 5) == 0) {
            char type_name[64] = {0};
            char role_name[16] = {0};
            if (sscanf(line + 5, "%63[^=]=%15s", type_name, role_name) == 2) {
                unsigned char t = mqtt_name_to_type_nibble(type_name);
                if (t) {
                    if (strcasecmp(role_name, "SUB") == 0) g_mqtt_role_map[t] = 1;
                    else if (strcasecmp(role_name, "PUB") == 0) g_mqtt_role_map[t] = 2;
                    else g_mqtt_role_map[t] = 0;
                    g_mqtt_type_known[t] = 1;
                }
            }
            continue;
        }

        if (strncmp(line, "TRANS ", 6) == 0) {
            char from_name[64] = {0};
            char to_name[64] = {0};
            if (sscanf(line + 6, "%63[^-]->%63s", from_name, to_name) == 2) {
                unsigned char from_t = 0;
                unsigned char to_t = mqtt_name_to_type_nibble(to_name);
                if (strcasecmp(from_name, "START") != 0) {
                    from_t = mqtt_name_to_type_nibble(from_name);
                }
                if (to_t) {
                    mqtt_model_add_transition(from_t, to_t);
                    g_mqtt_type_known[to_t] = 1;
                    if (from_t) g_mqtt_type_known[from_t] = 1;
                }
            }
            continue;
        }
    }

    free(copy);
}

/* Build a conservative MQTT transition model from extracted spec commands.
 * Structure is deterministic and executable; availability of commands comes
 * from official OASIS extraction. */
static void mqtt_build_structured_model_from_spec(char **commands, size_t cmd_count) {
    size_t i;

    memset(g_mqtt_type_known, 0, sizeof(g_mqtt_type_known));
    memset(g_mqtt_role_map, 0, sizeof(g_mqtt_role_map));
    memset(g_mqtt_transition, 0, sizeof(g_mqtt_transition));

    /* Roles (protocol semantics): */
    g_mqtt_role_map[3] = 2;   /* PUBLISH */
    g_mqtt_role_map[6] = 2;   /* PUBREL */
    g_mqtt_role_map[8] = 1;   /* SUBSCRIBE */
    g_mqtt_role_map[10] = 1;  /* UNSUBSCRIBE */

    /* Mark known types from spec extraction. */
    for (i = 0; i < cmd_count; i++) {
        unsigned char t = mqtt_name_to_type_nibble(commands[i]);
        if (t) g_mqtt_type_known[t] = 1;
    }

    /* Ensure critical client-emittable types always exist for execution. */
    g_mqtt_type_known[1] = 1;  /* CONNECT */
    g_mqtt_type_known[3] = 1;  /* PUBLISH */
    g_mqtt_type_known[8] = 1;  /* SUBSCRIBE */
    g_mqtt_type_known[10] = 1; /* UNSUBSCRIBE */
    g_mqtt_type_known[12] = 1; /* PINGREQ */
    g_mqtt_type_known[14] = 1; /* DISCONNECT */

    /* Start transitions (0 means start-of-sequence). */
    mqtt_model_add_transition(0, 1); /* start -> CONNECT */
    mqtt_model_add_transition(0, 3); /* start -> PUBLISH (edge/boundary) */

    /* Core client transition skeleton (MQTT 3.1.1 compatible). */
    mqtt_model_add_transition(1, 8);   /* CONNECT -> SUBSCRIBE */
    mqtt_model_add_transition(1, 3);   /* CONNECT -> PUBLISH */
    mqtt_model_add_transition(1, 12);  /* CONNECT -> PINGREQ */
    mqtt_model_add_transition(1, 14);  /* CONNECT -> DISCONNECT */

    mqtt_model_add_transition(8, 8);   /* SUBSCRIBE churn */
    mqtt_model_add_transition(8, 3);   /* SUBSCRIBE -> PUBLISH */
    mqtt_model_add_transition(8, 10);  /* SUBSCRIBE -> UNSUBSCRIBE */
    mqtt_model_add_transition(8, 12);  /* SUBSCRIBE -> PINGREQ */
    mqtt_model_add_transition(8, 14);  /* SUBSCRIBE -> DISCONNECT */

    mqtt_model_add_transition(10, 8);  /* UNSUBSCRIBE -> SUBSCRIBE */
    mqtt_model_add_transition(10, 3);  /* UNSUBSCRIBE -> PUBLISH */
    mqtt_model_add_transition(10, 12); /* UNSUBSCRIBE -> PINGREQ */
    mqtt_model_add_transition(10, 14); /* UNSUBSCRIBE -> DISCONNECT */

    mqtt_model_add_transition(3, 3);   /* PUBLISH stream */
    mqtt_model_add_transition(3, 8);   /* PUBLISH -> SUBSCRIBE */
    mqtt_model_add_transition(3, 12);  /* PUBLISH -> PINGREQ */
    mqtt_model_add_transition(3, 14);  /* PUBLISH -> DISCONNECT */
    mqtt_model_add_transition(3, 6);   /* QoS2 path */

    mqtt_model_add_transition(6, 7);   /* PUBREL -> PUBCOMP */
    mqtt_model_add_transition(6, 3);   /* PUBREL -> PUBLISH */
    mqtt_model_add_transition(6, 12);  /* PUBREL -> PINGREQ */
    mqtt_model_add_transition(6, 14);  /* PUBREL -> DISCONNECT */

    mqtt_model_add_transition(12, 12); /* heartbeat */
    mqtt_model_add_transition(12, 3);
    mqtt_model_add_transition(12, 8);
    mqtt_model_add_transition(12, 10);
    mqtt_model_add_transition(12, 14);

    /* Response-state transitions used in state extraction signature. */
    mqtt_model_add_transition(2, 9);   /* CONNACK -> SUBACK */
    mqtt_model_add_transition(9, 13);  /* SUBACK -> PINGRESP */
    mqtt_model_add_transition(13, 14); /* PINGRESP -> DISCONNECT */
    mqtt_model_add_transition(4, 4);   /* PUBACK stream */
    mqtt_model_add_transition(5, 6);   /* PUBREC -> PUBREL */
    mqtt_model_add_transition(7, 3);   /* PUBCOMP -> next publish */
    mqtt_model_add_transition(11, 12); /* UNSUBACK -> PINGREQ */
}

int mqtt_init_spec_state_model(void) {
    char *rfc_text;
    char **commands;
    char *sm_text;
    size_t cmd_count = 0;

    if (g_mqtt_spec_model_ready) return 1;

    rfc_text = fetch_rfc_text("MQTT");
    if (!rfc_text) {
        /* Build fallback model with empty command set; still deterministic. */
        mqtt_build_structured_model_from_spec(NULL, 0);
        g_mqtt_spec_model_ready = 1;
        fprintf(stderr, "[mqtt-model] OASIS fetch failed, using conservative fallback model\n");
        return 0;
    }

    commands = extract_rfc_commands(rfc_text, "MQTT", &cmd_count);
    mqtt_build_structured_model_from_spec(commands, cmd_count);
    sm_text = extract_rfc_state_machine(rfc_text, "MQTT");
    mqtt_apply_structured_state_machine(sm_text);

    if (commands) {
        for (size_t i = 0; i < cmd_count; i++) free(commands[i]);
        free(commands);
    }
    if (sm_text) free(sm_text);
    free(rfc_text);

    g_mqtt_spec_model_ready = 1;
    fprintf(stderr, "[mqtt-model] initialized from OASIS-derived command set (%zu commands)\n", cmd_count);
    return 1;
}

int mqtt_role_for_packet_type(unsigned char type_nibble) {
    if (!g_mqtt_spec_model_ready) mqtt_init_spec_state_model();
    return g_mqtt_role_map[type_nibble & 0x0F];
}

int mqtt_spec_transition_allowed(unsigned char prev_type, unsigned char next_type) {
    if (!g_mqtt_spec_model_ready) mqtt_init_spec_state_model();
    return g_mqtt_transition[prev_type & 0x0F][next_type & 0x0F] ? 1 : 0;
}

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
 * v5 Property Encoding Helpers (Sync MBFuzzer)
 *
 * MQTT v5 properties use a Property Length (variable byte integer)
 * followed by one or more Property entries, each consisting of an
 * Identifier byte and a value whose format depends on the Identifier.
 * ============================================ */

/* Write a v5 Property Length (variable byte integer) + count placeholder.
 * Returns starting position so caller can back-patch. */
static int v5_prop_start(unsigned char *buf, int buf_cap, int *pos) {
  if (*pos + 1 > buf_cap) return -1;
  buf[(*pos)++] = 0x00;  /* placeholder: property length = 0 */
  return *pos;
}

/* Back-patch the Property Length at prop_start to reflect actual bytes written. */
static void v5_prop_finish(unsigned char *buf, int prop_start, int pos) {
  int prop_len = pos - prop_start;  /* excludes the length byte itself */
  /* For now, property length fits in 1 byte (<128) so just overwrite the placeholder */
  if (prop_len > 0 && prop_len < 128) {
    buf[prop_start - 1] = (unsigned char)(prop_len & 0x7F);
  }
}

/* Add a v5 Byte property (Identifier + 1 byte value). */
static void v5_prop_byte(unsigned char *buf, int buf_cap, int *pos,
                         unsigned char id, unsigned char val) {
  if (*pos + 2 <= buf_cap) {
    buf[(*pos)++] = id;
    buf[(*pos)++] = val;
  }
}

/* Add a v5 Two Byte Integer property (Identifier + 2 byte value). */
static void v5_prop_u16(unsigned char *buf, int buf_cap, int *pos,
                        unsigned char id, uint16_t val) {
  if (*pos + 3 <= buf_cap) {
    buf[(*pos)++] = id;
    buf[(*pos)++] = (unsigned char)((val >> 8) & 0xFF);
    buf[(*pos)++] = (unsigned char)(val & 0xFF);
  }
}

/* Add a v5 Four Byte Integer property (Identifier + 4 byte value). */
static void v5_prop_u32(unsigned char *buf, int buf_cap, int *pos,
                        unsigned char id, uint32_t val) {
  if (*pos + 5 <= buf_cap) {
    buf[(*pos)++] = id;
    buf[(*pos)++] = (unsigned char)((val >> 24) & 0xFF);
    buf[(*pos)++] = (unsigned char)((val >> 16) & 0xFF);
    buf[(*pos)++] = (unsigned char)((val >> 8) & 0xFF);
    buf[(*pos)++] = (unsigned char)(val & 0xFF);
  }
}

/* Add a v5 UTF-8 String property (Identifier + 2-byte length + data). */
static void v5_prop_utf8(unsigned char *buf, int buf_cap, int *pos,
                         unsigned char id, const char *str) {
  size_t slen = str ? strlen(str) : 0;
  if (slen > 65535) slen = 65535;
  if (*pos + 3 + (int)slen <= buf_cap) {
    buf[(*pos)++] = id;
    buf[(*pos)++] = (unsigned char)((slen >> 8) & 0xFF);
    buf[(*pos)++] = (unsigned char)(slen & 0xFF);
    if (slen > 0) {
      memcpy(buf + *pos, str, slen);
      *pos += (int)slen;
    }
  }
}

/* Add a v5 UTF-8 String Pair property (Identifier + key_len + key + val_len + val). */
static void v5_prop_utf8_pair(unsigned char *buf, int buf_cap, int *pos,
                              unsigned char id, const char *key, const char *val) {
  size_t klen = key ? strlen(key) : 0;
  size_t vlen = val ? strlen(val) : 0;
  if (klen > 65535) klen = 65535;
  if (vlen > 65535) vlen = 65535;
  if (*pos + 5 + (int)(klen + vlen) <= buf_cap) {
    buf[(*pos)++] = id;
    buf[(*pos)++] = (unsigned char)((klen >> 8) & 0xFF);
    buf[(*pos)++] = (unsigned char)(klen & 0xFF);
    if (klen > 0) { memcpy(buf + *pos, key, klen); *pos += (int)klen; }
    buf[(*pos)++] = (unsigned char)((vlen >> 8) & 0xFF);
    buf[(*pos)++] = (unsigned char)(vlen & 0xFF);
    if (vlen > 0) { memcpy(buf + *pos, val, vlen); *pos += (int)vlen; }
  }
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

/* ============================================
 * Sync MBFuzzer: v5 Packet Builders
 *
 * MQTT v5 extends packet formats with:
 *   - CONNECT: Properties in variable header + will properties
 *   - DISCONNECT: Reason Code + Properties
 *   - AUTH: Reason Code + Properties (v5 only)
 *   - ACK packets: Reason Code + Properties
 * ============================================ */

/* v5 CONNECT with properties.
 * Protocol Level = 5, adds Session Expiry Interval, Receive Maximum,
 * Maximum Packet Size, Topic Alias Maximum, Request Response Info,
 * Request Problem Info, User Property, Auth Method, Auth Data. */
unsigned char *mqtt_build_connect_v5(const char *client_id,
                                      int clean_start,
                                      uint16_t keepalive,
                                      const char *will_topic,
                                      const char *will_message,
                                      const char *username,
                                      const char *password,
                                      size_t *out_len) {
    unsigned char var_buf[MQTT_MAX_PACKET_SIZE * 2];
    int pos = 0;
    int prop_start;

    /* Variable header: Protocol Name */
    var_buf[pos++] = 0x00; var_buf[pos++] = 0x04;
    var_buf[pos++] = 'M'; var_buf[pos++] = 'Q';
    var_buf[pos++] = 'T'; var_buf[pos++] = 'T';

    /* Protocol Level: 5 = MQTT v5.0 */
    var_buf[pos++] = 0x05;

    /* Connect Flags */
    unsigned char flags = 0;
    if (clean_start) flags |= 0x02;
    if (will_topic && will_message) {
        flags |= 0x04; /* Will Flag */
    }
    if (username) flags |= 0x80;
    if (password) flags |= 0x40;
    var_buf[pos++] = flags;

    /* Keep Alive */
    var_buf[pos++] = (unsigned char)((keepalive >> 8) & 0xFF);
    var_buf[pos++] = (unsigned char)(keepalive & 0xFF);

    /* v5 Properties — Session Expiry, Receive Max, Max Packet Size,
     * Topic Alias Max, Request Response Info, Request Problem Info,
     * User Property, Auth Method, Auth Data */
    prop_start = v5_prop_start(var_buf, sizeof(var_buf), &pos);
    if (prop_start > 0) {
        v5_prop_u32(var_buf, sizeof(var_buf), &pos, 0x11, 3600);    /* Session Expiry Interval */
        v5_prop_u16(var_buf, sizeof(var_buf), &pos, 0x21, 65535);   /* Receive Maximum */
        v5_prop_u32(var_buf, sizeof(var_buf), &pos, 0x27, 268435455);/* Maximum Packet Size */
        v5_prop_u16(var_buf, sizeof(var_buf), &pos, 0x22, 10);      /* Topic Alias Maximum */
        v5_prop_byte(var_buf, sizeof(var_buf), &pos, 0x19, 0);      /* Request Response Info */
        v5_prop_byte(var_buf, sizeof(var_buf), &pos, 0x17, 1);      /* Request Problem Info */
        v5_prop_utf8_pair(var_buf, sizeof(var_buf), &pos, 0x26, "mbfuzzer_sync", "v5"); /* User Property */
        v5_prop_finish(var_buf, prop_start, pos);
    }

    /* Payload: Client Identifier */
    pos += write_mqtt_string(var_buf + pos, client_id ? client_id : "fuzz_v5");

    /* v5 Will Properties (if will flag set) */
    if (will_topic && will_message) {
        int wp_start = v5_prop_start(var_buf, sizeof(var_buf), &pos);
        if (wp_start > 0) {
            v5_prop_u32(var_buf, sizeof(var_buf), &pos, 0x18, 0);   /* Will Delay Interval */
            v5_prop_byte(var_buf, sizeof(var_buf), &pos, 0x01, 0);  /* Payload Format Indicator */
            v5_prop_u32(var_buf, sizeof(var_buf), &pos, 0x02, 3600);/* Message Expiry Interval */
            v5_prop_utf8(var_buf, sizeof(var_buf), &pos, 0x03, "text/plain"); /* Content Type */
            v5_prop_utf8(var_buf, sizeof(var_buf), &pos, 0x08, "response/topic"); /* Response Topic */
            v5_prop_finish(var_buf, wp_start, pos);
        }
        pos += write_mqtt_string(var_buf + pos, will_topic);
        pos += write_mqtt_string(var_buf + pos, will_message);
    }

    if (username) pos += write_mqtt_string(var_buf + pos, username);
    if (password) pos += write_mqtt_string(var_buf + pos, password);

    return build_packet(MQTT_CONNECT, var_buf, pos, out_len);
}

/* v5 AUTH — Authentication exchange packet (MQTT v5 only).
 * Used for enhanced authentication beyond simple username/password.
 * MBFuzzer equivalent: generators/auth.py */
unsigned char *mqtt_build_auth(unsigned char reason_code,
                                const char *auth_method,
                                const char *auth_data,
                                size_t *out_len) {
    unsigned char var_buf[MQTT_MAX_PACKET_SIZE];
    int pos = 0;
    int prop_start;

    /* Reason Code: 0x00=Success, 0x18=Continue authentication, 0x19=Re-authenticate */
    var_buf[pos++] = reason_code;

    /* Properties: Authentication Method (0x15, required), Auth Data (0x16, optional) */
    prop_start = v5_prop_start(var_buf, sizeof(var_buf), &pos);
    if (prop_start > 0) {
        v5_prop_utf8(var_buf, sizeof(var_buf), &pos, 0x15,
                     auth_method ? auth_method : "SCRAM-SHA-256");
        if (auth_data && *auth_data) {
            v5_prop_utf8(var_buf, sizeof(var_buf), &pos, 0x16, auth_data);
        }
        v5_prop_finish(var_buf, prop_start, pos);
    }

    return build_packet(MQTT_AUTH, var_buf, pos, out_len);
}

/* v5 DISCONNECT with Reason Code + Properties.
 * MBFuzzer equivalent: generators/disconnect.py with reason codes. */
unsigned char *mqtt_build_disconnect_v5(unsigned char reason_code, size_t *out_len) {
    unsigned char var_buf[MQTT_MAX_PACKET_SIZE];
    int pos = 0;
    int prop_start;

    /* Reason Code */
    var_buf[pos++] = reason_code;

    /* Properties: Session Expiry Interval, Reason String, User Property */
    prop_start = v5_prop_start(var_buf, sizeof(var_buf), &pos);
    if (prop_start > 0) {
        v5_prop_u32(var_buf, sizeof(var_buf), &pos, 0x11, 0);       /* Session Expiry Interval */
        v5_prop_utf8(var_buf, sizeof(var_buf), &pos, 0x1f, "normal"); /* Reason String */
        v5_prop_finish(var_buf, prop_start, pos);
    }

    return build_packet(MQTT_DISCONNECT, var_buf, pos, out_len);
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

    /* Template 12: Reconnect edge — exercise session boundaries */
    {"reconnect_edge", 5,
     {"CONNECT", "DISCONNECT", "CONNECT", "PINGREQ", "DISCONNECT"}},

    /* Template 13: Out-of-order MQTT interaction edges */
    {"preconnect_boundary", 5,
     {"PUBLISH", "SUBSCRIBE", "CONNECT", "PINGREQ", "DISCONNECT"}},

    /* Template 14: QoS 2 handshake boundary */
    {"qos2_ack_boundary", 6,
     {"CONNECT", "PUBLISH", "PUBREC", "PUBREL", "PUBCOMP", "DISCONNECT"}},

    /* Template 15: Topic churn and subscription churn */
    {"topic_churn_boundary", 6,
     {"CONNECT", "SUBSCRIBE", "SUBSCRIBE", "UNSUBSCRIBE", "PUBLISH", "DISCONNECT"}},

    /* Sync MBFuzzer: v5 seed templates exercising v5-only features.
     * These use CONNECT_V5, AUTH, and DISCONNECT_V5 to reach broker
     * code paths that v3.1.1-only seeds can never hit:
     *   - handle__auth() (v5 only — entirely unreachable without this)
     *   - property__read_all() in v5 CONNECT path
     *   - handle__disconnect() with reason code + properties
     *   - subscription options (No Local, Retain Handling) in SUBSCRIBE */
    {"v5_connect_sub_pub", 5,
     {"CONNECT_V5", "SUBSCRIBE", "PUBLISH", "PINGREQ", "DISCONNECT_V5"}},

    {"v5_auth_exchange", 5,
     {"CONNECT_V5", "AUTH", "AUTH", "PINGREQ", "DISCONNECT_V5"}},

    {"v5_pub_properties", 7,
     {"CONNECT_V5", "SUBSCRIBE", "PUBLISH", "PUBLISH", "PUBLISH", "PINGREQ", "DISCONNECT_V5"}},

    {"v5_qos2_flow", 7,
     {"CONNECT_V5", "PUBLISH", "PUBREC", "PUBREL", "PUBCOMP", "PINGREQ", "DISCONNECT_V5"}},

    {"v5_disconnect_reason", 4,
     {"CONNECT_V5", "SUBSCRIBE", "PUBLISH", "DISCONNECT_V5"}},

    {"v5_mixed_full", 8,
     {"CONNECT_V5", "SUBSCRIBE", "PUBLISH", "AUTH", "UNSUBSCRIBE", "PUBLISH", "PINGREQ", "DISCONNECT_V5"}},

    {"v5_reconnect_edge", 5,
     {"CONNECT_V5", "DISCONNECT_V5", "CONNECT_V5", "PINGREQ", "DISCONNECT_V5"}},

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

/* ============================================
 * Auto-extracted multi-party interaction model
 *
 * Goal: push MQTT seed generation beyond fixed templates by learning
 * packet-transition and role-transition rules from existing corpus seeds.
 * This approximates MBFuzzer-style full interaction modeling:
 *   1) automatically extract message-transition rules from real traces
 *   2) infer role transitions (controller / subscriber / publisher)
 *   3) synthesize new high-probability interaction sequences
 * ============================================ */

typedef enum {
    MQTT_ROLE_CTRL = 0,
    MQTT_ROLE_SUB  = 1,
    MQTT_ROLE_PUB  = 2,
    MQTT_ROLE_MAX  = 3
} mqtt_role_t;

typedef struct {
    uint32_t type_freq[16];
    uint32_t type_trans[16][16];
    uint32_t role_freq[MQTT_ROLE_MAX];
    uint32_t role_trans[MQTT_ROLE_MAX][MQTT_ROLE_MAX];
    uint32_t sequence_count;
    uint32_t packet_count;
} mqtt_interaction_model_t;

static mqtt_role_t mqtt_type_to_role(unsigned char type_nibble) {
    switch (type_nibble) {
        case 3:  /* PUBLISH */
        case 6:  /* PUBREL */
            return MQTT_ROLE_PUB;
        case 8:  /* SUBSCRIBE */
        case 10: /* UNSUBSCRIBE */
            return MQTT_ROLE_SUB;
        default:
            return MQTT_ROLE_CTRL;
    }
}

/* Parse a raw MQTT seed and extract packet-type nibble sequence.
 * Returns number of packet types extracted. */
static int mqtt_extract_type_sequence(const unsigned char *buf, size_t buf_len,
                                      unsigned char *types, int max_types) {
    size_t pos = 0;
    int count = 0;
    if (!buf || !types || max_types <= 0) return 0;

    while (pos < buf_len && count < max_types) {
        int rem;
        size_t hdr_pos;
        size_t pkt_end;

        if (pos + 2 > buf_len) break;
        types[count++] = (unsigned char)(buf[pos] >> 4);
        pos++;

        hdr_pos = pos;
        rem = decode_remaining_length(buf, buf_len, &pos);
        if (rem < 0) break;
        pkt_end = pos + (size_t)rem;

        if (pkt_end <= hdr_pos || pkt_end > buf_len) {
            break;
        }
        pos = pkt_end;
    }

    return count;
}

static void mqtt_model_update_from_sequence(mqtt_interaction_model_t *m,
                                            const unsigned char *types,
                                            int n) {
    int i;
    if (!m || !types || n <= 0) return;

    m->sequence_count++;
    m->packet_count += (uint32_t)n;

    for (i = 0; i < n; i++) {
        unsigned char t = types[i] & 0x0F;
        mqtt_role_t r = mqtt_type_to_role(t);
        m->type_freq[t]++;
        m->role_freq[r]++;

        if (i + 1 < n) {
            unsigned char t2 = types[i + 1] & 0x0F;
            mqtt_role_t r2 = mqtt_type_to_role(t2);
            m->type_trans[t][t2]++;
            m->role_trans[r][r2]++;
        }
    }
}

static int mqtt_should_skip_seed_file(const char *name) {
    if (!name || !*name) return 1;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return 1;
    if (strstr(name, "README")) return 1;
    return 0;
}

static int mqtt_learn_interaction_model(const char *in_dir,
                                        mqtt_interaction_model_t *model) {
    DIR *d;
    struct dirent *de;
    int loaded = 0;
    if (!in_dir || !model) return 0;

    memset(model, 0, sizeof(*model));
    d = opendir(in_dir);
    if (!d) return 0;

    while ((de = readdir(d)) != NULL) {
        char *path;
        int fd;
        off_t fsz;
        unsigned char *buf;
        ssize_t rd;
        unsigned char seq[128];
        int nseq;

        if (mqtt_should_skip_seed_file(de->d_name)) continue;

        if (strstr(de->d_name, "enriched_mqtt_model_")) continue;

        if (asprintf(&path, "%s/%s", in_dir, de->d_name) < 0 || !path) continue;
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            free(path);
            continue;
        }
        fsz = lseek(fd, 0, SEEK_END);
        if (fsz <= 0 || fsz > (off_t)(1024 * 1024)) {
            close(fd);
            free(path);
            continue;
        }
        lseek(fd, 0, SEEK_SET);

        buf = (unsigned char *)malloc((size_t)fsz);
        if (!buf) {
            close(fd);
            free(path);
            continue;
        }
        rd = read(fd, buf, (size_t)fsz);
        close(fd);
        free(path);
        if (rd != fsz) {
            free(buf);
            continue;
        }

        nseq = mqtt_extract_type_sequence(buf, (size_t)fsz, seq, (int)(sizeof(seq) / sizeof(seq[0])));
        free(buf);
        if (nseq <= 0) continue;

        mqtt_model_update_from_sequence(model, seq, nseq);
        loaded++;
    }

    closedir(d);
    return loaded;
}

static unsigned char mqtt_pick_next_type(const mqtt_interaction_model_t *m,
                                         unsigned char cur_type,
                                         mqtt_role_t *cur_role) {
    int t;
    uint32_t best = 0;
    unsigned char best_t = 12; /* PINGREQ */

    if (!m) return best_t;

    /* Prefer high-frequency type-transition from current type. */
    for (t = 1; t <= 14; t++) {
        uint32_t score = m->type_trans[cur_type & 0x0F][t & 0x0F];
        if (score > best) {
            best = score;
            best_t = (unsigned char)t;
        }
    }

    /* Fallback to globally frequent type if no transition observed. */
    if (best == 0) {
        for (t = 1; t <= 14; t++) {
            uint32_t score = m->type_freq[t & 0x0F];
            if (score > best) {
                best = score;
                best_t = (unsigned char)t;
            }
        }
    }

    if (cur_role) *cur_role = mqtt_type_to_role(best_t);
    return best_t;
}

static const char *mqtt_type_nibble_to_client_name(unsigned char t) {
    const char *n = mqtt_type_nibble_to_name(t & 0x0F);
    if (!n) return "PINGREQ";
    return n;
}

static unsigned char *build_seed_from_type_sequence(const unsigned char *types,
                                                    int n_types,
                                                    int variant_idx,
                                                    size_t *out_len) {
    unsigned char *seed_buf;
    size_t total = 0;
    int i;

    if (!types || n_types <= 0) {
        *out_len = 0;
        return NULL;
    }

    seed_buf = (unsigned char *)malloc(MQTT_MAX_PACKET_SIZE * (size_t)n_types);
    if (!seed_buf) {
        *out_len = 0;
        return NULL;
    }

    for (i = 0; i < n_types; i++) {
        size_t pkt_len = 0;
        const char *name = mqtt_type_nibble_to_client_name(types[i]);
        unsigned char *pkt = build_packet_by_type(name,
                                                  variant_idx + i,
                                                  (variant_idx % 2),
                                                  (variant_idx % 3 == 0),
                                                  &pkt_len);
        if (pkt && pkt_len > 0) {
            memcpy(seed_buf + total, pkt, pkt_len);
            total += pkt_len;
            free(pkt);
        }
    }

    *out_len = total;
    return seed_buf;
}

static int mqtt_generate_model_based_seeds(const char *in_dir,
                                           const mqtt_interaction_model_t *m) {
    int generated = 0;
    int variant;
    if (!in_dir || !m || m->sequence_count == 0) return 0;

    /* Generate several modeled seeds with different lengths/starts.
     * We explicitly favor multi-party transitions:
     *   CTRL -> SUB -> PUB -> CTRL loops when learned transitions exist. */
    for (variant = 0; variant < 12; variant++) {
        unsigned char seq[12];
        int n = 0;
        size_t seed_len = 0;
        unsigned char *seed;
        char *path;
        int fd;

        unsigned char cur = 1; /* CONNECT as canonical start */
        mqtt_role_t role = mqtt_type_to_role(cur);

        seq[n++] = cur;
        while (n < 8 + (variant % 4)) {
            unsigned char next = mqtt_pick_next_type(m, cur, &role);

            /* Keep modeled sequences client-sensible: skip server-only replies
             * as start packets; allow later for handshake boundaries. */
            if (n == 1 && (next == 2 || next == 9 || next == 11 || next == 13)) {
                next = 8; /* SUBSCRIBE */
            }

            seq[n++] = next;
            cur = next;
        }

        /* Ensure graceful closing interaction. */
        if (n < (int)(sizeof(seq) / sizeof(seq[0])) - 1) {
            seq[n++] = 12; /* PINGREQ */
            seq[n++] = 14; /* DISCONNECT */
        }

        seed = build_seed_from_type_sequence(seq, n, variant * 13, &seed_len);
        if (!seed || seed_len == 0) {
            free(seed);
            continue;
        }

        if (asprintf(&path, "%s/enriched_mqtt_model_auto_v%d.raw", in_dir, variant) < 0 || !path) {
            free(seed);
            continue;
        }

        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            ssize_t wr = write(fd, seed, seed_len);
            close(fd);
            if (wr == (ssize_t)seed_len) {
                generated++;
                fprintf(stderr,
                        "[+] MQTT model seed: %s (%zu bytes, %d packets)\n",
                        path, seed_len, n);
            }
        }

        free(path);
        free(seed);
    }

    return generated;
}

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
    if (strcasecmp(type_name, "AUTH") == 0) {
        return mqtt_build_auth(0x18, "SCRAM-SHA-256", "auth_data_fuzz", out_len);
    }
    if (strcasecmp(type_name, "DISCONNECT_V5") == 0) {
        return mqtt_build_disconnect_v5(0x00, out_len);
    }
    if (strcasecmp(type_name, "CONNECT_V5") == 0) {
        return mqtt_build_connect_v5(
            client, 1, 60,
            has_will ? "will/v5/topic" : NULL,
            has_will ? "will_v5_msg" : NULL,
            has_auth ? "fuzz_v5_user" : NULL,
            has_auth ? "fuzz_v5_pass" : NULL,
            out_len);
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

/* Try to extract MQTT control packet names from official OASIS spec.
 * Returns number of inserted message types. */
static int mqtt_load_types_from_official_spec(khash_t(strSet) *message_types_set) {
    char *rfc_text;
    char **commands;
    size_t cmd_count = 0;
    int inserted = 0;

    if (!message_types_set) return 0;

    rfc_text = fetch_rfc_text("MQTT");
    if (!rfc_text) {
        fprintf(stderr, "[mqtt-builder] OASIS fetch unavailable, fallback to built-in MQTT types\n");
        return 0;
    }

    commands = extract_rfc_commands(rfc_text, "MQTT", &cmd_count);
    if (commands && cmd_count > 0) {
        for (size_t i = 0; i < cmd_count; i++) {
            int absent = 0;
            if (!commands[i] || !*commands[i]) continue;
            if (kh_get(strSet, message_types_set, commands[i]) == kh_end(message_types_set)) {
                char *copy = strdup(commands[i]);
                kh_put(strSet, message_types_set, copy, &absent);
                if (absent) inserted++;
            }
        }
    }

    if (commands) {
        for (size_t i = 0; i < cmd_count; i++) {
            free(commands[i]);
        }
        free(commands);
    }
    free(rfc_text);

    fprintf(stderr, "[mqtt-builder] Extracted %d MQTT message types from official OASIS spec\n", inserted);
    return inserted;
}

int mqtt_setup_hardcoded_grammars(klist_t(rang) *protocol_patterns,
                                   khash_t(strSet) *message_types_set,
                                   const char *out_dir) {
    int count = 0;
    int spec_count = 0;

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

    /* Primary source: official OASIS MQTT spec extraction. */
    spec_count = mqtt_load_types_from_official_spec(message_types_set);

    /* Fallback / completion: ensure critical client types always exist. */
    for (int i = 0; MQTT_CLIENT_TYPES[i]; i++) {
        int absent = 0;
        if (kh_get(strSet, message_types_set, MQTT_CLIENT_TYPES[i]) == kh_end(message_types_set)) {
            char *type_copy = strdup(MQTT_CLIENT_TYPES[i]);
            kh_put(strSet, message_types_set, type_copy, &absent);
            if (absent) count++;
        }
    }

    count += spec_count;

    /* Log the grammar output for consistency with text protocol path */
    if (out_dir) {
        char *grammar_path = NULL;
        asprintf(&grammar_path, "%s/protocol-grammars/llm-grammar-output-mqtt", out_dir);
        if (grammar_path) {
            int fd = open(grammar_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
                const char *header = "# MQTT hardcoded grammars (Fix-13)\n"
                                     "# Binary protocol — LLM grammar generation bypassed\n"
                                     "# Source priority: OASIS MQTT spec extraction + fallback types\n"
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

    fprintf(stderr, "[mqtt-builder] Injected %d MQTT message types (official-spec-first)\n", count);
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

    if (tmpl && tmpl->name) {
        if (strstr(tmpl->name, "reconnect") != NULL ||
            strstr(tmpl->name, "boundary") != NULL ||
            strstr(tmpl->name, "churn") != NULL) {
            has_will = 1;
            has_auth = (variant_idx % 2);
        }
        if (strstr(tmpl->name, "qos2") != NULL) {
            has_auth = 0;
        }
    }

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
    const char *auto_learn_env = getenv("CHATAFL_MQTT_AUTO_LEARN");

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
    for (int t = 0; t < n_templates; t++) {
        const mqtt_seed_template_t *tmpl = &MQTT_SEED_TEMPLATES[t];
        int variants_per_template = 3;

        if (tmpl->name) {
            if (strstr(tmpl->name, "edge") != NULL ||
                strstr(tmpl->name, "boundary") != NULL ||
                strstr(tmpl->name, "reconnect") != NULL ||
                strstr(tmpl->name, "churn") != NULL) {
                variants_per_template = 5;
            } else if (strstr(tmpl->name, "heavy") != NULL ||
                       strstr(tmpl->name, "mixed") != NULL) {
                variants_per_template = 4;
            }
        }

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
            "from %d templates with template-specific variant budgets\n",
            total_enriched, n_templates);

    /* Optional corpus auto-learning path (disabled by default).
     * Default now follows official-spec extraction only. */
    if (auto_learn_env && strcmp(auto_learn_env, "1") == 0) {
        mqtt_interaction_model_t model;
        int learned_files = mqtt_learn_interaction_model(in_dir, &model);
        if (learned_files > 0 && model.packet_count > 0) {
            int modeled = mqtt_generate_model_based_seeds(in_dir, &model);
            total_enriched += modeled;
            fprintf(stderr,
                    "[+] MQTT auto-model: learned from %d seeds, %u packets, generated %d modeled seeds\n",
                    learned_files, model.packet_count, modeled);
        } else {
            fprintf(stderr,
                    "[mqtt-builder] auto-model skipped: insufficient MQTT corpus for rule extraction\n");
        }
    } else {
        fprintf(stderr,
                "[mqtt-builder] auto-model disabled (set CHATAFL_MQTT_AUTO_LEARN=1 to enable)\n");
    }

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
    if (!buf || buf_len == 0) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
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
        case 2: { /* CONNACK */
            unsigned char session_present = 0;
            unsigned char reason_code = 0;
            if (pos + 2 <= pkt_end) {
                session_present = buf[pos++];
                reason_code = buf[pos++];
            }
            text_appendf(&out, &out_len, &cap, "CONNACK SessionPresent=%u ReturnCode=%u\n",
                         session_present & 0x01, reason_code);
            break;
        }
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
        case 9: { /* SUBACK */
            uint16_t pkt_id = 0;
            if (pos + 2 <= pkt_end) {
                pkt_id = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
                pos += 2;
            }
            text_appendf(&out, &out_len, &cap, "SUBACK PacketId=%u", pkt_id);
            if (pos < pkt_end) {
                text_appendf(&out, &out_len, &cap, " ReasonCode=%u", buf[pos]);
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
        case 11: { /* UNSUBACK */
            uint16_t pkt_id = 0;
            if (pos + 2 <= pkt_end) {
                pkt_id = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
                pos += 2;
            }
            text_appendf(&out, &out_len, &cap, "UNSUBACK PacketId=%u", pkt_id);
            if (pos < pkt_end) {
                text_appendf(&out, &out_len, &cap, " ReasonCode=%u", buf[pos]);
            }
            text_appendf(&out, &out_len, &cap, "\n");
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
