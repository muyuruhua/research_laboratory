/* mqtt-generate.h — MQTT v3.1.1 / v5 structured packet generator.
 *
 * Generates structurally valid and semi-valid MQTT packets for fuzzing,
 * including v5-specific features: Properties, AUTH, enhanced DISCONNECT,
 * subscription options (No Local, Retain Handling), Topic Alias, etc.
 *
 * All functions are protocol-gated: only called when -P MQTT.
 * Zero impact on other text protocols.
 */

#ifndef _MQTT_GENERATE_H
#define _MQTT_GENERATE_H

#include "types.h"

/* ── Constants ── */
#define MQTG_MAX_PKT     2048   /* Max single generated packet */
#define MQTG_PROTO_V311   4
#define MQTG_PROTO_V5     5

/* ── Packet type constants ── */
#define MQTG_CONNECT      1
#define MQTG_CONNACK      2
#define MQTG_PUBLISH      3
#define MQTG_PUBACK       4
#define MQTG_PUBREC       5
#define MQTG_PUBREL       6
#define MQTG_PUBCOMP      7
#define MQTG_SUBSCRIBE    8
#define MQTG_SUBACK       9
#define MQTG_UNSUBSCRIBE  10
#define MQTG_UNSUBACK     11
#define MQTG_PINGREQ      12
#define MQTG_PINGRESP     13
#define MQTG_DISCONNECT   14
#define MQTG_AUTH         15

/* ── Generation API ── */

/* Generate a single structured MQTT packet.
 * proto_ver: MQTG_PROTO_V311 (4), MQTG_PROTO_V5 (5), or 0 (random).
 * pkt_type:  MQTG_xxx (1-15), or 0 (random client-sendable type).
 * Returns length written to buf, or 0 on failure. */
u32 mqtt_gen_packet(u8 *buf, u32 cap, u8 proto_ver, u8 pkt_type);

/* Generate a complete MQTT message sequence:
 *   CONNECT + msg_count random messages + DISCONNECT.
 * Returns total bytes written, 0 on failure. */
u32 mqtt_gen_sequence(u8 *buf, u32 cap, u8 proto_ver, u32 msg_count);

/* Generate v5-specific seed files in seed_dir.
 * Called from enrich_testcases() to add v5 starting points.
 * Returns number of seed files created. */
u32 mqtt_generate_v5_seeds(const char *seed_dir);

#endif /* _MQTT_GENERATE_H */
