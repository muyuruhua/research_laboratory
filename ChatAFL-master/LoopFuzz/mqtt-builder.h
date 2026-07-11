/* mqtt-builder.h
 * Fix-13: MQTT binary packet builder for seed enrichment.
 *
 * The LLM-based grammar/enrichment pipeline assumes text protocols where
 * the LLM can generate "[\"CMD arg\\r\\n\",...]" JSON array templates.
 * For MQTT (binary), the LLM cannot produce valid hex-encoded packet
 * structures, resulting in 0 grammars / 0 enriched seeds.
 *
 * This module provides:
 *   1. Hardcoded MQTT packet builders (CONNECT, PUBLISH, SUBSCRIBE, etc.)
 *   2. A function to generate enriched binary seeds from combinations
 *      of MQTT packet types
 *   3. Integration points for setup_llm_grammars() and enrich_testcases()
 *
 * MQTT v3.1.1 packet format:
 *   Byte 0:  [type(4 bits) | flags(4 bits)]
 *   Byte 1+: Remaining Length (variable-length encoding)
 *   Byte 2+: Variable header + Payload
 */

#ifndef __MQTT_BUILDER_H
#define __MQTT_BUILDER_H

#include <stddef.h>
#include <stdint.h>
#include "khash.h"
#include "klist.h"
#include "chat-llm.h"  /* for klist_t(rang), khash_t(strSet) */

/* ============================================
 * MQTT Packet Type Constants (upper nibble)
 * ============================================ */
#define MQTT_CONNECT     0x10
#define MQTT_CONNACK     0x20
#define MQTT_PUBLISH     0x30
#define MQTT_PUBACK      0x40
#define MQTT_PUBREC      0x50
#define MQTT_PUBREL      0x62
#define MQTT_PUBCOMP     0x70
#define MQTT_SUBSCRIBE   0x82
#define MQTT_SUBACK      0x90
#define MQTT_UNSUBSCRIBE 0xA2
#define MQTT_UNSUBACK    0xB0
#define MQTT_PINGREQ     0xC0
#define MQTT_PINGRESP    0xD0
#define MQTT_DISCONNECT  0xE0
#define MQTT_AUTH        0xF0

/* Maximum size for a single MQTT test packet */
#define MQTT_MAX_PACKET_SIZE 1024

/* ============================================
 * Individual Packet Builders
 * Each returns a malloc'd buffer; caller must free().
 * *out_len is set to the packet length in bytes.
 * ============================================ */

/* CONNECT: client_id, clean_session, keepalive.
 * Optional will_topic/will_message if non-NULL. */
unsigned char *mqtt_build_connect(const char *client_id,
                                  int clean_session,
                                  uint16_t keepalive,
                                  const char *will_topic,
                                  const char *will_message,
                                  const char *username,
                                  const char *password,
                                  size_t *out_len);

/* PUBLISH: topic, payload, QoS (0/1/2), retain, packet_id (for QoS>0) */
unsigned char *mqtt_build_publish(const char *topic,
                                  const unsigned char *payload,
                                  size_t payload_len,
                                  int qos,
                                  int retain,
                                  uint16_t packet_id,
                                  size_t *out_len);

/* SUBSCRIBE: topic_filter, requested QoS, packet_id */
unsigned char *mqtt_build_subscribe(const char *topic_filter,
                                     int qos,
                                     uint16_t packet_id,
                                     size_t *out_len);

/* UNSUBSCRIBE: topic_filter, packet_id */
unsigned char *mqtt_build_unsubscribe(const char *topic_filter,
                                       uint16_t packet_id,
                                       size_t *out_len);

/* PINGREQ: fixed 2-byte packet */
unsigned char *mqtt_build_pingreq(size_t *out_len);

/* DISCONNECT: fixed 2-byte packet */
unsigned char *mqtt_build_disconnect(size_t *out_len);

/* Sync MBFuzzer: v5 packet builders
 * CONNECT_V5: adds Session Expiry, Receive Max, Max Packet Size,
 *   Topic Alias Max, Request Response/Problem Info, User Property.
 * AUTH: v5-only authentication exchange with reason code + auth method.
 * DISCONNECT_V5: enhanced disconnect with reason code + properties. */
unsigned char *mqtt_build_connect_v5(const char *client_id,
                                      int clean_start,
                                      uint16_t keepalive,
                                      const char *will_topic,
                                      const char *will_message,
                                      const char *username,
                                      const char *password,
                                      size_t *out_len);
unsigned char *mqtt_build_auth(unsigned char reason_code,
                                const char *auth_method,
                                const char *auth_data,
                                size_t *out_len);
unsigned char *mqtt_build_disconnect_v5(unsigned char reason_code, size_t *out_len);

/* PUBACK/PUBREC/PUBREL/PUBCOMP: packet_id */
unsigned char *mqtt_build_puback(uint16_t packet_id, size_t *out_len);
unsigned char *mqtt_build_pubrec(uint16_t packet_id, size_t *out_len);
unsigned char *mqtt_build_pubrel(uint16_t packet_id, size_t *out_len);
unsigned char *mqtt_build_pubcomp(uint16_t packet_id, size_t *out_len);

/* ============================================
 * High-Level Integration Functions
 * ============================================ */

/* Generate hardcoded MQTT grammar entries and inject them into
 * protocol_patterns and message_types_set.
 * Called from setup_llm_grammars() when protocol_name == "MQTT".
 * Returns number of patterns added. */
int mqtt_setup_hardcoded_grammars(klist_t(rang) *protocol_patterns,
                                   khash_t(strSet) *message_types_set,
                                   const char *out_dir);

/* Generate enriched MQTT seed files from existing seed(s).
 * Called from enrich_testcases() when protocol_name == "MQTT".
 * Reads seeds from in_dir, writes enriched seeds back to in_dir.
 * Returns number of enriched seeds generated. */
int mqtt_enrich_seeds(const char *in_dir,
                      khash_t(strSet) *message_types_set);

/* ============================================
 * Binary ↔ Text Conversion for LLM Integration
 *
 * The LLM cannot read/write raw binary MQTT packets.
 * These functions convert between binary and a human-readable
 * text representation so the LLM enrichment pipeline can work.
 *
 * Text format (one packet per line):
 *   CONNECT ClientId=fuzz_client CleanSession=1 KeepAlive=60
 *   SUBSCRIBE PacketId=1 Topic=test/# QoS=0
 *   PUBLISH Topic=test/topic QoS=0 Retain=0 Payload=hello
 *   PINGREQ
 *   DISCONNECT
 * ============================================ */

/* Convert binary MQTT packet buffer to text representation.
 * Returns malloc'd string; caller must free(). */
char *mqtt_binary_to_text(const unsigned char *buf, size_t buf_len);

/* Convert text representation (from LLM) back to binary MQTT packets.
 * Returns malloc'd buffer; caller must free(). Sets *out_len. */
unsigned char *mqtt_text_to_binary(const char *text, size_t *out_len);

/* Extract the MQTT message type name from a binary region.
 * Reads the upper nibble of the first byte at buf[start_byte].
 * Returns a ck_alloc'd string (e.g., "CONNECT") or NULL.
 * Caller must ck_free(). */
char *mqtt_extract_type_from_region(const unsigned char *buf, unsigned int start_byte);

/* ============================================
 * MQTT official-spec state model (OASIS-derived)
 *
 * These APIs expose a protocol model used by:
 *   1) seed generation (state-machine aware sequence construction)
 *   2) runtime multi-party executor routing / transition validation
 *
 * All logic is gated to MQTT call sites only.
 * ============================================ */

/* Initialize in-memory MQTT spec model from OASIS RFC text.
 * Returns 1 on success (or cached already-initialized), 0 on failure. */
int mqtt_init_spec_state_model(void);

/* Return role id for packet type nibble (1..15):
 * 0=controller, 1=subscriber, 2=publisher */
int mqtt_role_for_packet_type(unsigned char type_nibble);

/* Check whether transition prev_type -> next_type is allowed by model.
 * If prev_type==0, this means start-of-sequence transition.
 * Returns 1 if allowed, 0 otherwise. */
int mqtt_spec_transition_allowed(unsigned char prev_type, unsigned char next_type);

#endif /* __MQTT_BUILDER_H */
