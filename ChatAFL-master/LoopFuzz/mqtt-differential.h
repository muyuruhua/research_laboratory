/* mqtt-differential.h — MQTT field-level differential analysis engine.
 *
 * Implements MBFuzzer-style structured response comparison for MQTT:
 *   G-fields: packet type sequence + return/reason codes (protocol semantics)
 *   H-fields: payload content hashes (implementation-specific behavior)
 *
 * Three-tier divergence classification:
 *   MQTT_DIV_TYPE    — brokers produce different packet type sequences
 *   MQTT_DIV_CODE    — same types, different return/reason codes
 *   MQTT_DIV_PAYLOAD — same types+codes, different payload data
 *
 * Theoretical basis (MBFuzzer, ICSE 2025):
 *   Cross-implementation behavioral divergence is a high-value signal
 *   for vulnerability discovery: divergence indicates specification
 *   ambiguity or implementation bugs that single-target coverage alone
 *   cannot detect.
 *
 * Design constraints:
 *   - Zero-cost for non-MQTT protocols (callers gate on protocol_name)
 *   - No heap allocation in hot path (stack-allocated field arrays)
 *   - Bounded parsing: max MQTT_DIFF_MAX_PACKETS per response
 */

#ifndef __MQTT_DIFFERENTIAL_H
#define __MQTT_DIFFERENTIAL_H

#include <stdint.h>

/* Maximum MQTT packets we parse from a single broker response.
 * Bounded to avoid unbounded stack usage in the hot fuzzing loop. */
#define MQTT_DIFF_MAX_PACKETS 64

/* ════════════════════════════════════════════════════════════════════
 * Divergence severity levels (ordered by signal value)
 * ════════════════════════════════════════════════════════════════════ */
#define MQTT_DIV_NONE    0    /* Responses identical (no divergence)     */
#define MQTT_DIV_PAYLOAD 1    /* Same types+codes, different payload     */
#define MQTT_DIV_CODE    2    /* Same type sequence, different ret codes */
#define MQTT_DIV_TYPE    3    /* Different packet type sequences         */
#define MQTT_DIV_MISSING 4    /* One broker responded, other did not     */

/* ════════════════════════════════════════════════════════════════════
 * Parsed MQTT response field summary
 *
 * Corresponds to MBFuzzer's G-field/H-field decomposition:
 *   G-fields → pkt_types[] + return_codes[] + pkt_flags[] (protocol-semantic)
 *   H-fields → payload_hashes[] + var_header_hashes[] (implementation-behavioral)
 *
 * O3: Extended with pkt_flags[] (PUBLISH QoS/DUP/Retain, CONNACK Session
 * Present, v5 SUBACK full return code array hash) and var_header_hashes[]
 * (FNV-1a of variable header bytes) for deeper field-level comparison.
 *
 * Combined hashes allow O(1) equality checks before field-by-field diff.
 * ════════════════════════════════════════════════════════════════════ */
typedef struct {
  uint8_t  pkt_types[MQTT_DIFF_MAX_PACKETS];       /* Packet type nibbles (upper 4 bits of byte 0) */
  uint8_t  return_codes[MQTT_DIFF_MAX_PACKETS];     /* Return/reason codes from variable header     */
  uint8_t  pkt_flags[MQTT_DIFF_MAX_PACKETS];        /* O3: Fixed header flags (lower 4 bits of byte 0)
                                                     *     PUBLISH: DUP(3) QoS(2:1) Retain(0)
                                                     *     CONNACK: var_header[0] = Session Present   */
  uint32_t var_header_hashes[MQTT_DIFF_MAX_PACKETS]; /* O3: FNV-1a of entire variable header bytes   */
  uint32_t payload_hashes[MQTT_DIFF_MAX_PACKETS];    /* FNV-1a hash of packet payload bytes          */
  int      pkt_count;                                /* Number of packets successfully parsed        */
  uint32_t type_seq_hash;   /* Combined FNV-1a of all pkt_types — G-field fingerprint */
  uint32_t code_seq_hash;   /* Combined FNV-1a of all return_codes                    */
  uint32_t flags_hash;      /* O3: Combined FNV-1a of all pkt_flags                   */
  uint32_t full_hash;       /* Combined FNV-1a of types+codes+flags+payloads          */
} mqtt_response_fields_t;

/* ════════════════════════════════════════════════════════════════════
 * Divergence result from comparing two broker responses
 * ════════════════════════════════════════════════════════════════════ */
typedef struct {
  uint8_t  severity;        /* MQTT_DIV_* level — highest divergence detected       */
  double   strength;        /* Normalized divergence strength [0.0, 1.0]            */
  int      type_diffs;      /* Count of packet slots with different types           */
  int      code_diffs;      /* Count of packet slots with different return codes    */
  int      flags_diffs;     /* O3: Count of slots with different pkt_flags          */
  int      var_hdr_diffs;   /* O3: Count of slots with different var_header_hashes  */
  int      payload_diffs;   /* Count of packet slots with different payload hashes  */
  uint32_t pattern_hash;    /* Hash of the divergence pattern (for dedup tracking)  */
} mqtt_diff_result_t;

/* ════════════════════════════════════════════════════════════════════
 * Public API
 * ════════════════════════════════════════════════════════════════════ */

/* Parse a raw MQTT broker response buffer into structured field summary.
 * Handles malformed packets gracefully (skips unparseable bytes).
 * Complexity: O(buf_len), no heap allocation. */
void mqtt_diff_parse_response(const unsigned char *buf, unsigned int buf_len,
                              mqtt_response_fields_t *out);

/* Compare two parsed field summaries, return structured divergence result.
 * Performs three-level comparison: type sequence → return codes → payload.
 * Early-exits when full_hash matches (common case, O(1)).
 * Complexity: O(max_pkt_count) worst case. */
mqtt_diff_result_t mqtt_diff_compare(const mqtt_response_fields_t *a,
                                     const mqtt_response_fields_t *b);

/* Compare N broker responses pairwise, return maximum divergence found.
 * Complexity: O(N^2 * max_pkt_count), but N is typically 2-5. */
mqtt_diff_result_t mqtt_diff_compare_n(const mqtt_response_fields_t *fields,
                                       int n);

/* Compute a divergence score suitable for queue entry annotation.
 * Returns 0-100 based on severity and strength. */
int mqtt_diff_score_from_result(const mqtt_diff_result_t *r);

/* ════════════════════════════════════════════════════════════════════
 * B2: Forwarding-level differential analysis (MBFuzzer-style).
 *
 * Compares PUBLISH forwarding behavior across brokers:
 *   - Did the broker forward the message to subscribers?
 *   - Was the forwarded QoS/retain/topic correct?
 *   - Did bridge/remap alter the topic as expected?
 *
 * This matches MBFuzzer's core "multi-party forwarding differential"
 * where divergence in forwarded messages (not just direct responses)
 * is the primary bug-finding signal for non-compliance bugs.
 * ════════════════════════════════════════════════════════════════════ */

/* Forwarding fingerprint from one broker execution */
typedef struct {
  uint32_t fwd_count;                                    /* Number of forwarded PUBLISHes  */
  uint32_t fwd_topics[MQTT_DIFF_MAX_PACKETS];            /* FNV-1a of each forwarded topic */
  uint8_t  fwd_qos[MQTT_DIFF_MAX_PACKETS];              /* QoS of each forwarded msg      */
  uint8_t  fwd_retain[MQTT_DIFF_MAX_PACKETS];            /* Retain flag                    */
  uint32_t fwd_payload_hashes[MQTT_DIFF_MAX_PACKETS];    /* FNV-1a of each payload         */
  uint32_t combined_hash;                                /* Overall forwarding fingerprint  */
} mqtt_fwd_fields_t;

/* Parse forwarding data (subscriber fd buffer after PUBLISH) into fields. */
void mqtt_diff_parse_forwarding(const unsigned char *fwd_buf, unsigned int fwd_len,
                                mqtt_fwd_fields_t *out);

/* Compare forwarding fields from two brokers.
 * Detects: missing forwards, count mismatch, topic remap divergence,
 * QoS downgrade differences, retain propagation inconsistencies. */
mqtt_diff_result_t mqtt_diff_compare_fwd(const mqtt_fwd_fields_t *a,
                                         const mqtt_fwd_fields_t *b);

#endif /* __MQTT_DIFFERENTIAL_H */
