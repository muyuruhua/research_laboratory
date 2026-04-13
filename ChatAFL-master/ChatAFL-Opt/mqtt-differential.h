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
 *   G-fields → pkt_types[] + return_codes[] (protocol-semantic)
 *   H-fields → payload_hashes[] (implementation-behavioral)
 *
 * Combined hashes allow O(1) equality checks before field-by-field diff.
 * ════════════════════════════════════════════════════════════════════ */
typedef struct {
  uint8_t  pkt_types[MQTT_DIFF_MAX_PACKETS];     /* Packet type nibbles (upper 4 bits of byte 0) */
  uint8_t  return_codes[MQTT_DIFF_MAX_PACKETS];   /* Return/reason codes from variable header     */
  uint32_t payload_hashes[MQTT_DIFF_MAX_PACKETS];  /* FNV-1a hash of packet payload bytes          */
  int      pkt_count;                              /* Number of packets successfully parsed        */
  uint32_t type_seq_hash;   /* Combined FNV-1a of all pkt_types — G-field fingerprint */
  uint32_t code_seq_hash;   /* Combined FNV-1a of all return_codes                    */
  uint32_t full_hash;       /* Combined FNV-1a of types+codes+payloads                */
} mqtt_response_fields_t;

/* ════════════════════════════════════════════════════════════════════
 * Divergence result from comparing two broker responses
 * ════════════════════════════════════════════════════════════════════ */
typedef struct {
  uint8_t  severity;        /* MQTT_DIV_* level — highest divergence detected       */
  double   strength;        /* Normalized divergence strength [0.0, 1.0]            */
  int      type_diffs;      /* Count of packet slots with different types           */
  int      code_diffs;      /* Count of packet slots with different return codes    */
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

#endif /* __MQTT_DIFFERENTIAL_H */
