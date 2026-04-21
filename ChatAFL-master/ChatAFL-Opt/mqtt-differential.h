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

/* O8: Maximum brokers in heterogeneous cluster */
#define MQTT_DIFF_MAX_BROKERS 16

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
 * O8: Majority-voting result for N-way heterogeneous comparison.
 *
 * When N >= 3 brokers, majority voting identifies "outlier" brokers
 * whose behavior diverges from the consensus.  This is the primary
 * mechanism for detecting protocol non-compliance bugs — the
 * minority broker is likely violating the MQTT specification.
 * ════════════════════════════════════════════════════════════════════ */
#define MQTT_OUTLIER_MAX 16

typedef struct {
  uint8_t  is_outlier[MQTT_OUTLIER_MAX];  /* 1 if broker[i] is an outlier     */
  int      outlier_count;                  /* Total number of outlier brokers  */
  int      consensus_count;                /* Brokers in the majority group    */
  uint8_t  consensus_severity;             /* Divergence level of worst outlier*/
  double   consensus_strength;             /* Strength of the worst divergence */
  uint32_t consensus_type_hash;            /* Type-seq hash of majority group  */
  uint32_t consensus_code_hash;            /* Code-seq hash of majority group  */
  uint32_t pattern_hash;                   /* Dedup hash for this vote result  */
} mqtt_majority_vote_t;

/* ════════════════════════════════════════════════════════════════════
 * O8: Forwarding differential result.
 *
 * Compares PUBLISH forwarding behavior across N brokers.  Each broker's
 * forwarding fingerprint (hash of forwarded PUBLISH packets) is compared
 * to determine if brokers agree on message routing, QoS delivery, and
 * retain semantics.
 * ════════════════════════════════════════════════════════════════════ */
typedef struct {
  uint8_t  fwd_outlier[MQTT_OUTLIER_MAX]; /* 1 if broker[i] forwarded differently */
  int      fwd_outlier_count;              /* Brokers with divergent forwarding   */
  int      all_forwarded;                  /* 1 if all brokers forwarded the msg  */
  int      none_forwarded;                 /* 1 if no broker forwarded            */
  uint32_t pattern_hash;                   /* Dedup hash                          */
} mqtt_fwd_diff_result_t;

/* ════════════════════════════════════════════════════════════════════
 * O8: Noncompliance report entry.
 * ════════════════════════════════════════════════════════════════════ */
#define MQTT_NONCOMPLIANCE_DETAIL_LEN 512

typedef struct {
  int      outlier_index;                                     /* Broker index */
  char     outlier_impl[64];                                  /* Broker impl  */
  uint8_t  severity;                                          /* DIV level    */
  double   strength;                                          /* Normalized   */
  char     detail[MQTT_NONCOMPLIANCE_DETAIL_LEN];             /* Description  */
  uint32_t pattern_hash;                                      /* Dedup        */
} mqtt_noncompliance_entry_t;

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
 * O8: Majority-voting N-way comparison.
 *
 * For N >= 3 brokers, identifies the consensus behavior and marks
 * outlier brokers.  For N < 3, falls back to pairwise comparison.
 *
 * Parameters:
 *   fields[]   — parsed response fields per broker
 *   n          — number of brokers
 *   impl_names — array of implementation name strings (can be NULL)
 *   vote       — output: majority voting result
 *
 * Returns: worst-case mqtt_diff_result_t (same as mqtt_diff_compare_n)
 * ════════════════════════════════════════════════════════════════════ */
mqtt_diff_result_t mqtt_diff_majority_vote(
    const mqtt_response_fields_t *fields, int n,
    const char **impl_names,
    mqtt_majority_vote_t *vote);

/* O8: Compare forwarding hashes across N brokers with majority voting.
 *
 * Parameters:
 *   fwd_hashes[] — per-broker forwarding fingerprint (from mp_driver)
 *   n            — number of brokers
 *   result       — output: forwarding differential result
 */
void mqtt_diff_fwd_majority_vote(
    const uint32_t *fwd_hashes, int n,
    mqtt_fwd_diff_result_t *result);

/* O8: Score adjustment for cross-implementation divergence.
 * If the outlier has a different impl_name than the consensus,
 * the raw score is boosted by MQTT_CROSS_IMPL_BOOST_FACTOR.
 * Returns adjusted score (0-100). */
#define MQTT_CROSS_IMPL_BOOST_FACTOR 1.5
int mqtt_diff_score_cross_impl(
    const mqtt_diff_result_t *r,
    const mqtt_majority_vote_t *vote,
    const char **impl_names, int n);

/* O8: Build a noncompliance entry from a majority vote outlier.
 * Returns 1 if entry was populated, 0 if no outlier found. */
int mqtt_diff_build_noncompliance(
    const mqtt_majority_vote_t *vote,
    const mqtt_diff_result_t *worst_pair,
    const char **impl_names, int n,
    mqtt_noncompliance_entry_t *out);

#endif /* __MQTT_DIFFERENTIAL_H */
