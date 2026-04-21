/* mqtt-differential.c — MQTT field-level differential analysis engine.
 *
 * Implements structured response parsing and multi-broker comparison
 * following MBFuzzer's G-field/H-field decomposition for MQTT v3.1.1/v5.
 *
 * MQTT packet structure (for reference):
 *   Byte 0:     [Type(4b) | Flags(4b)]
 *   Byte 1..4:  Remaining Length (variable-length encoding, 1-4 bytes)
 *   Variable Header: depends on packet type (contains return codes)
 *   Payload:    type-specific data
 *
 * Return/reason code extraction by packet type:
 *   CONNACK (0x20): byte 1 of variable header (v3.1.1) or byte 2 (v5)
 *   PUBACK  (0x40): v5 only — byte 2 of variable header
 *   SUBACK  (0x90): after packet_id (2 bytes), payload = return codes
 *   UNSUBACK(0xB0): v5 only — after packet_id, payload = reason codes
 *   DISCONNECT(0xE0): v5 only — byte 0 of variable header = reason code
 *
 * No heap allocation — all output is written to caller-provided structs.
 */

#include "mqtt-differential.h"
#include <string.h>
#include <stdio.h>

/* FNV-1a 32-bit hash — fast, well-distributed, no allocation */
static uint32_t fnv1a_32(const unsigned char *data, unsigned int len) {
  uint32_t h = 2166136261u;
  for (unsigned int i = 0; i < len; i++) {
    h ^= data[i];
    h *= 16777619u;
  }
  return h;
}

/* Decode MQTT remaining length (variable-length encoding).
 * Returns decoded value and sets *bytes_consumed.
 * Returns -1 on malformed encoding. */
static int mqtt_diff_decode_remaining_length(const unsigned char *buf,
                                              unsigned int buf_len,
                                              unsigned int *bytes_consumed) {
  int value = 0;
  unsigned int multiplier = 1;
  unsigned int idx = 0;

  if (!buf || buf_len == 0) {
    *bytes_consumed = 0;
    return -1;
  }

  do {
    if (idx >= buf_len || idx >= 4) {
      *bytes_consumed = idx;
      return -1;  /* malformed */
    }
    value += (buf[idx] & 0x7F) * multiplier;
    multiplier *= 128;
    if (multiplier > 128 * 128 * 128 * 128) {
      *bytes_consumed = idx + 1;
      return -1;  /* too many continuation bytes */
    }
  } while ((buf[idx++] & 0x80) != 0);

  *bytes_consumed = idx;
  return value;
}

/* Extract return/reason code from a single MQTT packet's variable header.
 * Returns 0xFF if no return code is applicable for this packet type. */
static uint8_t mqtt_diff_extract_return_code(uint8_t pkt_type_nibble,
                                              const unsigned char *var_header,
                                              unsigned int var_header_len,
                                              const unsigned char *payload,
                                              unsigned int payload_len) {
  switch (pkt_type_nibble) {
  case 2:  /* CONNACK */
    /* v3.1.1: var_header[0]=flags, var_header[1]=return_code
     * v5:     var_header[0]=flags, var_header[1]=reason_code, then properties */
    if (var_header_len >= 2) return var_header[1];
    break;

  case 4:  /* PUBACK */
    /* v3.1.1: var_header = packet_id(2 bytes), no return code
     * v5:     var_header = packet_id(2) + reason_code(1) */
    if (var_header_len >= 3) return var_header[2];
    break;

  case 9:  /* SUBACK */
    /* var_header = packet_id(2 bytes), payload = return codes
     * Return the first return code as representative. */
    if (payload_len >= 1) return payload[0];
    break;

  case 11: /* UNSUBACK */
    /* v5: var_header = packet_id(2), payload = reason codes */
    if (payload_len >= 1) return payload[0];
    break;

  case 14: /* DISCONNECT (v5 only from server) */
    if (var_header_len >= 1) return var_header[0];
    break;

  default:
    break;
  }

  return 0xFF; /* No return code for this type */
}

/* ════════════════════════════════════════════════════════════════════
 * Public: Parse MQTT response into structured field summary
 * ════════════════════════════════════════════════════════════════════ */
void mqtt_diff_parse_response(const unsigned char *buf, unsigned int buf_len,
                              mqtt_response_fields_t *out) {
  unsigned int pos = 0;

  memset(out, 0, sizeof(*out));
  out->pkt_count = 0;

  if (!buf || buf_len == 0) return;

  while (pos < buf_len && out->pkt_count < MQTT_DIFF_MAX_PACKETS) {
    /* Need at least 2 bytes: fixed header byte + remaining length */
    if (pos + 1 >= buf_len) break;

    uint8_t byte0 = buf[pos];
    uint8_t type_nibble = (byte0 >> 4) & 0x0F;

    /* Validate type nibble (1-15 are valid MQTT types, 0 is reserved) */
    if (type_nibble == 0) {
      pos++;  /* Skip invalid byte */
      continue;
    }

    /* Decode remaining length */
    unsigned int rl_bytes = 0;
    int remaining_length = mqtt_diff_decode_remaining_length(
        buf + pos + 1, buf_len - pos - 1, &rl_bytes);

    if (remaining_length < 0) {
      /* Malformed remaining length — skip this byte and try next */
      pos++;
      continue;
    }

    unsigned int header_size = 1 + rl_bytes;
    unsigned int pkt_total = header_size + (unsigned int)remaining_length;

    /* Bounds check: entire packet must fit in buffer */
    if (pos + pkt_total > buf_len) break;

    int idx = out->pkt_count;
    out->pkt_types[idx] = type_nibble;

    /* Determine variable header and payload boundaries.
     * This is type-dependent; for simplicity we use a heuristic:
     * most response packets have 2-byte var header (packet_id) */
    const unsigned char *pkt_body = buf + pos + header_size;
    unsigned int body_len = (unsigned int)remaining_length;

    unsigned int var_header_len = 0;
    unsigned int payload_offset = 0;

    switch (type_nibble) {
    case 2:  /* CONNACK: 2 bytes var header (flags + return_code) */
      var_header_len = (body_len >= 2) ? 2 : body_len;
      payload_offset = var_header_len;
      break;
    case 3:  /* PUBLISH: topic_len(2) + topic + [packet_id(2) if QoS>0] */
      if (body_len >= 2) {
        unsigned int topic_len = ((unsigned int)pkt_body[0] << 8) | pkt_body[1];
        var_header_len = 2 + topic_len;
        /* QoS from flags */
        uint8_t qos = (byte0 >> 1) & 0x03;
        if (qos > 0) var_header_len += 2;
        if (var_header_len > body_len) var_header_len = body_len;
        payload_offset = var_header_len;
      }
      break;
    case 4:  /* PUBACK: packet_id(2) [+ reason_code(1) in v5] */
    case 5:  /* PUBREC */
    case 6:  /* PUBREL */
    case 7:  /* PUBCOMP */
      var_header_len = (body_len >= 2) ? body_len : body_len;
      /* These are all-variable-header, minimal payload */
      payload_offset = body_len;
      break;
    case 9:  /* SUBACK: packet_id(2), payload = return codes */
      var_header_len = (body_len >= 2) ? 2 : body_len;
      payload_offset = var_header_len;
      break;
    case 11: /* UNSUBACK */
      var_header_len = (body_len >= 2) ? 2 : body_len;
      payload_offset = var_header_len;
      break;
    case 13: /* PINGRESP: no variable header or payload */
      var_header_len = 0;
      payload_offset = 0;
      break;
    default:
      /* For other types, treat entire body as variable header */
      var_header_len = body_len;
      payload_offset = body_len;
      break;
    }

    /* Extract return code */
    const unsigned char *payload_ptr = (payload_offset < body_len)
                                       ? pkt_body + payload_offset : NULL;
    unsigned int payload_len = (payload_offset < body_len)
                               ? body_len - payload_offset : 0;

    out->return_codes[idx] = mqtt_diff_extract_return_code(
        type_nibble, pkt_body, var_header_len, payload_ptr, payload_len);

    /* O3: Capture fixed-header flags (lower nibble of byte 0).
     * For CONNACK, overlay Session Present from var_header[0]. */
    out->pkt_flags[idx] = byte0 & 0x0F;
    if (type_nibble == 2 && var_header_len >= 1) {
      /* CONNACK: flags byte = Session Present (bit 0 of var_header[0]) */
      out->pkt_flags[idx] = pkt_body[0] & 0x01;
    }

    /* O3: Hash the entire variable header for deeper comparison. */
    if (var_header_len > 0)
      out->var_header_hashes[idx] = fnv1a_32(pkt_body, var_header_len);
    else
      out->var_header_hashes[idx] = 0;

    /* Hash the payload content (H-field) */
    if (payload_ptr && payload_len > 0)
      out->payload_hashes[idx] = fnv1a_32(payload_ptr, payload_len);
    else
      out->payload_hashes[idx] = 0;

    out->pkt_count++;
    pos += pkt_total;
  }

  /* Compute combined hashes for fast equality check */
  if (out->pkt_count > 0) {
    out->type_seq_hash = fnv1a_32(out->pkt_types, (unsigned int)out->pkt_count);
    out->code_seq_hash = fnv1a_32(out->return_codes, (unsigned int)out->pkt_count);
    /* O3: flags_hash for fixed-header flags comparison */
    out->flags_hash = fnv1a_32(out->pkt_flags, (unsigned int)out->pkt_count);

    /* full_hash = hash of all five field arrays concatenated
     * O3: now includes pkt_flags and var_header_hashes */
    uint32_t h = 2166136261u;
    for (int i = 0; i < out->pkt_count; i++) {
      h ^= out->pkt_types[i];     h *= 16777619u;
      h ^= out->return_codes[i];  h *= 16777619u;
      h ^= out->pkt_flags[i];     h *= 16777619u;  /* O3 */
      h ^= (out->var_header_hashes[i] & 0xFF);         h *= 16777619u;  /* O3 */
      h ^= ((out->var_header_hashes[i] >> 8) & 0xFF);  h *= 16777619u;  /* O3 */
      h ^= (out->payload_hashes[i] & 0xFF);         h *= 16777619u;
      h ^= ((out->payload_hashes[i] >> 8) & 0xFF);  h *= 16777619u;
      h ^= ((out->payload_hashes[i] >> 16) & 0xFF); h *= 16777619u;
      h ^= ((out->payload_hashes[i] >> 24) & 0xFF); h *= 16777619u;
    }
    out->full_hash = h;
  }
}

/* ════════════════════════════════════════════════════════════════════
 * Public: Compare two parsed field summaries
 * ════════════════════════════════════════════════════════════════════ */
mqtt_diff_result_t mqtt_diff_compare(const mqtt_response_fields_t *a,
                                     const mqtt_response_fields_t *b) {
  mqtt_diff_result_t r;
  memset(&r, 0, sizeof(r));

  /* Handle missing responses */
  if (a->pkt_count == 0 && b->pkt_count == 0) {
    r.severity = MQTT_DIV_NONE;
    return r;
  }
  if (a->pkt_count == 0 || b->pkt_count == 0) {
    r.severity = MQTT_DIV_MISSING;
    r.strength = 1.0;
    r.pattern_hash = a->full_hash ^ b->full_hash ^ 0xDEAD;
    return r;
  }

  /* Fast path: if full hashes match, responses are identical */
  if (a->full_hash == b->full_hash && a->pkt_count == b->pkt_count) {
    /* Verify (hash collision is possible but unlikely) */
    int really_equal = 1;
    for (int i = 0; i < a->pkt_count && really_equal; i++) {
      if (a->pkt_types[i] != b->pkt_types[i] ||
          a->return_codes[i] != b->return_codes[i] ||
          a->pkt_flags[i] != b->pkt_flags[i] ||               /* O3 */
          a->var_header_hashes[i] != b->var_header_hashes[i] || /* O3 */
          a->payload_hashes[i] != b->payload_hashes[i])
        really_equal = 0;
    }
    if (really_equal) {
      r.severity = MQTT_DIV_NONE;
      return r;
    }
  }

  /* Level 1: Compare packet type sequences (G-field primary) */
  int min_count = (a->pkt_count < b->pkt_count) ? a->pkt_count : b->pkt_count;
  int max_count = (a->pkt_count > b->pkt_count) ? a->pkt_count : b->pkt_count;

  for (int i = 0; i < min_count; i++) {
    if (a->pkt_types[i] != b->pkt_types[i])
      r.type_diffs++;
  }
  /* Length difference counts as type divergence */
  r.type_diffs += (max_count - min_count);

  if (r.type_diffs > 0) {
    r.severity = MQTT_DIV_TYPE;
    r.strength = (double)r.type_diffs / (double)max_count;
    if (r.strength > 1.0) r.strength = 1.0;
    r.pattern_hash = a->type_seq_hash ^ b->type_seq_hash ^
                     ((uint32_t)a->pkt_count << 16) ^ (uint32_t)b->pkt_count;
    return r;
  }

  /* Level 2: Compare return codes (G-field secondary) */
  for (int i = 0; i < min_count; i++) {
    if (a->return_codes[i] != b->return_codes[i])
      r.code_diffs++;
  }

  if (r.code_diffs > 0) {
    r.severity = MQTT_DIV_CODE;
    r.strength = (double)r.code_diffs / (double)max_count;
    if (r.strength > 1.0) r.strength = 1.0;
    r.pattern_hash = a->code_seq_hash ^ b->code_seq_hash ^
                     ((uint32_t)r.code_diffs << 24);
    return r;
  }

  /* O3 Level 2.5: Compare fixed-header flags (PUBLISH QoS/DUP/Retain,
   * CONNACK Session Present).  Same type+return_code but different flags
   * indicates implementation-specific behavior (e.g., Session Present
   * disagreement, different retained-message delivery). */
  for (int i = 0; i < min_count; i++) {
    if (a->pkt_flags[i] != b->pkt_flags[i])
      r.flags_diffs++;
  }

  if (r.flags_diffs > 0) {
    r.severity = MQTT_DIV_CODE;  /* Same severity tier as return code */
    r.strength = (double)r.flags_diffs / (double)max_count * 0.8;
    if (r.strength > 1.0) r.strength = 1.0;
    r.pattern_hash = a->flags_hash ^ b->flags_hash ^
                     ((uint32_t)r.flags_diffs << 20);
    return r;
  }

  /* O3 Level 2.7: Compare variable header hashes (deeper G-field).
   * Catches property differences, topic length encoding variations,
   * different packet ID assignment strategies. */
  for (int i = 0; i < min_count; i++) {
    if (a->var_header_hashes[i] != b->var_header_hashes[i])
      r.var_hdr_diffs++;
  }

  if (r.var_hdr_diffs > 0) {
    r.severity = MQTT_DIV_PAYLOAD;  /* Slightly below code-level */
    r.strength = (double)r.var_hdr_diffs / (double)max_count * 0.7;
    if (r.strength > 1.0) r.strength = 1.0;
    r.pattern_hash = a->full_hash ^ b->full_hash ^ 0xABCD0000;
    return r;
  }

  /* Level 3: Compare payload hashes (H-field) */
  for (int i = 0; i < min_count; i++) {
    if (a->payload_hashes[i] != b->payload_hashes[i])
      r.payload_diffs++;
  }

  if (r.payload_diffs > 0) {
    r.severity = MQTT_DIV_PAYLOAD;
    r.strength = (double)r.payload_diffs / (double)max_count;
    if (r.strength > 1.0) r.strength = 1.0;
    r.pattern_hash = a->full_hash ^ b->full_hash;
    return r;
  }

  /* No divergence (responses are semantically identical) */
  r.severity = MQTT_DIV_NONE;
  return r;
}

/* ════════════════════════════════════════════════════════════════════
 * Public: Compare N broker responses pairwise
 * ════════════════════════════════════════════════════════════════════ */
mqtt_diff_result_t mqtt_diff_compare_n(const mqtt_response_fields_t *fields,
                                       int n) {
  mqtt_diff_result_t max_r;
  memset(&max_r, 0, sizeof(max_r));

  if (n < 2) return max_r;

  for (int i = 0; i < n; i++) {
    for (int j = i + 1; j < n; j++) {
      mqtt_diff_result_t r = mqtt_diff_compare(&fields[i], &fields[j]);
      if (r.severity > max_r.severity ||
          (r.severity == max_r.severity && r.strength > max_r.strength)) {
        max_r = r;
      }
    }
  }
  return max_r;
}

/* ════════════════════════════════════════════════════════════════════
 * Public: Convert divergence result to queue score (0-100)
 * ════════════════════════════════════════════════════════════════════ */
int mqtt_diff_score_from_result(const mqtt_diff_result_t *r) {
  if (!r) return 0;
  switch (r->severity) {
  case MQTT_DIV_MISSING: return (int)(95 + 5 * r->strength);
  case MQTT_DIV_TYPE:    return (int)(70 + 25 * r->strength);
  case MQTT_DIV_CODE:    return (int)(40 + 30 * r->strength);
  case MQTT_DIV_PAYLOAD: return (int)(10 + 30 * r->strength);
  default:               return 0;
  }
}

/* ════════════════════════════════════════════════════════════════════
 * O8: Majority-voting N-way comparison.
 *
 * Algorithm:
 *   1. Group brokers by their (type_seq_hash, code_seq_hash) fingerprint.
 *   2. The largest group is the "consensus" (majority).
 *   3. Brokers outside the consensus group are "outliers".
 *   4. Each outlier is compared pairwise against a consensus member
 *      to determine the divergence severity and strength.
 *   5. The worst (highest severity) outlier divergence is returned.
 *
 * For N < 3: falls back to standard pairwise comparison (no voting).
 * ════════════════════════════════════════════════════════════════════ */
mqtt_diff_result_t mqtt_diff_majority_vote(
    const mqtt_response_fields_t *fields, int n,
    const char **impl_names,
    mqtt_majority_vote_t *vote) {

  mqtt_diff_result_t worst;
  memset(&worst, 0, sizeof(worst));
  memset(vote, 0, sizeof(*vote));

  if (n < 2) return worst;

  /* For N == 2, fall back to standard pairwise (no majority possible) */
  if (n == 2) {
    worst = mqtt_diff_compare(&fields[0], &fields[1]);
    if (worst.severity > MQTT_DIV_NONE) {
      /* Heuristic: broker[1] is outlier (secondary), broker[0] is primary */
      vote->is_outlier[1] = 1;
      vote->outlier_count = 1;
      vote->consensus_count = 1;
      vote->consensus_severity = worst.severity;
      vote->consensus_strength = worst.strength;
      vote->consensus_type_hash = fields[0].type_seq_hash;
      vote->consensus_code_hash = fields[0].code_seq_hash;
      vote->pattern_hash = worst.pattern_hash;
    } else {
      vote->consensus_count = 2;
    }
    return worst;
  }

  /* Step 1: Compute behavioral fingerprint for each broker.
   * We combine type_seq_hash and code_seq_hash as the grouping key.
   * Brokers in the same group produce identical G-field behavior. */
  uint32_t fingerprints[MQTT_DIFF_MAX_BROKERS];
  int group_id[MQTT_DIFF_MAX_BROKERS];     /* Which group each broker belongs to */
  int group_count[MQTT_DIFF_MAX_BROKERS];  /* Size of each group */
  int num_groups = 0;
  uint32_t group_fp[MQTT_DIFF_MAX_BROKERS]; /* Fingerprint of each group */

  int limit = (n > MQTT_DIFF_MAX_BROKERS) ? MQTT_DIFF_MAX_BROKERS : n;

  for (int i = 0; i < limit; i++) {
    /* Combine type + code + flags hashes into a single fingerprint */
    fingerprints[i] = fields[i].type_seq_hash ^ (fields[i].code_seq_hash * 2654435761u)
                    ^ (fields[i].flags_hash * 40503u);

    /* Handle empty responses specially */
    if (fields[i].pkt_count == 0)
      fingerprints[i] = 0xDEADDEAD;

    /* Find or create group */
    int found = -1;
    for (int g = 0; g < num_groups; g++) {
      if (group_fp[g] == fingerprints[i]) {
        found = g;
        break;
      }
    }
    if (found >= 0) {
      group_id[i] = found;
      group_count[found]++;
    } else {
      group_fp[num_groups] = fingerprints[i];
      group_count[num_groups] = 1;
      group_id[i] = num_groups;
      num_groups++;
    }
  }

  /* Step 2: Find the largest group (consensus) */
  int consensus_group = 0;
  for (int g = 1; g < num_groups; g++) {
    if (group_count[g] > group_count[consensus_group])
      consensus_group = g;
  }

  vote->consensus_count = group_count[consensus_group];
  vote->consensus_type_hash = 0;
  vote->consensus_code_hash = 0;

  /* Find a consensus representative broker */
  int consensus_rep = -1;
  for (int i = 0; i < limit; i++) {
    if (group_id[i] == consensus_group) {
      consensus_rep = i;
      vote->consensus_type_hash = fields[i].type_seq_hash;
      vote->consensus_code_hash = fields[i].code_seq_hash;
      break;
    }
  }

  /* Step 3: Mark outliers and compute divergence vs consensus */
  vote->outlier_count = 0;
  for (int i = 0; i < limit; i++) {
    if (group_id[i] != consensus_group) {
      vote->is_outlier[i] = 1;
      vote->outlier_count++;

      /* Compare this outlier against the consensus representative */
      mqtt_diff_result_t r = mqtt_diff_compare(&fields[consensus_rep], &fields[i]);
      if (r.severity > worst.severity ||
          (r.severity == worst.severity && r.strength > worst.strength)) {
        worst = r;
      }
    }
  }

  vote->consensus_severity = worst.severity;
  vote->consensus_strength = worst.strength;

  /* Step 4: Compute pattern hash for dedup */
  {
    uint32_t h = 2166136261u;
    for (int i = 0; i < limit; i++) {
      h ^= fingerprints[i]; h *= 16777619u;
      h ^= (uint32_t)vote->is_outlier[i]; h *= 16777619u;
    }
    vote->pattern_hash = h;
    if (worst.pattern_hash == 0)
      worst.pattern_hash = h;
  }

  (void)impl_names;  /* Used by callers for reporting, not in core algo */
  return worst;
}

/* ════════════════════════════════════════════════════════════════════
 * O8: Forwarding hash majority voting.
 *
 * Compares per-broker forwarding fingerprints (fwd_hash from mp_driver).
 * Uses the same majority-voting approach: group by hash value, largest
 * group is consensus, others are outliers.
 * ════════════════════════════════════════════════════════════════════ */
void mqtt_diff_fwd_majority_vote(
    const uint32_t *fwd_hashes, int n,
    mqtt_fwd_diff_result_t *result) {

  memset(result, 0, sizeof(*result));
  if (n < 2 || !fwd_hashes) return;

  int limit = (n > MQTT_DIFF_MAX_BROKERS) ? MQTT_DIFF_MAX_BROKERS : n;

  /* Group by fwd_hash value */
  uint32_t group_vals[MQTT_DIFF_MAX_BROKERS];
  int group_counts[MQTT_DIFF_MAX_BROKERS];
  int group_map[MQTT_DIFF_MAX_BROKERS];
  int num_groups = 0;

  /* Track zero-hash (no forwarding) separately */
  int zero_count = 0;
  for (int i = 0; i < limit; i++) {
    if (fwd_hashes[i] == 0) zero_count++;
  }

  for (int i = 0; i < limit; i++) {
    int found = -1;
    for (int g = 0; g < num_groups; g++) {
      if (group_vals[g] == fwd_hashes[i]) {
        found = g; break;
      }
    }
    if (found >= 0) {
      group_map[i] = found;
      group_counts[found]++;
    } else {
      group_vals[num_groups] = fwd_hashes[i];
      group_counts[num_groups] = 1;
      group_map[i] = num_groups;
      num_groups++;
    }
  }

  if (num_groups <= 1) {
    /* All brokers agree on forwarding */
    result->all_forwarded = (zero_count == 0);
    result->none_forwarded = (zero_count == limit);
    return;
  }

  /* Find consensus group */
  int consensus_group = 0;
  for (int g = 1; g < num_groups; g++) {
    if (group_counts[g] > group_counts[consensus_group])
      consensus_group = g;
  }

  /* Mark outliers */
  uint32_t h = 2166136261u;
  for (int i = 0; i < limit; i++) {
    if (group_map[i] != consensus_group) {
      result->fwd_outlier[i] = 1;
      result->fwd_outlier_count++;
    }
    h ^= fwd_hashes[i]; h *= 16777619u;
  }
  result->pattern_hash = h;
  result->all_forwarded = (zero_count == 0);
  result->none_forwarded = (zero_count == limit);
}

/* ════════════════════════════════════════════════════════════════════
 * O8: Cross-implementation score boost.
 *
 * When an outlier broker has a different implementation than the
 * consensus majority, the divergence is far more likely to be a
 * real protocol non-compliance bug (not just non-determinism).
 * Boost the raw score by MQTT_CROSS_IMPL_BOOST_FACTOR.
 * ════════════════════════════════════════════════════════════════════ */
int mqtt_diff_score_cross_impl(
    const mqtt_diff_result_t *r,
    const mqtt_majority_vote_t *vote,
    const char **impl_names, int n) {

  int base_score = mqtt_diff_score_from_result(r);
  if (!vote || !impl_names || n < 2 || vote->outlier_count == 0)
    return base_score;

  /* Find consensus impl name */
  const char *consensus_impl = NULL;
  int limit = (n > MQTT_DIFF_MAX_BROKERS) ? MQTT_DIFF_MAX_BROKERS : n;
  for (int i = 0; i < limit; i++) {
    if (!vote->is_outlier[i] && impl_names[i]) {
      consensus_impl = impl_names[i];
      break;
    }
  }
  if (!consensus_impl) return base_score;

  /* Check if any outlier has a different implementation */
  int cross_impl = 0;
  for (int i = 0; i < limit; i++) {
    if (vote->is_outlier[i] && impl_names[i]) {
      if (strcmp(impl_names[i], consensus_impl) != 0) {
        cross_impl = 1;
        break;
      }
    }
  }

  if (cross_impl) {
    int boosted = (int)(base_score * MQTT_CROSS_IMPL_BOOST_FACTOR);
    return (boosted > 100) ? 100 : boosted;
  }
  return base_score;
}

/* ════════════════════════════════════════════════════════════════════
 * O8: Build a noncompliance report entry from majority vote outlier.
 *
 * Populates out with the first (worst) outlier's info.
 * Returns 1 if populated, 0 if no actionable outlier.
 * ════════════════════════════════════════════════════════════════════ */
int mqtt_diff_build_noncompliance(
    const mqtt_majority_vote_t *vote,
    const mqtt_diff_result_t *worst_pair,
    const char **impl_names, int n,
    mqtt_noncompliance_entry_t *out) {

  memset(out, 0, sizeof(*out));
  if (!vote || vote->outlier_count == 0 || !worst_pair)
    return 0;
  if (worst_pair->severity == MQTT_DIV_NONE)
    return 0;

  int limit = (n > MQTT_DIFF_MAX_BROKERS) ? MQTT_DIFF_MAX_BROKERS : n;

  /* Find the first outlier */
  for (int i = 0; i < limit; i++) {
    if (vote->is_outlier[i]) {
      out->outlier_index = i;
      if (impl_names && impl_names[i]) {
        int slen = (int)strlen(impl_names[i]);
        if (slen > 63) slen = 63;
        memcpy(out->outlier_impl, impl_names[i], slen);
      }
      break;
    }
  }

  out->severity = worst_pair->severity;
  out->strength = worst_pair->strength;
  out->pattern_hash = vote->pattern_hash;

  const char *sev_name = "unknown";
  switch (worst_pair->severity) {
  case MQTT_DIV_MISSING: sev_name = "MISSING_RESPONSE"; break;
  case MQTT_DIV_TYPE:    sev_name = "TYPE_MISMATCH";    break;
  case MQTT_DIV_CODE:    sev_name = "CODE_MISMATCH";    break;
  case MQTT_DIV_PAYLOAD: sev_name = "PAYLOAD_MISMATCH"; break;
  }

  snprintf(out->detail, MQTT_NONCOMPLIANCE_DETAIL_LEN,
           "outlier=%s(idx=%d) severity=%s strength=%.2f "
           "consensus=%d/%d type_diffs=%d code_diffs=%d "
           "flags_diffs=%d payload_diffs=%d",
           out->outlier_impl, out->outlier_index, sev_name,
           worst_pair->strength,
           vote->consensus_count, n,
           worst_pair->type_diffs, worst_pair->code_diffs,
           worst_pair->flags_diffs, worst_pair->payload_diffs);

  return 1;
}
