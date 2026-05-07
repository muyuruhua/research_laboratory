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
 * B2: Forwarding-level differential analysis.
 *
 * Parse subscriber-received PUBLISH packets into structured forwarding
 * fingerprint, then compare across brokers to detect:
 *   - Missing forwarding (broker silently drops messages)
 *   - Topic remap inconsistencies (bridge prefix mismatch)
 *   - QoS downgrade divergence (different QoS in forwarded message)
 *   - Retain propagation differences
 *   - Payload modification during forwarding
 *
 * This directly matches MBFuzzer's forward_message differential
 * (handle_network_response.py → difftest → compare_g_fields/h_fields)
 * but implemented in zero-allocation C for the hot fuzzing path.
 * ════════════════════════════════════════════════════════════════════ */

void mqtt_diff_parse_forwarding(const unsigned char *fwd_buf,
                                unsigned int fwd_len,
                                mqtt_fwd_fields_t *out) {
  unsigned int pos = 0;

  memset(out, 0, sizeof(*out));

  if (!fwd_buf || fwd_len == 0) return;

  while (pos < fwd_len && out->fwd_count < MQTT_DIFF_MAX_PACKETS) {
    if (pos + 1 >= fwd_len) break;

    uint8_t byte0 = fwd_buf[pos];
    uint8_t type_nibble = (byte0 >> 4) & 0x0F;

    /* Decode remaining length */
    unsigned int rl_bytes = 0;
    int remaining_length = mqtt_diff_decode_remaining_length(
        fwd_buf + pos + 1, fwd_len - pos - 1, &rl_bytes);

    if (remaining_length < 0) { pos++; continue; }

    unsigned int header_size = 1 + rl_bytes;
    unsigned int pkt_total = header_size + (unsigned int)remaining_length;

    if (pos + pkt_total > fwd_len) break;

    /* Only process PUBLISH packets (type 3) for forwarding analysis */
    if (type_nibble == 3) {
      int idx = (int)out->fwd_count;
      const unsigned char *body = fwd_buf + pos + header_size;
      unsigned int body_len = (unsigned int)remaining_length;

      out->fwd_qos[idx] = (byte0 >> 1) & 0x03;
      out->fwd_retain[idx] = byte0 & 0x01;

      /* Extract topic */
      if (body_len >= 2) {
        unsigned int tlen = ((unsigned int)body[0] << 8) | body[1];
        if (tlen <= body_len - 2) {
          out->fwd_topics[idx] = fnv1a_32(body + 2, tlen);

          /* Extract payload hash */
          unsigned int consumed = 2 + tlen;
          if (out->fwd_qos[idx] > 0) consumed += 2; /* packet ID */
          if (consumed < body_len) {
            out->fwd_payload_hashes[idx] = fnv1a_32(
                body + consumed, body_len - consumed);
          }
        }
      }

      out->fwd_count++;
    }

    pos += pkt_total;
  }

  /* Combined hash */
  if (out->fwd_count > 0) {
    uint32_t h = 2166136261u;
    for (unsigned int i = 0; i < out->fwd_count; i++) {
      h ^= out->fwd_topics[i];          h *= 16777619u;
      h ^= out->fwd_qos[i];             h *= 16777619u;
      h ^= out->fwd_retain[i];          h *= 16777619u;
      h ^= out->fwd_payload_hashes[i];  h *= 16777619u;
    }
    h ^= out->fwd_count; h *= 16777619u;
    out->combined_hash = h;
  }
}

mqtt_diff_result_t mqtt_diff_compare_fwd(const mqtt_fwd_fields_t *a,
                                         const mqtt_fwd_fields_t *b) {
  mqtt_diff_result_t r;
  memset(&r, 0, sizeof(r));

  /* Both empty = no divergence */
  if (a->fwd_count == 0 && b->fwd_count == 0) {
    r.severity = MQTT_DIV_NONE;
    return r;
  }

  /* One forwarded, other didn't = MISSING (strongest signal) */
  if (a->fwd_count == 0 || b->fwd_count == 0) {
    r.severity = MQTT_DIV_MISSING;
    r.strength = 1.0;
    r.pattern_hash = a->combined_hash ^ b->combined_hash ^ 0xFD00;
    return r;
  }

  /* Fast path: identical combined hash */
  if (a->combined_hash == b->combined_hash && a->fwd_count == b->fwd_count) {
    r.severity = MQTT_DIV_NONE;
    return r;
  }

  /* Different forward counts = TYPE-level divergence
   * (e.g., one broker duplicates shared-sub delivery) */
  if (a->fwd_count != b->fwd_count) {
    r.severity = MQTT_DIV_TYPE;
    int diff = (int)a->fwd_count - (int)b->fwd_count;
    if (diff < 0) diff = -diff;
    int max_c = (int)(a->fwd_count > b->fwd_count ? a->fwd_count : b->fwd_count);
    r.strength = (double)diff / (double)max_c;
    r.type_diffs = diff;
    r.pattern_hash = a->combined_hash ^ b->combined_hash ^ 0xFD01;
    return r;
  }

  /* Same count: compare per-message topic/QoS/retain (CODE-level = remap divergence) */
  unsigned int min_c = a->fwd_count < b->fwd_count ? a->fwd_count : b->fwd_count;
  int topic_diffs = 0, qos_diffs = 0, retain_diffs = 0, payload_diffs = 0;

  for (unsigned int i = 0; i < min_c; i++) {
    if (a->fwd_topics[i] != b->fwd_topics[i]) topic_diffs++;
    if (a->fwd_qos[i] != b->fwd_qos[i]) qos_diffs++;
    if (a->fwd_retain[i] != b->fwd_retain[i]) retain_diffs++;
    if (a->fwd_payload_hashes[i] != b->fwd_payload_hashes[i]) payload_diffs++;
  }

  /* Topic or QoS divergence = CODE level (remap/downgrade bug) */
  if (topic_diffs > 0 || qos_diffs > 0 || retain_diffs > 0) {
    r.severity = MQTT_DIV_CODE;
    r.code_diffs = topic_diffs + qos_diffs + retain_diffs;
    r.strength = (double)r.code_diffs / (double)(min_c * 3);
    if (r.strength > 1.0) r.strength = 1.0;
    r.pattern_hash = a->combined_hash ^ b->combined_hash ^ 0xFD02;
    return r;
  }

  /* Payload-only divergence */
  if (payload_diffs > 0) {
    r.severity = MQTT_DIV_PAYLOAD;
    r.payload_diffs = payload_diffs;
    r.strength = (double)payload_diffs / (double)min_c;
    r.pattern_hash = a->combined_hash ^ b->combined_hash ^ 0xFD03;
    return r;
  }

  r.severity = MQTT_DIV_NONE;
  return r;
}
