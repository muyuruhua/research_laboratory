/* mqtt-generate.c — MQTT v3.1.1 / v5 structured packet generator.
 *
 * Generates structurally valid (and semi-valid) MQTT packets for fuzzing.
 *
 * Key feature: MQTT v5 support including Properties, AUTH, enhanced
 * DISCONNECT, subscription options — exercising mosquitto code paths
 * that byte-level havoc and v3.1.1-only seeds can never reach:
 *   - handle__connect()   v5 branch + property__read_all()
 *   - handle__auth()      (v5 only — entirely unreachable without this)
 *   - handle__disconnect() with reason code + properties
 *   - handle__subscribe()  with No Local / Retain Handling options
 *   - Topic alias mapping  in handle__publish()
 *
 * Design:
 *   - All randomness via random() (shared AFL PRNG, reproducible)
 *   - Packets are valid enough to pass mosquitto initial parsing
 *     but contain fuzzed values to explore deep error/edge paths
 *   - Data-driven property generation via prop_spec_t tables
 *   - Zero global mutable state; safe for concurrent use
 */

#include "mqtt-generate.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

/* ════════════════════════════════════════════════════════════════════
 * Section 1: Helpers
 * ════════════════════════════════════════════════════════════════════ */

static inline u32 mg_rand(u32 limit) {
  if (limit <= 1) return 0;
  return (u32)(random() % limit);
}

/* Encode MQTT variable-length integer. Returns bytes written (1-4). */
static u32 encode_varint(u8 *buf, u32 val) {
  u32 pos = 0;
  do {
    u8 byte = val % 128;
    val /= 128;
    if (val > 0) byte |= 0x80;
    buf[pos++] = byte;
  } while (val > 0 && pos < 4);
  return pos;
}

/* Encode a UTF-8 string (2-byte big-endian length prefix + data). */
static u32 encode_utf8(u8 *buf, u32 cap, const char *str, u32 slen) {
  if (cap < 2 + slen) return 0;
  buf[0] = (u8)((slen >> 8) & 0xFF);
  buf[1] = (u8)(slen & 0xFF);
  if (slen > 0) memcpy(buf + 2, str, slen);
  return 2 + slen;
}

/* Wrap a body with MQTT fixed header: type_flags byte + remaining length. */
static u32 wrap_packet(u8 *out, u32 cap, u8 type_flags,
                       const u8 *body, u32 body_len) {
  u8 hdr[5];
  u32 hdr_len = 1;
  hdr[0] = type_flags;
  hdr_len += encode_varint(hdr + 1, body_len);
  if (hdr_len + body_len > cap) return 0;
  memcpy(out, hdr, hdr_len);
  if (body_len > 0) memcpy(out + hdr_len, body, body_len);
  return hdr_len + body_len;
}

/* ════════════════════════════════════════════════════════════════════
 * Section 2: Data Pools
 * ════════════════════════════════════════════════════════════════════ */

static const char *mg_topics[] = {
  "test/topic", "$SYS/broker/version", "$SYS/broker/clients/connected",
  "a/b/c/d/e", "#", "+/data", "home/+/temperature",
  "$share/grp/test/topic", "sensor/temp", "t", "",
  "very/deep/topic/level1/level2/level3/level4",
  /* P8: Additional shared subscription patterns to exercise v2.1.x
   * shared subscription routing (sub__add shared, sub__search shared,
   * round-robin distribution, No Local interaction with shared subs). */
  "$share/grp1/test/+", "$share/grp2/sensor/#",
  "$share/g3/home/+/temperature", "$share/grp1/#",
};
#define MG_NTOPICS ((u32)(sizeof(mg_topics) / sizeof(mg_topics[0])))

static const char *mg_cids[] = {
  "gen_v5_01", "gen_v5_sub", "gen_v5_pub", "", "x",
  "client_with_long_id_for_boundary_test_purpose_1234567",
};
#define MG_NCIDS ((u32)(sizeof(mg_cids) / sizeof(mg_cids[0])))

static const char *mg_auth_methods[] = {
  "SCRAM-SHA-256", "SCRAM-SHA-1", "PLAIN", "external",
};
#define MG_NAUTH ((u32)(sizeof(mg_auth_methods) / sizeof(mg_auth_methods[0])))

/* v5 DISCONNECT reason codes */
static const u8 mg_disc_reasons[] = {
  0x00, 0x04, 0x80, 0x81, 0x82, 0x8D, 0x8E, 0x93, 0x94, 0x95, 0x98,
};
#define MG_NDISC ((u32)(sizeof(mg_disc_reasons) / sizeof(mg_disc_reasons[0])))

/* v5 AUTH reason codes */
static const u8 mg_auth_reasons[] = { 0x00, 0x18, 0x19 };

/* v5 ACK reason codes (PUBACK/PUBREC) */
static const u8 mg_ack_reasons[] = {
  0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99,
};
#define MG_NACK ((u32)(sizeof(mg_ack_reasons) / sizeof(mg_ack_reasons[0])))

/* ════════════════════════════════════════════════════════════════════
 * Section 3: v5 Property Generation (data-driven)
 * ════════════════════════════════════════════════════════════════════ */

typedef enum {
  PT_BYTE, PT_U16, PT_U32, PT_VARINT, PT_UTF8, PT_UTF8_PAIR, PT_BINARY,
} prop_type_t;

typedef struct { u8 id; prop_type_t type; } prop_spec_t;

/* --- Per-packet-type property tables --- */
static const prop_spec_t connect_props[] = {
  {0x11, PT_U32},       /* Session Expiry Interval */
  {0x21, PT_U16},       /* Receive Maximum */
  {0x27, PT_U32},       /* Maximum Packet Size */
  {0x22, PT_U16},       /* Topic Alias Maximum */
  {0x19, PT_BYTE},      /* Request Response Information */
  {0x17, PT_BYTE},      /* Request Problem Information */
  {0x26, PT_UTF8_PAIR}, /* User Property */
  {0x15, PT_UTF8},      /* Authentication Method */
  {0x16, PT_BINARY},    /* Authentication Data */
};

static const prop_spec_t publish_props[] = {
  {0x01, PT_BYTE},      /* Payload Format Indicator */
  {0x02, PT_U32},       /* Message Expiry Interval */
  {0x23, PT_U16},       /* Topic Alias */
  {0x08, PT_UTF8},      /* Response Topic */
  {0x09, PT_BINARY},    /* Correlation Data */
  {0x0B, PT_VARINT},    /* Subscription Identifier */
  {0x03, PT_UTF8},      /* Content Type */
  {0x26, PT_UTF8_PAIR}, /* User Property */
};

static const prop_spec_t subscribe_props[] = {
  {0x0B, PT_VARINT},    /* Subscription Identifier */
  {0x26, PT_UTF8_PAIR}, /* User Property */
};

static const prop_spec_t disconnect_props[] = {
  {0x11, PT_U32},       /* Session Expiry Interval */
  {0x1F, PT_UTF8},      /* Reason String */
  {0x26, PT_UTF8_PAIR}, /* User Property */
  {0x1C, PT_UTF8},      /* Server Reference */
};

static const prop_spec_t ack_props[] = {
  {0x1F, PT_UTF8},      /* Reason String */
  {0x26, PT_UTF8_PAIR}, /* User Property */
};

#define ARRAY_CNT(a) ((u32)(sizeof(a) / sizeof((a)[0])))

/* Generate a random property block: varint(prop_length) + properties.
 * Returns bytes written to buf, or 0 if cap too small. */
static u32 gen_properties(u8 *buf, u32 cap,
                          const prop_spec_t *specs, u32 nspecs) {
  u8 prop_buf[768];
  u32 plen = 0;

  for (u32 i = 0; i < nspecs && plen < 700; i++) {
    /* ~60% chance to include each property */
    if (mg_rand(5) < 2) continue;
    if (plen + 80 > sizeof(prop_buf)) break;

    prop_buf[plen++] = specs[i].id;

    switch (specs[i].type) {
    case PT_BYTE:
      prop_buf[plen++] = (u8)mg_rand(256);
      break;
    case PT_U16: {
      u16 v = (u16)mg_rand(65536);
      prop_buf[plen++] = (u8)(v >> 8);
      prop_buf[plen++] = (u8)(v & 0xFF);
      break;
    }
    case PT_U32: {
      u32 v = (u32)random();
      prop_buf[plen++] = (u8)(v >> 24);
      prop_buf[plen++] = (u8)(v >> 16);
      prop_buf[plen++] = (u8)(v >> 8);
      prop_buf[plen++] = (u8)(v & 0xFF);
      break;
    }
    case PT_VARINT: {
      u32 v = mg_rand(268435456); /* max varint value */
      plen += encode_varint(prop_buf + plen, v);
      break;
    }
    case PT_UTF8: {
      const char *s = mg_topics[mg_rand(MG_NTOPICS)];
      u32 sl = (u32)strlen(s);
      prop_buf[plen++] = (u8)(sl >> 8);
      prop_buf[plen++] = (u8)(sl & 0xFF);
      if (sl > 0) { memcpy(prop_buf + plen, s, sl); plen += sl; }
      break;
    }
    case PT_UTF8_PAIR: {
      const char *k = mg_topics[mg_rand(MG_NTOPICS)];
      const char *v = mg_topics[mg_rand(MG_NTOPICS)];
      u32 kl = (u32)strlen(k), vl = (u32)strlen(v);
      prop_buf[plen++] = (u8)(kl >> 8); prop_buf[plen++] = (u8)(kl & 0xFF);
      if (kl > 0) { memcpy(prop_buf + plen, k, kl); plen += kl; }
      prop_buf[plen++] = (u8)(vl >> 8); prop_buf[plen++] = (u8)(vl & 0xFF);
      if (vl > 0) { memcpy(prop_buf + plen, v, vl); plen += vl; }
      break;
    }
    case PT_BINARY: {
      u32 dl = mg_rand(24) + 1;
      prop_buf[plen++] = (u8)(dl >> 8);
      prop_buf[plen++] = (u8)(dl & 0xFF);
      for (u32 j = 0; j < dl && plen < sizeof(prop_buf); j++)
        prop_buf[plen++] = (u8)mg_rand(256);
      break;
    }
    }
  }

  /* Encode: varint(plen) + prop_buf */
  u8 len_enc[4];
  u32 len_bytes = encode_varint(len_enc, plen);
  if (len_bytes + plen > cap) return 0;
  memcpy(buf, len_enc, len_bytes);
  memcpy(buf + len_bytes, prop_buf, plen);
  return len_bytes + plen;
}

/* Generate an empty property block (just the length=0 byte). */
static u32 gen_empty_properties(u8 *buf, u32 cap) {
  if (cap < 1) return 0;
  buf[0] = 0x00;
  return 1;
}

/* ════════════════════════════════════════════════════════════════════
 * Section 4: Individual Packet Generators
 * ════════════════════════════════════════════════════════════════════ */

/* ── O4: Context-aware generation helpers ──
 * When a non-NULL mqtt_gen_ctx_t is threaded through, these helpers
 * ensure:
 *   - gen_connect uses a consistent client_id within the session
 *   - gen_subscribe records subscribed topics in the context
 *   - gen_publish prefers a topic that was previously subscribed
 *   - gen_publish assigns / reuses v5 topic aliases
 *   - gen_ack / gen_unsubscribe reference topics / pkt_ids from context
 */

/* --- CONNECT (v3.1.1 and v5) --- */
static u32 gen_connect_ctx(u8 *buf, u32 cap, u8 ver, mqtt_gen_ctx_t *ctx) {
  u8 body[1024];
  u32 pos = 0;
  const char *cid;

  /* O4: Use context-pinned client_id if available, otherwise pick random
   * and store it so subsequent CONNECTs in the same sequence are consistent. */
  if (ctx && ctx->client_id_valid) {
    cid = ctx->client_id;
  } else {
    cid = mg_cids[mg_rand(MG_NCIDS)];
    if (ctx) {
      u32 sl = (u32)strlen(cid);
      if (sl < sizeof(ctx->client_id)) {
        memcpy(ctx->client_id, cid, sl + 1);
        ctx->client_id_valid = 1;
      }
    }
  }
  u32 cid_len = (u32)strlen(cid);

  /* Protocol Name */
  body[pos++] = 0x00; body[pos++] = 0x04;
  body[pos++] = 'M'; body[pos++] = 'Q'; body[pos++] = 'T'; body[pos++] = 'T';

  /* Protocol Level */
  body[pos++] = (ver == MQTG_PROTO_V5) ? 0x05 : 0x04;

  /* Connect Flags — randomize will/user/pass */
  u8 flags = 0x02; /* Clean Session / Clean Start */
  int has_will  = mg_rand(3) == 0;
  int has_user  = mg_rand(3) == 0;
  int has_pass  = has_user && mg_rand(2);
  u8 will_qos   = (u8)mg_rand(3);
  u8 will_retain = (u8)mg_rand(2);
  if (has_will)  flags |= 0x04 | (will_qos << 3) | (will_retain << 5);
  if (has_user)  flags |= 0x80;
  if (has_pass)  flags |= 0x40;
  body[pos++] = flags;

  /* Keep Alive */
  u16 ka = (u16)(mg_rand(120) + 10);
  body[pos++] = (u8)(ka >> 8); body[pos++] = (u8)(ka & 0xFF);

  /* v5: Properties */
  if (ver == MQTG_PROTO_V5) {
    u32 plen = gen_properties(body + pos, sizeof(body) - pos,
                              connect_props, ARRAY_CNT(connect_props));
    if (plen == 0) return 0;
    pos += plen;
  }

  /* Payload: Client Identifier */
  pos += encode_utf8(body + pos, sizeof(body) - pos, cid, cid_len);

  /* v5 Will Properties (if will flag set) */
  if (has_will && ver == MQTG_PROTO_V5) {
    pos += gen_empty_properties(body + pos, sizeof(body) - pos);
  }

  /* Will Topic + Will Payload (if will flag set) */
  if (has_will) {
    const char *wt = mg_topics[mg_rand(MG_NTOPICS)];
    pos += encode_utf8(body + pos, sizeof(body) - pos, wt, (u32)strlen(wt));
    /* Will Payload as binary data */
    u8 wp[] = "will_payload";
    u32 wplen = (u32)sizeof(wp) - 1;
    if (pos + 2 + wplen <= sizeof(body)) {
      body[pos++] = (u8)(wplen >> 8); body[pos++] = (u8)(wplen & 0xFF);
      memcpy(body + pos, wp, wplen); pos += wplen;
    }
  }

  /* Username / Password */
  if (has_user) {
    pos += encode_utf8(body + pos, sizeof(body) - pos, "fuzz_user", 9);
  }
  if (has_pass) {
    pos += encode_utf8(body + pos, sizeof(body) - pos, "fuzz_pass", 9);
  }

  return wrap_packet(buf, cap, 0x10, body, pos);
}

/* --- PUBLISH (v3.1.1 and v5) --- */
static u32 gen_publish_ctx(u8 *buf, u32 cap, u8 ver, mqtt_gen_ctx_t *ctx) {
  u8 body[1024];
  u32 pos = 0;
  const char *topic;
  u8 qos = (u8)mg_rand(3);
  u8 dup = (u8)mg_rand(2);
  u8 retain = (u8)mg_rand(2);
  u16 pkt_id;

  /* O4: Topic selection priority:
   *   70% — reuse a previously subscribed topic (semantic consistency)
   *   20% — reuse last published topic (intra-session consistency)
   *   10% — random topic (exploration)
   * This ensures PUBLISH messages reach the subscriber path in the
   * broker, exercising subs__send() → matching → delivery code. */
  if (ctx && ctx->n_sub_topics > 0 && mg_rand(10) < 7) {
    topic = ctx->sub_topics[mg_rand(ctx->n_sub_topics)];
  } else if (ctx && ctx->pub_topic_valid && mg_rand(10) < 9) {
    topic = ctx->pub_topic;
  } else {
    topic = mg_topics[mg_rand(MG_NTOPICS)];
  }

  /* O4: Record this topic for future dependency */
  if (ctx) {
    u32 tl = (u32)strlen(topic);
    if (tl < sizeof(ctx->pub_topic)) {
      memcpy(ctx->pub_topic, topic, tl + 1);
      ctx->pub_topic_valid = 1;
    }
  }

  /* O4: Monotonic packet ID from context to avoid ID reuse bugs */
  if (ctx) {
    pkt_id = ctx->next_pkt_id++;
    if (ctx->next_pkt_id == 0) ctx->next_pkt_id = 1;
  } else {
    pkt_id = (u16)(mg_rand(65534) + 1);
  }

  /* Topic Name */
  pos += encode_utf8(body + pos, sizeof(body) - pos, topic, (u32)strlen(topic));

  /* Packet Identifier (only for QoS > 0) */
  if (qos > 0) {
    body[pos++] = (u8)(pkt_id >> 8);
    body[pos++] = (u8)(pkt_id & 0xFF);
  }

  /* v5: Properties */
  if (ver == MQTG_PROTO_V5) {
    u32 plen = gen_properties(body + pos, sizeof(body) - pos,
                              publish_props, ARRAY_CNT(publish_props));
    if (plen == 0) return 0;
    pos += plen;
  }

  /* Payload (random bytes) */
  u32 payload_len = mg_rand(64);
  for (u32 i = 0; i < payload_len && pos < sizeof(body); i++)
    body[pos++] = (u8)mg_rand(256);

  u8 type_flags = (u8)((3 << 4) | (dup << 3) | (qos << 1) | retain);
  return wrap_packet(buf, cap, type_flags, body, pos);
}

/* --- SUBSCRIBE (v3.1.1 and v5) --- */
static u32 gen_subscribe_ctx(u8 *buf, u32 cap, u8 ver, mqtt_gen_ctx_t *ctx) {
  u8 body[512];
  u32 pos = 0;
  u16 pkt_id;
  u32 n_filters = mg_rand(3) + 1; /* 1-3 topic filters */

  /* O4: Monotonic packet ID from context */
  if (ctx) {
    pkt_id = ctx->next_pkt_id++;
    if (ctx->next_pkt_id == 0) ctx->next_pkt_id = 1;
  } else {
    pkt_id = (u16)(mg_rand(65534) + 1);
  }

  /* Packet Identifier */
  body[pos++] = (u8)(pkt_id >> 8);
  body[pos++] = (u8)(pkt_id & 0xFF);

  /* v5: Properties */
  if (ver == MQTG_PROTO_V5) {
    u32 plen = gen_properties(body + pos, sizeof(body) - pos,
                              subscribe_props, ARRAY_CNT(subscribe_props));
    if (plen == 0) return 0;
    pos += plen;
  }

  /* Topic Filters */
  for (u32 f = 0; f < n_filters && pos + 10 < sizeof(body); f++) {
    const char *tf = mg_topics[mg_rand(MG_NTOPICS)];
    pos += encode_utf8(body + pos, sizeof(body) - pos, tf, (u32)strlen(tf));

    /* O4: Record subscribed topics in context for PUBLISH dependency */
    if (ctx && ctx->n_sub_topics < 4) {
      u32 tl = (u32)strlen(tf);
      if (tl > 0 && tl < 128 && tf[0] != '#' && tf[0] != '+') {
        memcpy(ctx->sub_topics[ctx->n_sub_topics], tf, tl + 1);
        ctx->n_sub_topics++;
      }
    }

    if (ver == MQTG_PROTO_V5) {
      /* v5 Subscription Options byte:
       * bits 0-1: QoS (0-2)
       * bit 2:    No Local (don't echo own publishes)
       * bit 3:    Retain As Published
       * bits 4-5: Retain Handling (0-2) */
      u8 qos = (u8)mg_rand(3);
      u8 no_local = (u8)mg_rand(2);
      u8 rap = (u8)mg_rand(2);
      u8 rh = (u8)mg_rand(3);
      body[pos++] = (u8)(qos | (no_local << 2) | (rap << 3) | (rh << 4));
    } else {
      body[pos++] = (u8)mg_rand(3); /* QoS 0-2 */
    }
  }

  return wrap_packet(buf, cap, 0x82, body, pos);
}

/* --- UNSUBSCRIBE (v3.1.1 and v5) --- */
static u32 gen_unsubscribe_ctx(u8 *buf, u32 cap, u8 ver, mqtt_gen_ctx_t *ctx) {
  u8 body[512];
  u32 pos = 0;
  u16 pkt_id;

  /* O4: Monotonic packet ID from context */
  if (ctx) {
    pkt_id = ctx->next_pkt_id++;
    if (ctx->next_pkt_id == 0) ctx->next_pkt_id = 1;
  } else {
    pkt_id = (u16)(mg_rand(65534) + 1);
  }

  body[pos++] = (u8)(pkt_id >> 8);
  body[pos++] = (u8)(pkt_id & 0xFF);

  if (ver == MQTG_PROTO_V5) {
    pos += gen_empty_properties(body + pos, sizeof(body) - pos);
  }

  /* O4: Prefer unsubscribing from previously subscribed topics */
  u32 nf = mg_rand(2) + 1;
  for (u32 f = 0; f < nf && pos + 10 < sizeof(body); f++) {
    const char *tf;
    if (ctx && ctx->n_sub_topics > 0 && mg_rand(3) < 2)
      tf = ctx->sub_topics[mg_rand(ctx->n_sub_topics)];
    else
      tf = mg_topics[mg_rand(MG_NTOPICS)];
    pos += encode_utf8(body + pos, sizeof(body) - pos, tf, (u32)strlen(tf));
  }

  return wrap_packet(buf, cap, 0xA2, body, pos);
}

/* --- ACK packets: PUBACK / PUBREC / PUBREL / PUBCOMP --- */
static u32 gen_ack(u8 *buf, u32 cap, u8 type_byte, u8 ver) {
  u8 body[256];
  u32 pos = 0;
  u16 pkt_id = (u16)(mg_rand(65534) + 1);

  body[pos++] = (u8)(pkt_id >> 8);
  body[pos++] = (u8)(pkt_id & 0xFF);

  if (ver == MQTG_PROTO_V5) {
    /* Reason Code */
    body[pos++] = mg_ack_reasons[mg_rand(MG_NACK)];
    /* Properties (sometimes include, sometimes omit for minimal packet) */
    if (mg_rand(3) > 0) {
      u32 plen = gen_properties(body + pos, sizeof(body) - pos,
                                ack_props, ARRAY_CNT(ack_props));
      if (plen > 0) pos += plen;
    }
  }

  return wrap_packet(buf, cap, type_byte, body, pos);
}

/* --- DISCONNECT (v3.1.1 trivial, v5 enhanced) --- */
static u32 gen_disconnect(u8 *buf, u32 cap, u8 ver) {
  if (ver != MQTG_PROTO_V5) {
    /* v3.1.1: fixed 2 bytes */
    if (cap < 2) return 0;
    buf[0] = 0xE0; buf[1] = 0x00;
    return 2;
  }

  u8 body[512];
  u32 pos = 0;

  /* v5: Reason Code */
  body[pos++] = mg_disc_reasons[mg_rand(MG_NDISC)];

  /* v5: Properties */
  u32 plen = gen_properties(body + pos, sizeof(body) - pos,
                            disconnect_props, ARRAY_CNT(disconnect_props));
  if (plen > 0) pos += plen;

  return wrap_packet(buf, cap, 0xE0, body, pos);
}

/* --- AUTH (v5 only) --- */
static u32 gen_auth(u8 *buf, u32 cap) {
  u8 body[512];
  u32 pos = 0;

  /* Reason Code */
  body[pos++] = mg_auth_reasons[mg_rand(3)];

  /* Properties — always include Authentication Method (required by spec) */
  {
    u8 prop_buf[256];
    u32 plen = 0;

    /* Authentication Method (0x15) — required */
    const char *method = mg_auth_methods[mg_rand(MG_NAUTH)];
    u32 mlen = (u32)strlen(method);
    prop_buf[plen++] = 0x15;
    prop_buf[plen++] = (u8)(mlen >> 8);
    prop_buf[plen++] = (u8)(mlen & 0xFF);
    memcpy(prop_buf + plen, method, mlen); plen += mlen;

    /* Authentication Data (0x16) — random bytes */
    u32 dlen = mg_rand(16) + 4;
    prop_buf[plen++] = 0x16;
    prop_buf[plen++] = (u8)(dlen >> 8);
    prop_buf[plen++] = (u8)(dlen & 0xFF);
    for (u32 j = 0; j < dlen && plen < sizeof(prop_buf); j++)
      prop_buf[plen++] = (u8)mg_rand(256);

    /* Optionally add Reason String (0x1F) */
    if (mg_rand(3) == 0) {
      const char *rs = "auth_in_progress";
      u32 rslen = (u32)strlen(rs);
      prop_buf[plen++] = 0x1F;
      prop_buf[plen++] = (u8)(rslen >> 8);
      prop_buf[plen++] = (u8)(rslen & 0xFF);
      memcpy(prop_buf + plen, rs, rslen); plen += rslen;
    }

    /* Encode property length + body */
    u8 len_enc[4];
    u32 len_bytes = encode_varint(len_enc, plen);
    if (pos + len_bytes + plen > sizeof(body)) return 0;
    memcpy(body + pos, len_enc, len_bytes); pos += len_bytes;
    memcpy(body + pos, prop_buf, plen); pos += plen;
  }

  return wrap_packet(buf, cap, 0xF0, body, pos);
}

/* --- PINGREQ --- */
static u32 gen_pingreq(u8 *buf, u32 cap) {
  if (cap < 2) return 0;
  buf[0] = 0xC0; buf[1] = 0x00;
  return 2;
}

/* ════════════════════════════════════════════════════════════════════
 * Section 5: Top-Level API
 * ════════════════════════════════════════════════════════════════════ */

/* O4: Backward-compatible wrappers (no context — for seed generation) */
static u32 gen_connect(u8 *buf, u32 cap, u8 ver)     { return gen_connect_ctx(buf, cap, ver, NULL); }
static u32 gen_publish(u8 *buf, u32 cap, u8 ver)      { return gen_publish_ctx(buf, cap, ver, NULL); }
static u32 gen_subscribe(u8 *buf, u32 cap, u8 ver)    { return gen_subscribe_ctx(buf, cap, ver, NULL); }
static u32 gen_unsubscribe(u8 *buf, u32 cap, u8 ver)  { return gen_unsubscribe_ctx(buf, cap, ver, NULL); }

/* Client-sendable packet types for random selection */
static const u8 client_types[] = {
  MQTG_CONNECT, MQTG_PUBLISH, MQTG_SUBSCRIBE, MQTG_UNSUBSCRIBE,
  MQTG_PINGREQ, MQTG_DISCONNECT, MQTG_PUBACK, MQTG_PUBREC,
  MQTG_PUBREL, MQTG_PUBCOMP, MQTG_AUTH,
};
#define N_CLIENT_TYPES ARRAY_CNT(client_types)

/* Client types excluding CONNECT/DISCONNECT (for mid-session generation) */
static const u8 mid_session_types[] = {
  MQTG_PUBLISH, MQTG_SUBSCRIBE, MQTG_UNSUBSCRIBE,
  MQTG_PINGREQ, MQTG_PUBACK, MQTG_PUBREC,
  MQTG_PUBREL, MQTG_PUBCOMP, MQTG_AUTH,
};
#define N_MID_SESSION ARRAY_CNT(mid_session_types)

/* O4: Context initialisation */
void mqtt_gen_ctx_init(mqtt_gen_ctx_t *ctx, u8 proto_ver) {
  if (!ctx) return;
  memset(ctx, 0, sizeof(*ctx));
  ctx->next_pkt_id = 1;
  ctx->next_alias  = 1;
  ctx->alias_max   = 10; /* default; overridable */
  ctx->ver = proto_ver;
  if (ctx->ver == 0)
    ctx->ver = (mg_rand(5) < 3) ? MQTG_PROTO_V5 : MQTG_PROTO_V311;
}

/* O4: Context-aware single packet generation */
u32 mqtt_gen_packet_ctx(u8 *buf, u32 cap, mqtt_gen_ctx_t *ctx, u8 pkt_type) {
  if (!buf || cap < 2) return 0;

  u8 ver = ctx ? ctx->ver : 0;
  if (ver == 0) ver = (mg_rand(5) < 3) ? MQTG_PROTO_V5 : MQTG_PROTO_V311;

  u8 pt = pkt_type;
  if (pt == 0) pt = client_types[mg_rand(N_CLIENT_TYPES)];
  if (pt == MQTG_AUTH) ver = MQTG_PROTO_V5;

  switch (pt) {
  case MQTG_CONNECT:     return gen_connect_ctx(buf, cap, ver, ctx);
  case MQTG_PUBLISH:     return gen_publish_ctx(buf, cap, ver, ctx);
  case MQTG_SUBSCRIBE:   return gen_subscribe_ctx(buf, cap, ver, ctx);
  case MQTG_UNSUBSCRIBE: return gen_unsubscribe_ctx(buf, cap, ver, ctx);
  case MQTG_PUBACK:      return gen_ack(buf, cap, 0x40, ver);
  case MQTG_PUBREC:      return gen_ack(buf, cap, 0x50, ver);
  case MQTG_PUBREL:      return gen_ack(buf, cap, 0x62, ver);
  case MQTG_PUBCOMP:     return gen_ack(buf, cap, 0x70, ver);
  case MQTG_PINGREQ:     return gen_pingreq(buf, cap);
  case MQTG_DISCONNECT:  return gen_disconnect(buf, cap, ver);
  case MQTG_AUTH:         return gen_auth(buf, cap);
  default:                return gen_pingreq(buf, cap);
  }
}

/* Original context-free API (preserved for backward compatibility) */
u32 mqtt_gen_packet(u8 *buf, u32 cap, u8 proto_ver, u8 pkt_type) {
  if (!buf || cap < 2) return 0;

  /* Choose proto version if not specified: 60% v5, 40% v3.1.1 */
  u8 ver = proto_ver;
  if (ver == 0) ver = (mg_rand(5) < 3) ? MQTG_PROTO_V5 : MQTG_PROTO_V311;

  /* Choose packet type if not specified */
  u8 pt = pkt_type;
  if (pt == 0) pt = client_types[mg_rand(N_CLIENT_TYPES)];

  /* AUTH is v5-only; force v5 */
  if (pt == MQTG_AUTH) ver = MQTG_PROTO_V5;

  switch (pt) {
  case MQTG_CONNECT:     return gen_connect(buf, cap, ver);
  case MQTG_PUBLISH:     return gen_publish(buf, cap, ver);
  case MQTG_SUBSCRIBE:   return gen_subscribe(buf, cap, ver);
  case MQTG_UNSUBSCRIBE: return gen_unsubscribe(buf, cap, ver);
  case MQTG_PUBACK:      return gen_ack(buf, cap, 0x40, ver);
  case MQTG_PUBREC:      return gen_ack(buf, cap, 0x50, ver);
  case MQTG_PUBREL:      return gen_ack(buf, cap, 0x62, ver);
  case MQTG_PUBCOMP:     return gen_ack(buf, cap, 0x70, ver);
  case MQTG_PINGREQ:     return gen_pingreq(buf, cap);
  case MQTG_DISCONNECT:  return gen_disconnect(buf, cap, ver);
  case MQTG_AUTH:         return gen_auth(buf, cap);
  default:                return gen_pingreq(buf, cap);
  }
}

/* O4: Context-aware sequence generation — threads semantic dependencies
 * through the entire CONNECT → messages → DISCONNECT flow. */
u32 mqtt_gen_sequence(u8 *buf, u32 cap, u8 proto_ver, u32 msg_count) {
  if (!buf || cap < 64) return 0;

  mqtt_gen_ctx_t ctx;
  mqtt_gen_ctx_init(&ctx, proto_ver);

  u32 total = 0;

  /* CONNECT — context records client_id */
  u32 n = gen_connect_ctx(buf + total, cap - total, ctx.ver, &ctx);
  if (n == 0) return 0;
  total += n;

  /* N mid-session messages — context threads topic / alias / pkt_id */
  for (u32 i = 0; i < msg_count && total + 64 < cap; i++) {
    u8 pt = mid_session_types[mg_rand(N_MID_SESSION)];
    /* AUTH only for v5 */
    if (pt == MQTG_AUTH && ctx.ver != MQTG_PROTO_V5)
      pt = MQTG_PUBLISH;
    n = mqtt_gen_packet_ctx(buf + total, cap - total, &ctx, pt);
    if (n > 0) total += n;
  }

  /* DISCONNECT */
  n = gen_disconnect(buf + total, cap - total, ctx.ver);
  if (n > 0) total += n;

  return total;
}

/* ════════════════════════════════════════════════════════════════════
 * Section 6: v5 Seed Generation
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
  const char *name;
  u8 ver;
  u8 forced_types[8]; /* 0-terminated list of forced packet types */
  u32 extra_random;   /* number of additional random mid-session packets */
} v5_seed_plan_t;

static const v5_seed_plan_t v5_seed_plans[] = {
  /* Basic v5 CONNECT → SUBSCRIBE → PUBLISH → DISCONNECT */
  { "v5_basic",     5, {MQTG_SUBSCRIBE, MQTG_PUBLISH, 0}, 0 },
  /* v5 CONNECT with AUTH exchange */
  { "v5_auth",      5, {MQTG_AUTH, MQTG_AUTH, 0}, 0 },
  /* v5 PUBLISH with properties (topic alias, message expiry, etc.) */
  { "v5_pub_props", 5, {MQTG_SUBSCRIBE, MQTG_PUBLISH, MQTG_PUBLISH, MQTG_PUBLISH, 0}, 0 },
  /* v5 SUBSCRIBE with subscription options */
  { "v5_sub_opts",  5, {MQTG_SUBSCRIBE, MQTG_SUBSCRIBE, MQTG_PUBLISH, MQTG_UNSUBSCRIBE, 0}, 0 },
  /* v5 enhanced DISCONNECT with reason code */
  { "v5_disconnect",5, {MQTG_SUBSCRIBE, MQTG_PUBLISH, 0}, 0 },
  /* v5 QoS 2 flow: PUBLISH → PUBREC → PUBREL → PUBCOMP */
  { "v5_qos2_flow", 5, {MQTG_SUBSCRIBE, MQTG_PUBLISH, MQTG_PUBREC, MQTG_PUBREL, MQTG_PUBCOMP, 0}, 0 },
  /* Mixed v5: many different packet types */
  { "v5_mixed",     5, {MQTG_SUBSCRIBE, MQTG_PUBLISH, MQTG_AUTH, MQTG_UNSUBSCRIBE, MQTG_PINGREQ, 0}, 2 },
  /* Long v5 session with extra random packets */
  { "v5_long_sess", 5, {MQTG_SUBSCRIBE, 0}, 8 },
  /* v4 baseline with same structure (for differential comparison) */
  { "v4_baseline",  4, {MQTG_SUBSCRIBE, MQTG_PUBLISH, MQTG_PUBLISH, 0}, 1 },
  /* P8: Shared subscription sequences — exercise v2.1.x shared sub
   * distribution, round-robin delivery, No Local + shared interaction.
   * Multiple SUBSCRIBEs create overlapping shared groups; PUBLISHes
   * to matching topics trigger the shared subscription code paths. */
  { "v5_shared_sub", 5, {MQTG_SUBSCRIBE, MQTG_SUBSCRIBE, MQTG_SUBSCRIBE, MQTG_PUBLISH, MQTG_PUBLISH, MQTG_UNSUBSCRIBE, 0}, 2 },
};

#define N_V5_PLANS ARRAY_CNT(v5_seed_plans)

u32 mqtt_generate_v5_seeds(const char *seed_dir) {
  if (!seed_dir) return 0;

  u32 count = 0;
  u8 seq_buf[8192];

  for (u32 p = 0; p < N_V5_PLANS; p++) {
    const v5_seed_plan_t *plan = &v5_seed_plans[p];

    /* Generate 3 variants of each plan */
    for (u32 v = 0; v < 3; v++) {
      u32 total = 0;

      /* CONNECT */
      u32 n = gen_connect(seq_buf, sizeof(seq_buf), plan->ver);
      if (n == 0) continue;
      total += n;

      /* Forced packet types */
      for (u32 i = 0; plan->forced_types[i] != 0 && i < 8; i++) {
        u8 pt = plan->forced_types[i];
        u8 pver = plan->ver;
        if (pt == MQTG_AUTH && pver != MQTG_PROTO_V5) continue;
        n = mqtt_gen_packet(seq_buf + total, sizeof(seq_buf) - total, pver, pt);
        if (n > 0) total += n;
      }

      /* Extra random packets */
      for (u32 i = 0; i < plan->extra_random; i++) {
        u8 pt = mid_session_types[mg_rand(N_MID_SESSION)];
        if (pt == MQTG_AUTH && plan->ver != MQTG_PROTO_V5)
          pt = MQTG_PUBLISH;
        n = mqtt_gen_packet(seq_buf + total, sizeof(seq_buf) - total, plan->ver, pt);
        if (n > 0) total += n;
      }

      /* DISCONNECT */
      n = gen_disconnect(seq_buf + total, sizeof(seq_buf) - total, plan->ver);
      if (n > 0) total += n;

      if (total == 0) continue;

      /* Write seed file */
      char path[512];
      snprintf(path, sizeof(path), "%s/enriched_mqtt_%s_v%u.raw",
               seed_dir, plan->name, v);

      int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
      if (fd >= 0) {
        ssize_t written = write(fd, seq_buf, total);
        close(fd);
        if (written == (ssize_t)total) {
          count++;
          fprintf(stderr, "[+] MQTT v5 seed: %s (%u bytes)\n", path, total);
        }
      }
    }
  }

  fprintf(stderr, "[+] MQTT v5 seed generation: created %u seeds from %u plans\n",
          count, (u32)N_V5_PLANS);
  return count;
}
