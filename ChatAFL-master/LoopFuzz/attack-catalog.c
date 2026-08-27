/* attack-catalog.c — CVE-pattern attack seed catalog (Stage 2).
 *
 * Deterministic seed-file generation encoding the bug-trigger patterns
 * distilled from papers/漏洞发现经验 (ChatAFL's 9 0-days in
 * Live555/ProFTPD/Kamailio + MBFuzzer's 4 core MQTT bugs; see
 * papers/ChatAFLBugDetect.txt / MBFuzzerBugDetect.txt).
 *
 * Every seed is written into in_dir BEFORE read_testcases() runs, so it
 * flows through the EXISTING admission channel: queued, coverage-accounted,
 * and auto-deprioritized when it adds no new edges.  This is the exact
 * mechanism the MQTT binary enrichment (mqtt_generate_v5_seeds) already
 * uses, verified not to perturb b_abs/edges metrics.
 *
 * Gated by CHATAFL_ATTACK_SEEDS (default OFF — bit-identical behavior
 * when unset).  Per-protocol cap via CHATAFL_ATTACK_SEED_MAX (default 16).
 * Single message <= 16KB, whole seed <= 64KB; both enforced in the writer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "types.h"
#include "attack-catalog.h"

#define ATTACK_ARRAY_CNT(a) ((unsigned int)(sizeof(a) / sizeof((a)[0])))

/* ------------------------------------------------------------------ */
/* Gate + limits                                                       */
/* ------------------------------------------------------------------ */

/* Same lazy-getenv-cache convention as attack_oracle_enabled() in
 * protocol-oracle-precise.c.  Default OFF. */
static int attack_seeds_enabled(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *env = getenv("CHATAFL_ATTACK_SEEDS");
    cached = (env && (atoi(env) == 1 || strcasecmp(env, "on") == 0 ||
                      strcasecmp(env, "yes") == 0 ||
                      strcasecmp(env, "true") == 0)) ? 1 : 0;
  }
  return cached;
}

static unsigned int attack_seed_cap(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *env = getenv("CHATAFL_ATTACK_SEED_MAX");
    cached = (env && atoi(env) > 0) ? atoi(env) : 16;
  }
  return (unsigned int)cached;
}

#define ATTACK_MSG_MAX  (16 * 1024)  /* single message budget  */
#define ATTACK_SEED_MAX (64 * 1024)  /* whole-seed budget      */

/* ------------------------------------------------------------------ */
/* Deterministic payload fillers                                       */
/* ------------------------------------------------------------------ */

/* 'a'..'p' cycling filler — grep-able, and variant index shifts the
 * pattern so variants are byte-different (AFL content-hash dedup safe). */
static unsigned int fill_cycling(unsigned char *buf, unsigned int n,
                                 unsigned int seed) {
  for (unsigned int i = 0; i < n; i++)
    buf[i] = (unsigned char)('a' + ((i + seed) % 16));
  return n;
}

/* Scratch buffers for long payloads built at render time (long-topic /
 * long-path / oversized-chunk).  Static because the catalog is written
 * once at startup, single-threaded — same pattern as mqtt-generate.c's
 * plan tables. */
static unsigned char g_scratch[ATTACK_MSG_MAX];
static unsigned int  g_scratch_len = 0;

/* Repeat bookkeeping: after the first repeat of a step is rendered
 * (variant-differentiated), later repeats copy it verbatim so repeated
 * SETUPs stay byte-identical (the server sees the same request shape). */
static unsigned int g_last_rep_start = 0;
static unsigned int g_last_rep_len = 0;

/* ------------------------------------------------------------------ */
/* Raw (binary MQTT) packet builders                                   */
/* ------------------------------------------------------------------ */

static unsigned int mqtt_put_varint(unsigned char *out, unsigned int len) {
  unsigned int n = 0;
  do {
    unsigned char d = len % 128;
    len /= 128;
    if (len > 0) d |= 0x80;
    out[n++] = d;
  } while (len > 0 && n < 4);
  return n;
}

static unsigned int mqtt_put_packet(unsigned char *out, unsigned char byte0,
                                    const unsigned char *body,
                                    unsigned int body_len) {
  out[0] = byte0;
  unsigned int n = mqtt_put_varint(out + 1, body_len);
  if (body_len) memcpy(out + 1 + n, body, body_len);
  return 1 + n + body_len;
}

/* CONNECT, v3.1.1, clean session, client id "attack". */
static unsigned int mqtt_gen_connect(unsigned char *out) {
  unsigned char body[64];
  unsigned int n = 0;
  body[n++] = 0x00; body[n++] = 0x04;
  memcpy(body + n, "MQTT", 4); n += 4;
  body[n++] = 0x04;   /* protocol level 4 */
  body[n++] = 0x02;   /* clean session    */
  body[n++] = 0x00; body[n++] = 0x3C;  /* keepalive 60 */
  body[n++] = 0x00; body[n++] = 0x06;
  memcpy(body + n, "attack", 6); n += 6;
  return mqtt_put_packet(out, 0x10, body, n);
}

/* SUBSCRIBE, packet id 1, one topic filter at the given QoS. */
static unsigned int mqtt_gen_subscribe(unsigned char *out, unsigned int cap,
                                       const char *topic, unsigned int tl,
                                       unsigned char qos) {
  unsigned char body[ATTACK_MSG_MAX / 2];
  unsigned int n = 0;
  if (tl + 5 > sizeof(body) || tl + 7 > cap) return 0;
  body[n++] = 0x00; body[n++] = 0x01;
  body[n++] = (unsigned char)(tl >> 8);
  body[n++] = (unsigned char)(tl & 0xFF);
  memcpy(body + n, topic, tl); n += tl;
  body[n++] = qos & 0x03;
  return mqtt_put_packet(out, 0x82, body, n);
}

/* PUBLISH QoS0 (dup=0, retain per arg) with a plain payload. */
static unsigned int mqtt_gen_publish(unsigned char *out, unsigned int cap,
                                     const char *topic, unsigned int tl,
                                     const char *payload, unsigned int pl,
                                     int retain) {
  unsigned char body[ATTACK_MSG_MAX / 2];
  unsigned int n = 0;
  if (tl + pl + 2 > sizeof(body) || tl + pl + 4 > cap) return 0;
  body[n++] = (unsigned char)(tl >> 8);
  body[n++] = (unsigned char)(tl & 0xFF);
  memcpy(body + n, topic, tl); n += tl;
  if (pl) { memcpy(body + n, payload, pl); n += pl; }
  return mqtt_put_packet(out, retain ? 0x31 : 0x30, body, n);
}

static unsigned int mqtt_gen_disconnect(unsigned char *out) {
  return mqtt_put_packet(out, 0xE0, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* Step rendering                                                      */
/* ------------------------------------------------------------------ */

/* Render one step into out (cap bytes).  Returns bytes written, 0 on
 * overflow/unknown step.  Long payloads are substituted by the caller
 * (build_text_seed) before this runs, so only plain text/raw remain. */
static unsigned int render_step(unsigned char *out, unsigned int cap,
                                const attack_msg_step_t *st,
                                unsigned int variant) {
  if (!st) return 0;

  if (st->raw) {                                   /* raw binary */
    if (st->raw_len > cap) return 0;
    memcpy(out, st->raw, st->raw_len);
    return st->raw_len;
  }

  if (st->line_fmt) {                              /* printf-style text */
    char line[ATTACK_MSG_MAX + 16];
    int k;
    if (!st->payload) {
      k = snprintf(line, sizeof(line), "%s", st->line_fmt);
    } else if (variant && strstr(st->line_fmt, "%s")) {
      /* Variant differentiation: splice the variant digit into the first
       * %s payload ("aaaa" → "aaa1") so variants hash differently and AFL
       * keeps both seeds instead of content-deduping the second one. */
      char vp[16];
      snprintf(vp, sizeof(vp), "%s%u", st->payload, variant);
      k = snprintf(line, sizeof(line), st->line_fmt, vp);
    } else {
      k = snprintf(line, sizeof(line), st->line_fmt, st->payload);
    }
    if (k < 0 || (unsigned int)k >= sizeof(line)) return 0;
    if ((unsigned int)k > cap) return 0;
    memcpy(out, line, (unsigned int)k);
    return (unsigned int)k;
  }

  (void)variant; (void)out; (void)cap;
  return 0;
}

/* Variant differentiation for payload-less steps: bump the CSeq value
 * (the digits following "CSeq:") so repeat-heavy patterns also differ
 * between v0 and v1.  Returns the (unchanged) length. */
static unsigned int render_step_variant_bump(unsigned char *out,
                                             unsigned int cap,
                                             const attack_msg_step_t *st,
                                             unsigned int variant) {
  unsigned int n = render_step(out, cap, st, 0);
  if (!n || !variant) return n;
  /* find the LAST "CSeq:" marker; bump the digits following it */
  for (int i = (int)n - 6; i >= 0; i--) {
    if (out[i] == 'C' && memcmp(out + i, "CSeq:", 5) == 0) {
      int j = i + 5;
      while (j < (int)n && out[j] == ' ') j++;
      if (j < (int)n && out[j] >= '0' && out[j] <= '9') {
        /* additive rotation on the units digit: guaranteed byte change
         * for any variant != 0 */
        out[j] = (unsigned char)('0' + ((out[j] - '0' + variant) % 10));
        return n;
      }
    }
  }
  /* no CSeq (FTP/SIP/SMTP): rotate the first printable byte of the
   * message's first line — commands differ between variants */
  for (unsigned int k = 0; k < n; k++) {
    if (out[k] >= 'A' && out[k] <= 'Z') {
      out[k] = (unsigned char)('A' + ((out[k] - 'A' + variant) % 26));
      return n;
    }
  }
  return n;
}

/* ------------------------------------------------------------------ */
/* Per-protocol pattern tables                                         */
/*                                                                     */
/* Text formats match the seed corpora exactly:                        */
/*   RTSP — benchmark/subjects/RTSP/Live555/in-rtsp (request lines,    */
/*          CSeq headers, \r\n line endings, blank-line-separated)     */
/*   FTP  — in-ftp (bare command lines, \n endings, no CSeq)           */
/*   SIP  — in-sip (full header block + Content-Length, \n endings)    */
/*   SMTP — in-smtp (command lines; AUTH PLAIN base64 blob)            */
/*   MQTT — in-mqtt raw binary control packets, no framing            */
/* ------------------------------------------------------------------ */

/* ---- RTSP (Live555 31284aa) — 7 patterns from ChatAFL Table VII ---- */

/* Bug 1: SETUP→PLAY→PAUSE→PLAY heap-UAF (PAUSE frees the RTCP instance,
 * the following PLAY reuses it unvalidated). */
static const attack_msg_step_t pat_pause_play_uaf[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=38784-38785\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\nRange: npt=0.000-\r\n\r\n", NULL, NULL, 0, 1},
  {"PAUSE rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 5\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 6\r\nSession: 000022B8\r\nRange: npt=0.000-\r\n\r\n", NULL, NULL, 0, 1},
};

/* Bug 2 + Bug 7 (leak variant): repeated SETUP on an established
 * session.  Bug 2 is the UAF at low repeat counts; Bug 7 is the leak at
 * high repeat counts — the input shape is identical, so one pattern with
 * a high repeat count serves both (distinguished by ASAN at the target). */
static const attack_msg_step_t pat_repeat_setup[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=38784-38785\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\nTransport: RTP/AVP;unicast;client_port=38786-38787\r\n\r\n", NULL, NULL, 0, 8},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 5\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
};

/* Bug 3: DESCRIBE with malformed nested URL path → stack-UAR in the
 * URL parser.  Variant 1 nests deeper; variant 2 adds traversal. */
static const attack_msg_step_t pat_describe_nested_url[] = {
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest/track1/../track1/./mp3AudioTest/../mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
};

/* Bug 4: OPTIONS→DESCRIBE→SETUP with malformed Transport header params
 * → stack-UAR in transport parsing.  Variant 1: interleaved without
 * ports; variant 2: duplicate + unknown modes. */
static const attack_msg_step_t pat_setup_malformed_transport[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;interleaved=0-1;mode=\\22PLAY\\22,RECORD;ssrc=000022B8;destination=127.0.0.1;source=127.0.0.1;ttl=1\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=\\22PLAY\\22,\\22PLAY\\22;append;unicast;multicast\r\n\r\n", NULL, NULL, 0, 1},
};

/* Bug 5: oversized interleaved RTP chunk while streaming.  The binary
 * '$<channel><len16><data>' frame after PLAY is the RTP-over-TCP shape;
 * the data payload is filled to ATTACK_MSG_MAX by the writer hook. */
static const attack_msg_step_t pat_oversized_rtp[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  /* $ chan=0 len=0x4000 — the writer patches the payload after this
   * step by appending filler up to the message budget. */
  {"$\x00\x40\x00", NULL, NULL, 0, 1},
};

/* Bug 6: TEARDOWN then keep sending on the same session → UAF in
 * RTPInterface::sendDataOverTCP (the teardown-then-send race shape).
 * The interleaved frames after TEARDOWN are what re-enter the freed
 * TCP-session path. */
static const attack_msg_step_t pat_teardown_then_send[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"TEARDOWN rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 5\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"$\x00\x00\x10" "AAAAAAAAAAAAAAAA", NULL, NULL, 0, 3},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 6\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
};

/* ---- FTP (ProFTPD 61e621e) — 1 pattern ---- */

/* USER→PASS→CWD with an overlong path → heap overflow.  The payload
 * string is 2KB; the writer also emits a 8KB variant (n_variants=2 with
 * a longer payload table). */
static const attack_msg_step_t pat_cwd_long_path[] = {
  {"USER ubuntu\r\n", NULL, NULL, 0, 1},
  {"PASS ubuntu\r\n", NULL, NULL, 0, 1},
  {"CWD %s\r\n", "aaaa", NULL, 0, 1},   /* placeholder — patched at render time */
};

/* ---- SIP (Kamailio a220901) — 1 pattern ---- */

/* Malformed INVITE with abnormally nested Via/From header parameters →
 * memory leak in header parsing.  Two variants: nested branches vs
 * nested display-name quoting. */
static const attack_msg_step_t pat_invite_nested_via[] = {
  {"INVITE sip:33@127.0.0.1:5060 SIP/2.0\r\n", NULL, NULL, 0, 1},
  {"Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-1-2;received=127.0.0.1;rport=5061;branch=z9hG4bK-1-3;branch=z9hG4bK-1-4;branch=z9hG4bK-1-5;branch=z9hG4bK-1-6;branch=z9hG4bK-1-7;branch=z9hG4bK-1-8;maddr=127.0.0.1;tlsv=1.2\r\n", NULL, NULL, 0, 1},
  {"From: \\22nested \\22inner\\22 deep\\22 <sip:30@127.0.0.1>;tag=1;tag=2;tag=3;tag=4;tag=5\r\n", NULL, NULL, 0, 1},
  {"To: <sip:33@127.0.0.1:5060>\r\n", NULL, NULL, 0, 1},
  {"Call-ID: 1-attack@127.0.0.1\r\n", NULL, NULL, 0, 1},
  {"CSeq: 2 INVITE\r\n", NULL, NULL, 0, 1},
  {"Max-Forwards: 100\r\n", NULL, NULL, 0, 1},
  {"Content-Length: 0\r\n\r\n", NULL, NULL, 0, 1},
};

/* ---- SMTP (Exim d6a5a05) — 1 exploratory pattern ---- */

/* Oversized AUTH PLAIN (RFC 4616; initial-response SASL blob on one
 * line).  Exim found no bug in the ChatAFL paper; this is an
 * exploratory seed in the same shape family (long single-line token
 * after a grammar-valid greeting dance). */
static const attack_msg_step_t pat_auth_plain_oversized[] = {
  {"EHLO localhost\r\n", NULL, NULL, 0, 1},
  {"AUTH PLAIN %s\r\n", "AGFhYQBhYWE=", NULL, 0, 1},  /* patched at render time */
};

/* ------------------------------------------------------------------ */
/* MQTT raw-pattern assembly (built in code, not tables — packets are  */
/* binary and share a long-topic scratch buffer)                       */
/* ------------------------------------------------------------------ */

/* MBFuzzer Bug 2 (VerneMQ heap overflow): subscribe + publish must hit
 * the same overlong topic.  Multi-sender shape flattened to one
 * connection: SUBSCRIBE(long topic) then PUBLISH(same topic) — the
 * single-connection projection MBFuzzer's scheduler coordinates across
 * two senders. */
static unsigned int build_mqtt_long_topic(unsigned char *out,
                                          unsigned int cap,
                                          unsigned int topic_len) {
  unsigned int total = 0, n;
  if (topic_len > sizeof(g_scratch)) return 0;
  fill_cycling(g_scratch, topic_len, 0);

  n = mqtt_gen_connect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  n = mqtt_gen_subscribe(out + total, cap - total,
                         (const char *)g_scratch, topic_len, 1);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_publish(out + total, cap - total,
                       (const char *)g_scratch, topic_len, "hit", 3, 0);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_disconnect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  return total;
}

/* MBFuzzer Bug 1 (Mosquitto null-deref/race): persistent session,
 * retained publish to the subscribed topic.  Single-connection
 * projection of the two-sender retained-message race. */
static unsigned int build_mqtt_persistent_retained(unsigned char *out,
                                                   unsigned int cap) {
  unsigned int total = 0, n;
  const char *topic = "attack/retained";

  n = mqtt_gen_connect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  n = mqtt_gen_subscribe(out + total, cap - total, topic,
                         (unsigned int)strlen(topic), 1);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_publish(out + total, cap - total, topic,
                       (unsigned int)strlen(topic), "retained", 8, 1);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_disconnect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  return total;
}

/* MBFuzzer Bug 3 (EMQX duplicate forward): two shared-subscription
 * SUBSCRIBEs on $shared/group/... then a QoS2-shaped publish (packet id
 * via QoS1 subscribe keeps the builder small; the duplicate-forward
 * code path keys on the shared group, not the pub QoS bits). */
static unsigned int build_mqtt_shared_sub(unsigned char *out,
                                          unsigned int cap) {
  unsigned int total = 0, n;
  const char *t1 = "$shared/attackgrp/test";
  const char *t2 = "$shared/attackgrp2/test";

  n = mqtt_gen_connect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  n = mqtt_gen_subscribe(out + total, cap - total, t1,
                         (unsigned int)strlen(t1), 2);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_subscribe(out + total, cap - total, t2,
                         (unsigned int)strlen(t2), 2);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_publish(out + total, cap - total, "test", 4, "dup", 3, 0);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_disconnect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  return total;
}

/* MBFuzzer Bug 4 (NanoMQ $SYS bypass): wildcard multi-level subscribe
 * then publish to a $SYS topic. */
static unsigned int build_mqtt_sys_wildcard(unsigned char *out,
                                            unsigned int cap) {
  unsigned int total = 0, n;
  const char *wild = "+/+/+";
  const char *sys  = "$SYS/broker/status";

  n = mqtt_gen_connect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  n = mqtt_gen_subscribe(out + total, cap - total, wild,
                         (unsigned int)strlen(wild), 0);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_subscribe(out + total, cap - total, "#",
                         1, 0);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_publish(out + total, cap - total, sys,
                       (unsigned int)strlen(sys), "x", 1, 0);
  if (!n) return 0;
    total += n;
  n = mqtt_gen_disconnect(out + total);
  if (!n || n > cap - total) return 0;
    total += n;
  return total;
}

/* ------------------------------------------------------------------ */
/* Pattern table + writer                                              */
/* ------------------------------------------------------------------ */

static const attack_pattern_t attack_patterns[] = {
  /* RTSP — Live555 commit 31284aa (ChatAFL 7 0-days) */
  { "rtsp_pause_play_uaf", "RTSP", "ChatAFL-live555-UAF-1",
    pat_pause_play_uaf, ATTACK_ARRAY_CNT(pat_pause_play_uaf), 2 },
  { "rtsp_repeat_setup_uaf", "RTSP", "ChatAFL-live555-UAF-2",
    pat_repeat_setup, ATTACK_ARRAY_CNT(pat_repeat_setup), 2 },
  { "rtsp_describe_nested_url", "RTSP", "ChatAFL-live555-UAR-1",
    pat_describe_nested_url, ATTACK_ARRAY_CNT(pat_describe_nested_url), 2 },
  { "rtsp_setup_malformed_transport", "RTSP", "ChatAFL-live555-UAR-2",
    pat_setup_malformed_transport,
    ATTACK_ARRAY_CNT(pat_setup_malformed_transport), 2 },
  { "rtsp_oversized_rtp_chunk", "RTSP", "ChatAFL-live555-overflow",
    pat_oversized_rtp, ATTACK_ARRAY_CNT(pat_oversized_rtp), 1 },
  { "rtsp_repeat_setup_leak", "RTSP", "ChatAFL-live555-leak",
    pat_repeat_setup, ATTACK_ARRAY_CNT(pat_repeat_setup), 1 },
  { "rtsp_teardown_then_send", "RTSP", "ChatAFL-live555-UAF-3",
    pat_teardown_then_send, ATTACK_ARRAY_CNT(pat_teardown_then_send), 2 },

  /* FTP — ProFTPD commit 61e621e (ChatAFL 0-day) */
  { "ftp_cwd_long_path", "FTP", "ChatAFL-proftpd-overflow",
    pat_cwd_long_path, ATTACK_ARRAY_CNT(pat_cwd_long_path), 2 },

  /* SIP — Kamailio commit a220901 (ChatAFL 0-day) */
  { "sip_invite_nested_via", "SIP", "ChatAFL-kamailio-leak",
    pat_invite_nested_via, ATTACK_ARRAY_CNT(pat_invite_nested_via), 2 },

  /* SMTP — Exim d6a5a05 (no bug in paper; exploratory) */
  { "smtp_auth_plain_oversized", "SMTP", "exploratory",
    pat_auth_plain_oversized, ATTACK_ARRAY_CNT(pat_auth_plain_oversized), 2 },
};

/* Long-payload tables keyed by (pattern id, variant): rendered at build
 * time because they exceed sane table-string sizes. */
typedef struct {
  const char *pat_id;
  unsigned int variant;
  unsigned int len_a;   /* payload length for this variant */
} attack_len_spec_t;

/* FTP CWD path lengths: variant 0 → 2KB, variant 1 → 8KB. */
static const attack_len_spec_t ftp_cwd_lens[] = {
  { "ftp_cwd_long_path", 0, 2048 },
  { "ftp_cwd_long_path", 1, 8192 },
};

/* SMTP AUTH PLAIN blob lengths: variant 0 → 1KB, variant 1 → 8KB. */
static const attack_len_spec_t smtp_auth_lens[] = {
  { "smtp_auth_plain_oversized", 0, 1024 },
  { "smtp_auth_plain_oversized", 1, 8192 },
};

/* MQTT long-topic lengths: variant 0 → 256B, variant 1 → 512B. */
static const attack_len_spec_t mqtt_topic_lens[] = {
  { "mqtt_long_topic_sub_pub", 0, 256 },
  { "mqtt_long_topic_sub_pub", 1, 512 },
};

static const attack_len_spec_t *
find_len_spec(const attack_len_spec_t *tbl, unsigned int n,
              const char *id, unsigned int variant) {
  for (unsigned int i = 0; i < n; i++)
    if (strcmp(tbl[i].pat_id, id) == 0 && tbl[i].variant == variant)
      return &tbl[i];
  return NULL;
}

/* Write one seed file.  Returns 1 on success. */
static int write_seed_file(const char *seed_dir, const char *id,
                           unsigned int variant, const unsigned char *buf,
                           unsigned int len) {
  char path[512];
  snprintf(path, sizeof(path), "%s/attack_%s_v%u.raw", seed_dir, id, variant);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return 0;
  ssize_t written = write(fd, buf, len);
  close(fd);
  if (written != (ssize_t)len) {
    unlink(path);
    return 0;
  }
  fprintf(stderr, "[+] attack seed: %s (%u bytes)\n", path, len);
  return 1;
}

/* Build one text-protocol seed: render each step (with repeats), then
 * post-process the long-payload placeholder steps.  Returns total bytes
 * or 0 on overflow. */
static unsigned int build_text_seed(const attack_pattern_t *pat,
                                    unsigned int variant,
                                    unsigned char *out, unsigned int cap) {
  unsigned int total = 0;
  g_last_rep_len = 0;   /* stale bookkeeping from a previous seed */

  for (unsigned int s = 0; s < pat->n_steps; s++) {
    const attack_msg_step_t *st = &pat->steps[s];
    unsigned int reps = st->repeat ? st->repeat : 1;

    for (unsigned int r = 0; r < reps; r++) {
      /* Long-payload patching: when the payload is the 4-byte marker
       * "aaaa" (FTP CWD) / base64 stub (SMTP AUTH), substitute a
       * deterministic filler of the variant's configured length. */
      const char *subst = NULL;
      unsigned int subst_len = 0;

      if (st->payload && strcmp(st->payload, "aaaa") == 0) {
        const attack_len_spec_t *ls =
          find_len_spec(ftp_cwd_lens, ATTACK_ARRAY_CNT(ftp_cwd_lens),
                        pat->id, variant);
        unsigned int want = ls ? ls->len_a : 2048;
        if (want > sizeof(g_scratch)) want = sizeof(g_scratch);
        g_scratch_len = fill_cycling(g_scratch, want, variant);
        subst = (const char *)g_scratch;
        subst_len = g_scratch_len;
      } else if (st->payload && strcmp(st->payload, "AGFhYQBhYWE=") == 0) {
        const attack_len_spec_t *ls =
          find_len_spec(smtp_auth_lens, ATTACK_ARRAY_CNT(smtp_auth_lens),
                        pat->id, variant);
        unsigned int want = ls ? ls->len_a : 1024;
        if (want > sizeof(g_scratch)) want = sizeof(g_scratch);
        g_scratch_len = fill_cycling(g_scratch, want, variant);
        subst = (const char *)g_scratch;
        subst_len = g_scratch_len;
      }

      unsigned int n;
      if (subst) {
        /* Render "PREFIX%sSUFFIX" manually: split at the %s. */
        const char *fmt = st->line_fmt;
        const char *pct = fmt ? strstr(fmt, "%s") : NULL;
        if (!pct) return 0;
        unsigned int pre = (unsigned int)(pct - fmt);
        const char *suf = pct + 2;
        unsigned int suflen = (unsigned int)strlen(suf);
        if (total + pre + subst_len + suflen > cap) return 0;
        memcpy(out + total, fmt, pre); total += pre;
        memcpy(out + total, subst, subst_len); total += subst_len;
        memcpy(out + total, suf, suflen); total += suflen;
        n = 1; /* handled */
      } else if (r == 0) {
        /* first repeat: variant-differentiated render (CSeq bump or
         * payload splice) so v0/v1 files hash differently */
        n = render_step_variant_bump(out + total, cap - total, st, variant);
      } else {
        /* subsequent repeats must be byte-identical to the first */
        if (total + g_last_rep_len > cap) { n = 0; }
        else {
          memcpy(out + total, out + g_last_rep_start, g_last_rep_len);
          n = g_last_rep_len;
        }
      }
      if (r == 0 && n) {
        g_last_rep_start = total;
        g_last_rep_len = n;
      }
      if (n == 0 && !subst) {
        /* repeat-driven overflow: trim repeats, don't fail the seed */
        break;
      }
      if (subst) continue;
      total += n;
    }
  }
  return total;
}

/* Oversized-RTP patching: after the text steps of the oversized-rtp
 * pattern, append filler so the '$' frame's payload approaches the
 * message budget.  The '$\x00\x40\x00' header declares 16KB. */
static unsigned int patch_oversized_rtp(unsigned char *buf,
                                        unsigned int total,
                                        unsigned int cap) {
  /* find the last '$' frame header in the buffer */
  for (int i = (int)total - 1; i >= 2; i--) {
    if (buf[i] == '$' && buf[i + 1] == 0x00) {
      unsigned int hdr_end = (unsigned int)i + 4;
      unsigned int fill = cap - hdr_end;
      if (fill > 0) fill_cycling(buf + hdr_end, fill, 0);
      /* patch len field to match */
      buf[i + 2] = (unsigned char)(fill >> 8);
      buf[i + 3] = (unsigned char)(fill & 0xFF);
      return hdr_end + fill;
    }
  }
  return total;
}

/* ------------------------------------------------------------------ */
/* Deep-state sequence patterns (DSE-fix, 2026-08-25)                  */
/*                                                                    */
/* The v1 DSE plateau hook was a stub: it logged a template name but   */
/* never generated or injected anything, so the known race-trigger     */
/* sequences (PAUSE->PLAY toggles, post-TEARDOWN PLAY, deep FTP file   */
/* ops) had no directed supply.  These patterns render the deep-state  */
/* templates as seed files through the SAME proven in_dir /            */
/* read_testcases() admission channel as the CVE patterns above —      */
/* additive-only, coverage-accounted, auto-deprioritized when they     */
/* add no edges.  Files are named attack_deep_* so the payload guard   */
/* and Stage-0 triage treat them uniformly.                            */
/* Gated by CHATAFL_DEEP_STATE_EXPLORE (default ON), cap via           */
/* CHATAFL_DEEP_STATE_SEED_MAX (default 6).                            */
/* ------------------------------------------------------------------ */

static int deep_state_enabled(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *env = getenv("CHATAFL_DEEP_STATE_EXPLORE");
    cached = (env && atoi(env) == 0) ? 0 : 1;   /* default ON */
  }
  return cached;
}

static unsigned int deep_state_seed_cap(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *env = getenv("CHATAFL_DEEP_STATE_SEED_MAX");
    cached = (env && atoi(env) > 0) ? atoi(env) : 6;
  }
  return (unsigned int)cached;
}

/* RTSP: rapid PAUSE/PLAY toggles — the UAR window widens with each
 * session-state reversal; distinct from the single-PAUSE CVE seed. */
static const attack_msg_step_t pat_deep_rtsp_toggle[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=38784-38785\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PAUSE rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 5\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 6\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PAUSE rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 7\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 8\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
};

/* RTSP: TEARDOWN then reuse the dead session (logic/state shape —
 * distinct from the interleaved-frame teardown-then-send CVE seed). */
static const attack_msg_step_t pat_deep_rtsp_dead_session[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=38784-38785\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"TEARDOWN rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 5\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 6\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 7\r\n\r\n", NULL, NULL, 0, 1},
};

/* RTSP: PAUSE after PAUSE (double-pause state reversal). */
static const attack_msg_step_t pat_deep_rtsp_double_pause[] = {
  {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", NULL, NULL, 0, 1},
  {"DESCRIBE rtsp://127.0.0.1:8554/mp3AudioTest RTSP/1.0\r\nCSeq: 2\r\n\r\n", NULL, NULL, 0, 1},
  {"SETUP rtsp://127.0.0.1:8554/mp3AudioTest/track1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=38784-38785\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 4\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PAUSE rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 5\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PAUSE rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 6\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
  {"PLAY rtsp://127.0.0.1:8554/mp3AudioTest/ RTSP/1.0\r\nCSeq: 7\r\nSession: 000022B8\r\n\r\n", NULL, NULL, 0, 1},
};

/* FTP: deep authenticated file-state lifecycle. */
static const attack_msg_step_t pat_deep_ftp_file_lifecycle[] = {
  {"USER ubuntu\r\n", NULL, NULL, 0, 1},
  {"PASS ubuntu\r\n", NULL, NULL, 0, 1},
  {"CWD /tmp\r\n", NULL, NULL, 0, 1},
  {"MKD deep_a\r\n", NULL, NULL, 0, 1},
  {"CWD deep_a\r\n", NULL, NULL, 0, 1},
  {"MKD deep_b\r\n", NULL, NULL, 0, 1},
  {"CWD deep_b\r\n", NULL, NULL, 0, 1},
  {"PWD\r\n", NULL, NULL, 0, 1},
  {"CDUP\r\n", NULL, NULL, 0, 1},
  {"RMD deep_b\r\n", NULL, NULL, 0, 1},
  {"RMD deep_a\r\n", NULL, NULL, 0, 1},
};

/* FTP: data-channel abort mid-sequence (ABOR race shape). */
static const attack_msg_step_t pat_deep_ftp_abor[] = {
  {"USER ubuntu\r\n", NULL, NULL, 0, 1},
  {"PASS ubuntu\r\n", NULL, NULL, 0, 1},
  {"TYPE I\r\n", NULL, NULL, 0, 1},
  {"PORT 127,0,0,1,178,255\r\n", NULL, NULL, 0, 1},
  {"STOR deepfile\r\n", NULL, NULL, 0, 1},
  {"ABOR\r\n", NULL, NULL, 0, 1},
  {"RETR deepfile\r\n", NULL, NULL, 0, 1},
  {"ABOR\r\n", NULL, NULL, 0, 1},
  {"QUIT\r\n", NULL, NULL, 0, 1},
};

/* SMTP: mid-session RSET then re-MAIL (auth/session state reuse). */
static const attack_msg_step_t pat_deep_smtp_rset_reuse[] = {
  {"EHLO client\r\n", NULL, NULL, 0, 1},
  {"MAIL FROM:<a@local>\r\n", NULL, NULL, 0, 1},
  {"RCPT TO:<b@local>\r\n", NULL, NULL, 0, 1},
  {"DATA\r\n", NULL, NULL, 0, 1},
  {"RSET\r\n", NULL, NULL, 0, 1},
  {"MAIL FROM:<c@local>\r\n", NULL, NULL, 0, 1},
  {"RCPT TO:<d@local>\r\n", NULL, NULL, 0, 1},
  {"RSET\r\n", NULL, NULL, 0, 1},
  {"QUIT\r\n", NULL, NULL, 0, 1},
};

/* SIP: dialog re-INVITE after BYE (session reuse state shape). */
static const attack_msg_step_t pat_deep_sip_reinvite[] = {
  {"REGISTER sip:33@127.0.0.1:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-d1\r\nFrom: <sip:33@127.0.0.1>;tag=d1\r\nTo: <sip:33@127.0.0.1>\r\nCall-ID: deep-1@127.0.0.1\r\nCSeq: 1 REGISTER\r\nContact: <sip:33@127.0.0.1:5061>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", NULL, NULL, 0, 1},
  {"INVITE sip:34@127.0.0.1:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-d2\r\nFrom: <sip:33@127.0.0.1>;tag=d2\r\nTo: <sip:34@127.0.0.1>\r\nCall-ID: deep-2@127.0.0.1\r\nCSeq: 2 INVITE\r\nContact: <sip:33@127.0.0.1:5061>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", NULL, NULL, 0, 1},
  {"BYE sip:34@127.0.0.1:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-d3\r\nFrom: <sip:33@127.0.0.1>;tag=d2\r\nTo: <sip:34@127.0.0.1>\r\nCall-ID: deep-2@127.0.0.1\r\nCSeq: 3 BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", NULL, NULL, 0, 1},
  {"INVITE sip:34@127.0.0.1:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-d4\r\nFrom: <sip:33@127.0.0.1>;tag=d2\r\nTo: <sip:34@127.0.0.1>\r\nCall-ID: deep-2@127.0.0.1\r\nCSeq: 4 INVITE\r\nContact: <sip:33@127.0.0.1:5061>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", NULL, NULL, 0, 1},
};

/* HTTP/DAAP: resource lifecycle (read/read/delete/read). */
static const attack_msg_step_t pat_deep_http_lifecycle[] = {
  {"GET /databases/1/items HTTP/1.1\r\nHost: localhost\r\n\r\n", NULL, NULL, 0, 1},
  {"GET /databases/1/items?query=a HTTP/1.1\r\nHost: localhost\r\n\r\n", NULL, NULL, 0, 1},
  {"DELETE /databases/1/items/1 HTTP/1.1\r\nHost: localhost\r\n\r\n", NULL, NULL, 0, 1},
  {"GET /databases/1/items/1 HTTP/1.1\r\nHost: localhost\r\n\r\n", NULL, NULL, 0, 1},
  {"GET /databases/1/items HTTP/1.1\r\nHost: localhost\r\n\r\n", NULL, NULL, 0, 1},
};

static const attack_pattern_t deep_patterns[] = {
  { "deep_rtsp_toggle", "RTSP", "deep-state/pause-play-toggle",
    pat_deep_rtsp_toggle, ATTACK_ARRAY_CNT(pat_deep_rtsp_toggle), 1 },
  { "deep_rtsp_dead_session", "RTSP", "deep-state/teardown-reuse",
    pat_deep_rtsp_dead_session, ATTACK_ARRAY_CNT(pat_deep_rtsp_dead_session), 1 },
  { "deep_rtsp_double_pause", "RTSP", "deep-state/double-pause",
    pat_deep_rtsp_double_pause, ATTACK_ARRAY_CNT(pat_deep_rtsp_double_pause), 1 },
  { "deep_ftp_file_lifecycle", "FTP", "deep-state/file-lifecycle",
    pat_deep_ftp_file_lifecycle, ATTACK_ARRAY_CNT(pat_deep_ftp_file_lifecycle), 1 },
  { "deep_ftp_abor", "FTP", "deep-state/data-abort",
    pat_deep_ftp_abor, ATTACK_ARRAY_CNT(pat_deep_ftp_abor), 1 },
  { "deep_smtp_rset_reuse", "SMTP", "deep-state/rset-reuse",
    pat_deep_smtp_rset_reuse, ATTACK_ARRAY_CNT(pat_deep_smtp_rset_reuse), 1 },
  { "deep_sip_reinvite", "SIP", "deep-state/reinvite-after-bye",
    pat_deep_sip_reinvite, ATTACK_ARRAY_CNT(pat_deep_sip_reinvite), 1 },
  { "deep_http_lifecycle", "HTTP", "deep-state/resource-lifecycle",
    pat_deep_http_lifecycle, ATTACK_ARRAY_CNT(pat_deep_http_lifecycle), 1 },
};

unsigned int deep_state_enrich_seeds(const char *seed_dir, const char *protocol) {
  if (!deep_state_enabled()) return 0;
  if (!seed_dir || !protocol) return 0;

  unsigned int count = 0;
  unsigned int cap = deep_state_seed_cap();
  static unsigned char seed_buf[ATTACK_SEED_MAX];

  for (unsigned int p = 0;
       p < ATTACK_ARRAY_CNT(deep_patterns) && count < cap; p++) {
    const attack_pattern_t *pat = &deep_patterns[p];
    if (strcasecmp(pat->protocol, protocol) != 0 &&
        !(strcasecmp(protocol, "DAAP") == 0 &&
          strcasecmp(pat->protocol, "HTTP") == 0))
      continue;

    unsigned int len = build_text_seed(pat, 0, seed_buf, sizeof(seed_buf));
    if (!len) continue;
    if (write_seed_file(seed_dir, pat->id, 0, seed_buf, len))
      count++;
  }

  if (count)
    fprintf(stderr, "[+] deep-state seed generation (%s): %u files\n",
            protocol, count);
  return count;
}

/* ------------------------------------------------------------------ */
/* Payload patterns for the havoc payload guard (P0-2, 2026-08-25)    */
/*                                                                    */
/* Short, grep-cheap byte anchors whose corruption by havoc destroys  */
/* an attack seed's trigger semantics: traversal payloads, the RTSP   */
/* session token (without it PAUSE/PLAY never re-enters the session   */
/* path), and the MQTT $SYS topic.  Evidence (2026-08-21 pure-ftpd):  */
/* only the pristine seed kept "../.." among 130 RNTO queue entries.  */
/* ------------------------------------------------------------------ */

unsigned int attack_payload_patterns(const char *protocol,
                                     const char *patterns_out[4]) {
  static const char *ftp_pats[]  = { "../..", "abcdefgh", NULL };
  static const char *rtsp_pats[] = { "000022B8", "../", NULL };
  static const char *mqtt_pats[] = { "$SYS/", "$share/", NULL };
  unsigned int n = 0;

  if (!protocol || !patterns_out) return 0;
  for (unsigned int k = 0; k < 4; k++) patterns_out[k] = NULL;

  const char **pats = NULL;
  if (strcasecmp(protocol, "FTP") == 0) pats = ftp_pats;
  else if (strcasecmp(protocol, "RTSP") == 0) pats = rtsp_pats;
  else if (strcasecmp(protocol, "MQTT") == 0) pats = mqtt_pats;

  if (!pats) return 0;
  for (; pats[n] && n < 4; n++) patterns_out[n] = pats[n];
  return n;
}

/* ------------------------------------------------------------------ */
/* Public entry                                                        */
/* ------------------------------------------------------------------ */

unsigned int attack_enrich_seeds(const char *seed_dir, const char *protocol) {
  if (!attack_seeds_enabled()) return 0;
  if (!seed_dir || !protocol) return 0;

  unsigned int count = 0;
  unsigned int cap = attack_seed_cap();
  static unsigned char seed_buf[ATTACK_SEED_MAX];

  /* --- MQTT: binary builders, not the text tables --- */
  if (strcasecmp(protocol, "MQTT") == 0) {
    /* long-topic variants (VerneMQ heap-overflow shape) */
    for (unsigned int v = 0; v < 2 && count < cap; v++) {
      const attack_len_spec_t *ls =
        find_len_spec(mqtt_topic_lens, ATTACK_ARRAY_CNT(mqtt_topic_lens),
                      "mqtt_long_topic_sub_pub", v);
      unsigned int tlen = ls ? ls->len_a : 256;
      unsigned int len = build_mqtt_long_topic(seed_buf,
                                               sizeof(seed_buf), tlen);
      if (len && write_seed_file(seed_dir, "mqtt_long_topic_sub_pub", v,
                                 seed_buf, len))
        count++;
    }
    if (count < cap) {
      unsigned int len = build_mqtt_persistent_retained(seed_buf,
                                                        sizeof(seed_buf));
      if (len && write_seed_file(seed_dir, "mqtt_persistent_retained", 0,
                                 seed_buf, len))
        count++;
    }
    if (count < cap) {
      unsigned int len = build_mqtt_shared_sub(seed_buf, sizeof(seed_buf));
      if (len && write_seed_file(seed_dir, "mqtt_shared_sub", 0,
                                 seed_buf, len))
        count++;
    }
    if (count < cap) {
      unsigned int len = build_mqtt_sys_wildcard(seed_buf, sizeof(seed_buf));
      if (len && write_seed_file(seed_dir, "mqtt_sys_wildcard", 0,
                                 seed_buf, len))
        count++;
    }
    fprintf(stderr, "[+] attack seed generation (MQTT): %u files\n", count);
    return count;
  }

  /* --- text protocols: table-driven --- */
  for (unsigned int p = 0;
       p < ATTACK_ARRAY_CNT(attack_patterns) && count < cap; p++) {
    const attack_pattern_t *pat = &attack_patterns[p];
    if (strcasecmp(pat->protocol, protocol) != 0) continue;

    for (unsigned int v = 0; v < pat->n_variants && count < cap; v++) {
      unsigned int len = build_text_seed(pat, v, seed_buf,
                                         sizeof(seed_buf));
      if (!len) continue;

      if (strcmp(pat->id, "rtsp_oversized_rtp_chunk") == 0)
        len = patch_oversized_rtp(seed_buf, len, sizeof(seed_buf));

      if (write_seed_file(seed_dir, pat->id, v, seed_buf, len))
        count++;
    }
  }

  fprintf(stderr, "[+] attack seed generation (%s): %u files\n",
          protocol, count);
  return count;
}
