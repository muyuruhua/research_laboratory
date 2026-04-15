/* mp-driver-mqtt.c — MQTT multi-party driver implementation.
 *
 * Implements the mp_driver_t callbacks for MQTT pub/sub fuzzing.
 *
 * Role mapping (from OASIS spec model in mqtt-builder.c):
 *   role 0 = ctrl  → CONNECT, DISCONNECT, PINGREQ, etc.
 *   role 1 = sub   → SUBSCRIBE, UNSUBSCRIBE
 *   role 2 = pub   → PUBLISH, PUBREL
 *
 * fd layout: fds[0]=sub_fd, fds[1]=pub_fd, fds[2]=ctrl_fd
 *
 * The driver is purely static — no global mutable state.
 * All per-execution state lives in mp_context_t.priv.
 */

#include "mp-driver.h"
#include "mqtt-builder.h"   /* mqtt_role_for_packet_type, mqtt_init_spec_state_model */
#include "alloc-inl.h"      /* ck_free, ck_alloc */

#include <string.h>
#include <strings.h>        /* strcasecmp */
#include <unistd.h>         /* close */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>      /* A3: TCP_NODELAY */
#include <arpa/inet.h>
#include <netdb.h>

/* ── External globals we need (defined in afl-fuzz.c) ── */
extern u32 local_port;
extern u8  mqtt_cross_session_enabled;  /* P2b: set in afl-fuzz.c init */
extern u8  mqtt_field_mutate_enabled;   /* P0+P2: gates v5 handshake */

/* ── Forward: net_send / net_recv from aflnet.c ── */
extern int  net_send(int sockfd, struct timeval timeout,
                     char *mem, unsigned int len);
extern int  net_recv(int sockfd, struct timeval timeout,
                     int poll_w, char **response_buf,
                     unsigned int *response_buf_size);

/* ════════════════════════════════════════════════════════════════════
 * Per-execution private state
 * ════════════════════════════════════════════════════════════════════ */

/* O2: Forward differential result for one PUBLISH → subscribe path */
typedef struct {
  u8   received;        /* 1 if sub_fd got a forwarded PUBLISH */
  u8   fwd_pkt_type;    /* high nibble of received byte 0 (should be 3 = PUBLISH) */
  u8   fwd_qos;         /* QoS of forwarded message */
  u8   fwd_retain;      /* Retain flag of forwarded message */
  u32  fwd_payload_len; /* Payload length of forwarded message */
  u32  fwd_topic_hash;  /* FNV-1a hash of forwarded topic name */
} mqtt_fwd_diff_entry_t;

#define MQTT_FWD_DIFF_MAX 16  /* Max forward-diff entries per execution */

typedef struct {
  char        *handshake_resp;       /* secondary handshake buffer */
  unsigned int handshake_resp_len;

  /* O2: Forward differential tracking */
  mqtt_fwd_diff_entry_t fwd_entries[MQTT_FWD_DIFF_MAX];
  u32                   fwd_count;
  u32                   fwd_hash;    /* combined hash of all fwd results */
} mqtt_mp_priv_t;

/* ════════════════════════════════════════════════════════════════════
 * Helper: open one TCP connection with retry
 * (mirrors mqtt_open_cluster_socket from afl-fuzz.c but takes
 *  an explicit local_port argument for testability)
 * ════════════════════════════════════════════════════════════════════ */
static int mqtt_mp_open_one(const char *ip, u32 port, u32 bind_port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serv_addr, local_addr;
  struct hostent *he = NULL;
  int n;

  if (sockfd < 0) return -1;

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port   = htons(port);
  if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) != 1) {
    he = gethostbyname(ip);
    if (!he || !he->h_addr_list || !he->h_addr_list[0]) {
      close(sockfd);
      return -1;
    }
    memcpy(&serv_addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
  }

  if (bind_port > 0) {
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family      = AF_INET;
    local_addr.sin_port        = htons(bind_port);
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr))) {
      close(sockfd);
      return -1;
    }
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    /* A9: Tighter retry — 200 × 500 µs = 100 ms ceiling */
    for (n = 0; n < 200; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0)
        break;
      usleep(500);
    }
    if (n == 200) { close(sockfd); return -1; }
  }

  /* A3: Disable Nagle — send small MQTT packets immediately */
  { int one = 1; setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }

  return sockfd;
}

/* ════════════════════════════════════════════════════════════════════
 * Lightweight packet builders (inline, no malloc — suitable for the
 * hot fuzz loop where every µs counts).
 * ════════════════════════════════════════════════════════════════════ */
static u32 pack_connect(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  u32 rem     = 10 + 2 + cid_len;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  out[0] = 0x10; out[1] = (u8)rem;
  out[2] = 0x00; out[3] = 0x04;
  out[4] = 'M'; out[5] = 'Q'; out[6] = 'T'; out[7] = 'T';
  out[8] = 0x04; out[9] = 0x02;  /* Protocol level 4, CleanSession=1 */
  out[10] = 0x00; out[11] = 0x3C;
  out[12] = (u8)((cid_len >> 8) & 0xFF);
  out[13] = (u8)(cid_len & 0xFF);
  memcpy(out + 14, cid, cid_len);
  return 14 + cid_len;
}

/* P2b: CONNECT with CleanSession=0 for session resume probing.
 * This tells the broker to restore any stored session state (pending QoS1/2
 * messages, subscriptions) for the given client ID. */
static u32 pack_connect_persistent(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  u32 rem     = 10 + 2 + cid_len;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  out[0] = 0x10; out[1] = (u8)rem;
  out[2] = 0x00; out[3] = 0x04;
  out[4] = 'M'; out[5] = 'Q'; out[6] = 'T'; out[7] = 'T';
  out[8] = 0x04; out[9] = 0x00;  /* Protocol level 4, CleanSession=0 */
  out[10] = 0x00; out[11] = 0x3C;
  out[12] = (u8)((cid_len >> 8) & 0xFF);
  out[13] = (u8)(cid_len & 0xFF);
  memcpy(out + 14, cid, cid_len);
  return 14 + cid_len;
}

static u32 pack_subscribe(u8 *out, u32 cap, u16 pid, const char *topic, u8 qos) {
  u32 tlen = (u32)strlen(topic);
  u32 rem  = 2 + 2 + tlen + 1;
  if (!out || cap < (2 + rem) || tlen > 65535) return 0;
  out[0] = 0x82; out[1] = (u8)rem;
  out[2] = (u8)((pid >> 8) & 0xFF); out[3] = (u8)(pid & 0xFF);
  out[4] = (u8)((tlen >> 8) & 0xFF); out[5] = (u8)(tlen & 0xFF);
  memcpy(out + 6, topic, tlen);
  out[6 + tlen] = (u8)(qos & 0x03);
  return 7 + tlen;
}

/* P0+P2: v5 CONNECT — exercises mosquitto's handle__connect() v5 branch,
 * property__read_all(), and v5 session management code paths. */
static u32 pack_connect_v5(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  /* v5 Properties to include (fixed set for handshake reliability):
   *   0x11 Session Expiry Interval = 0xFFFFFFFF (max)
   *   0x21 Receive Maximum = 65535
   *   0x22 Topic Alias Maximum = 10
   *   0x19 Request Response Information = 1
   *   0x17 Request Problem Information = 1 */
  u8 props[] = {
    0x11, 0xFF, 0xFF, 0xFF, 0xFF,  /* Session Expiry Interval */
    0x21, 0xFF, 0xFF,              /* Receive Maximum */
    0x22, 0x00, 0x0A,              /* Topic Alias Maximum = 10 */
    0x19, 0x01,                    /* Request Response Information */
    0x17, 0x01,                    /* Request Problem Information */
  };
  u32 props_len = (u32)sizeof(props);
  u32 rem = 10 + 1 + props_len + 2 + cid_len;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;

  u32 pos = 0;
  out[pos++] = 0x10;         /* CONNECT */
  out[pos++] = (u8)rem;      /* remaining length */
  out[pos++] = 0x00; out[pos++] = 0x04;
  out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'T'; out[pos++] = 'T';
  out[pos++] = 0x05;         /* Protocol Level 5 */
  out[pos++] = 0x02;         /* Connect Flags: Clean Start = 1 */
  out[pos++] = 0x00; out[pos++] = 0x3C; /* Keep Alive = 60s */
  out[pos++] = (u8)props_len;  /* Properties Length */
  memcpy(out + pos, props, props_len); pos += props_len;
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  return pos;
}

/* P0+P2: v5 SUBSCRIBE with subscription options —
 * exercises No Local, Retain As Published, Retain Handling code paths. */
static u32 pack_subscribe_v5(u8 *out, u32 cap, u16 pid,
                              const char *topic, u8 qos) {
  u32 tlen = (u32)strlen(topic);
  /* v5 SUBSCRIBE: packet_id(2) + props_len(1, =0) + topic_filter + sub_options(1) */
  u32 rem = 2 + 1 + 2 + tlen + 1;
  if (!out || cap < (2 + rem) || tlen > 65535) return 0;

  u32 pos = 0;
  out[pos++] = 0x82;         /* SUBSCRIBE */
  out[pos++] = (u8)rem;      /* remaining length */
  out[pos++] = (u8)((pid >> 8) & 0xFF);
  out[pos++] = (u8)(pid & 0xFF);
  out[pos++] = 0x00;         /* Properties Length = 0 */
  out[pos++] = (u8)((tlen >> 8) & 0xFF);
  out[pos++] = (u8)(tlen & 0xFF);
  memcpy(out + pos, topic, tlen); pos += tlen;
  /* Subscription Options: QoS | No Local(0) | RAP(1) | RetainHandling(0) */
  out[pos++] = (u8)((qos & 0x03) | 0x08);  /* RAP=1 to test retain-as-published */
  return pos;
}

/* ════════════════════════════════════════════════════════════════════
 * mp_driver_t callback implementations
 * ════════════════════════════════════════════════════════════════════ */

/* fds[0]=sub, fds[1]=pub, fds[2]=ctrl */
#define SUB_IDX  0
#define PUB_IDX  1
#define CTRL_IDX 2

static int mqtt_open_connections(mp_context_t *ctx) {
  u32 saved = local_port;

  /* Determine whether the target is "local" (127.0.0.1 / localhost).
   * For remote brokers (Docker hostnames like mqttb1, mqttb2) we must NOT
   * bind ctrl_fd to 127.0.0.1:local_port — binding a loopback source to
   * a non-loopback destination fails on Linux.  local_port binding is only
   * needed for SIP-style protocols on the single-fd path, not for MQTT. */
  int is_local = 0;
  if (ctx->server_ip) {
    if (strcmp(ctx->server_ip, "127.0.0.1") == 0 ||
        strcmp(ctx->server_ip, "localhost") == 0)
      is_local = 1;
  }
  u32 ctrl_bind_port = is_local ? saved : 0;

  /* sub + pub use ephemeral ports; ctrl uses configured local_port only for local targets */
  local_port = 0;
  ctx->fds[SUB_IDX] = mqtt_mp_open_one(ctx->server_ip, ctx->server_port, 0);
  ctx->fds[PUB_IDX] = mqtt_mp_open_one(ctx->server_ip, ctx->server_port, 0);
  local_port = saved;
  ctx->fds[CTRL_IDX] = mqtt_mp_open_one(ctx->server_ip, ctx->server_port, ctrl_bind_port);

  for (int i = 0; i < ctx->fd_count; i++) {
    if (ctx->fds[i] < 0) return -1;
    setsockopt(ctx->fds[i], SOL_SOCKET, SO_SNDTIMEO,
               (char *)&ctx->timeout, sizeof(ctx->timeout));
    setsockopt(ctx->fds[i], SOL_SOCKET, SO_RCVTIMEO,
               (char *)&ctx->timeout, sizeof(ctx->timeout));
  }
  return 0;
}

static int mqtt_handshake(mp_context_t *ctx) {
  u8  pkt[256];
  u32 pkt_len;
  mqtt_mp_priv_t *priv = (mqtt_mp_priv_t *)ck_alloc(sizeof(mqtt_mp_priv_t));
  memset(priv, 0, sizeof(*priv));
  ctx->priv = priv;

  /* CONNECT on all 3 fds with distinct client IDs.
   * P0+P2: sub_fd uses v5 CONNECT (when field mutation is enabled) to
   * exercise mosquitto's v5 code paths: property__read_all(),
   * v5 session management, v5→v4 message conversion on forwarding.
   * pub_fd and ctrl_fd stay v4 for stability. */
  static const char *cids[3] = { "afl_sub", "afl_pub", "afl_ctrl" };
  for (int i = 0; i < ctx->fd_count; i++) {
    if (i == SUB_IDX && mqtt_field_mutate_enabled)
      pkt_len = pack_connect_v5(pkt, sizeof(pkt), cids[i]);
    else
      pkt_len = pack_connect(pkt, sizeof(pkt), cids[i]);
    if (!pkt_len ||
        net_send(ctx->fds[i], ctx->timeout, (char *)pkt, pkt_len) != (int)pkt_len)
      return -1;
    /* sub_fd responses go to shared buffer; others go to priv buffer */
    if (i == SUB_IDX)
      net_recv(ctx->fds[i], ctx->timeout, ctx->poll_wait_msecs,
               ctx->response_buf, (unsigned int *)ctx->response_buf_size);
    else
      net_recv(ctx->fds[i], ctx->timeout, ctx->poll_wait_msecs,
               &priv->handshake_resp, &priv->handshake_resp_len);
  }

  /* SUBSCRIBE on sub_fd to wildcard '#' (all topics)
   * P2b: Use QoS 1 so the broker stores messages for persistent sessions
   * P0+P2: Use v5 SUBSCRIBE with subscription options when field mutation enabled */
  u8 sub_qos = mqtt_cross_session_enabled ? 1 : 0;
  if (mqtt_field_mutate_enabled)
    pkt_len = pack_subscribe_v5(pkt, sizeof(pkt), 1, "#", sub_qos);
  else
    pkt_len = pack_subscribe(pkt, sizeof(pkt), 1, "#", sub_qos);
  if (!pkt_len ||
      net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len) != (int)pkt_len)
    return -1;
  net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
           ctx->response_buf, (unsigned int *)ctx->response_buf_size);

  return 0;
}

static int mqtt_role_for_message(mp_context_t *ctx,
                                 const unsigned char *msg, u32 msg_len) {
  (void)ctx;
  if (!msg || msg_len == 0) return -1;

  u8 type_nibble = (u8)(msg[0] >> 4);

  /* CONNECT(1) and DISCONNECT(14) are handled by handshake/cleanup */
  if (type_nibble == 1 || type_nibble == 14)
    return -1;  /* skip */

  int role = mqtt_role_for_packet_type(type_nibble);

  /* Map OASIS role → fd index:
   * OASIS role 0 (ctrl)  → CTRL_IDX (2)
   * OASIS role 1 (sub)   → SUB_IDX  (0)
   * OASIS role 2 (pub)   → PUB_IDX  (1) */
  if      (role == 2) return PUB_IDX;
  else if (role == 1) return SUB_IDX;
  else                return CTRL_IDX;
}

static int mqtt_after_send(mp_context_t *ctx, int role) {
  /* After PUBLISH on pub_fd, drain sub_fd for forwarded messages —
   * this triggers subs__send() / sub__messages_queue() in the broker */
  if (role == PUB_IDX) {
    /* O2: Capture forwarded PUBLISH for differential analysis.
     * Instead of discarding the sub_fd response, we parse it to extract
     * forwarding metadata: QoS, retain, topic hash, payload length.
     * This allows the diff engine to detect forwarding inconsistencies
     * between broker versions / configurations — matching MBFuzzer's
     * core "bridge mode" differential strategy.
     *
     * We use a temporary buffer (not ctx->response_buf) to avoid
     * interfering with the main response collection path. */
    char         *fwd_buf  = NULL;
    unsigned int  fwd_len  = 0;
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             &fwd_buf, &fwd_len);

    mqtt_mp_priv_t *priv = (mqtt_mp_priv_t *)ctx->priv;
    if (fwd_buf && fwd_len >= 2 && priv && priv->fwd_count < MQTT_FWD_DIFF_MAX) {
      /* Parse each MQTT packet in the forwarded buffer */
      u32 off = 0;
      while (off + 2 <= fwd_len && priv->fwd_count < MQTT_FWD_DIFF_MAX) {
        u8 byte0 = (u8)fwd_buf[off];
        u8 ptype = (byte0 >> 4) & 0x0F;

        /* Decode remaining length (variable-length integer) */
        u32 rem_len = 0, multiplier = 1, hdr_bytes = 1;
        u32 roff = off + 1;
        while (roff < fwd_len && hdr_bytes <= 4) {
          u8 enc = (u8)fwd_buf[roff];
          rem_len += (enc & 0x7F) * multiplier;
          multiplier *= 128;
          hdr_bytes++;
          roff++;
          if (!(enc & 0x80)) break;
        }

        u32 pkt_total = hdr_bytes + rem_len;
        if (off + pkt_total > fwd_len) break; /* truncated packet */

        if (ptype == 3) { /* PUBLISH */
          mqtt_fwd_diff_entry_t *e = &priv->fwd_entries[priv->fwd_count];
          e->received    = 1;
          e->fwd_pkt_type = ptype;
          e->fwd_qos     = (byte0 >> 1) & 0x03;
          e->fwd_retain  = byte0 & 0x01;

          /* Extract topic: 2-byte length prefix + topic name */
          u32 body_off = off + hdr_bytes;
          if (body_off + 2 <= fwd_len) {
            u32 tlen = ((u8)fwd_buf[body_off] << 8) | (u8)fwd_buf[body_off + 1];
            /* FNV-1a hash of topic name */
            u32 h = 0x811C9DC5;
            for (u32 ti = 0; ti < tlen && body_off + 2 + ti < fwd_len; ti++) {
              h ^= (u8)fwd_buf[body_off + 2 + ti];
              h *= 0x01000193;
            }
            e->fwd_topic_hash = h;

            /* Payload length = remaining_len - topic_header - pkt_id (if QoS>0) */
            u32 consumed = 2 + tlen;
            if (e->fwd_qos > 0) consumed += 2;
            e->fwd_payload_len = (rem_len > consumed) ? (rem_len - consumed) : 0;
          }

          priv->fwd_count++;
        }

        off += pkt_total;
      }

      /* O2: Compute combined forward-diff fingerprint.
       * This is a single hash over all fwd_entries that the diff engine
       * can compare across brokers to detect forwarding divergences. */
      {
        u32 h = 0x811C9DC5;
        for (u32 i = 0; i < priv->fwd_count; i++) {
          mqtt_fwd_diff_entry_t *e = &priv->fwd_entries[i];
          h ^= e->fwd_qos;        h *= 0x01000193;
          h ^= e->fwd_retain;     h *= 0x01000193;
          h ^= e->fwd_topic_hash; h *= 0x01000193;
          h ^= e->fwd_payload_len; h *= 0x01000193;
        }
        h ^= priv->fwd_count;     h *= 0x01000193;
        priv->fwd_hash = h;
      }
    }

    if (fwd_buf) ck_free(fwd_buf);
  }
  return 0;
}

static void mqtt_drain_all(mp_context_t *ctx) {
  net_recv(ctx->fds[CTRL_IDX], ctx->timeout, ctx->poll_wait_msecs,
           ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  net_recv(ctx->fds[PUB_IDX],  ctx->timeout, ctx->poll_wait_msecs,
           ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  net_recv(ctx->fds[SUB_IDX],  ctx->timeout, ctx->poll_wait_msecs,
           ctx->response_buf, (unsigned int *)ctx->response_buf_size);
}

static void mqtt_cleanup(mp_context_t *ctx) {

  /* ============================================
   * P2b: Cross-session state fuzzing probe.
   *
   * BEFORE the final disconnect, simulate a session-resume cycle:
   *   1. DISCONNECT the sub client
   *   2. Close its fd
   *   3. Re-open a new TCP connection
   *   4. CONNECT with same client ID + CleanSession=0
   *   5. SUBSCRIBE "#" again (QoS 1)
   *   6. Drain — the broker should redeliver any unACK'd QoS 1/2 msgs
   *      and any retained messages, exercising session management code.
   *   7. Update ctx->fds[SUB_IDX] so caller closes the new fd.
   *
   * This exercises mosquitto code paths:
   *   - handle__connect() session-present logic
   *   - db__message_reconnect_reset()
   *   - sub__messages_queue() with stored messages
   *   - context__send_will() edge cases
   *
   * Gated: only runs when mqtt_cross_session_enabled == 1.
   * Overhead: ~1-2ms for the reconnection (negligible at 10 exec/s).
   * ============================================ */
  if (mqtt_cross_session_enabled) {
    u8  pkt[256];
    u32 pkt_len;

    /* Step 1: Disconnect sub client */
    u8 disc[2] = { 0xE0, 0x00 };
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)disc, 2);

    /* Step 2: Close sub fd */
    close(ctx->fds[SUB_IDX]);
    ctx->fds[SUB_IDX] = -1;

    /* Step 3: Reopen TCP connection (ephemeral port, short retry) */
    int new_fd = -1;
    for (int attempt = 0; attempt < 50; attempt++) {
      new_fd = mqtt_mp_open_one(ctx->server_ip, ctx->server_port, 0);
      if (new_fd >= 0) break;
      usleep(500);
    }

    if (new_fd >= 0) {
      setsockopt(new_fd, SOL_SOCKET, SO_SNDTIMEO,
                 (char *)&ctx->timeout, sizeof(ctx->timeout));
      setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO,
                 (char *)&ctx->timeout, sizeof(ctx->timeout));

      /* Step 4: CONNECT with CleanSession=0 — resume previous session */
      pkt_len = pack_connect_persistent(pkt, sizeof(pkt), "afl_sub");
      if (pkt_len > 0) {
        net_send(new_fd, ctx->timeout, (char *)pkt, pkt_len);
        /* Read CONNACK — Session Present flag should be 1 */
        char *resp_buf = NULL;
        unsigned int resp_len = 0;
        net_recv(new_fd, ctx->timeout, ctx->poll_wait_msecs,
                 &resp_buf, &resp_len);
        if (resp_buf) ck_free(resp_buf);
      }

      /* Step 5: Re-SUBSCRIBE "#" at QoS 1 */
      pkt_len = pack_subscribe(pkt, sizeof(pkt), 2, "#", 1);
      if (pkt_len > 0) {
        net_send(new_fd, ctx->timeout, (char *)pkt, pkt_len);
        char *resp_buf = NULL;
        unsigned int resp_len = 0;
        net_recv(new_fd, ctx->timeout, ctx->poll_wait_msecs,
                 &resp_buf, &resp_len);
        if (resp_buf) ck_free(resp_buf);
      }

      /* Step 6: Drain — collect any redelivered/retained messages */
      {
        char *resp_buf = NULL;
        unsigned int resp_len = 0;
        net_recv(new_fd, ctx->timeout, ctx->poll_wait_msecs,
                 &resp_buf, &resp_len);
        if (resp_buf) ck_free(resp_buf);
      }

      /* Step 7: Update fd so the caller's close() works on the new fd */
      ctx->fds[SUB_IDX] = new_fd;
    }
    /* else: reconnection failed — sub_fd stays -1, caller's close(-1) is harmless */
  }

  /* Graceful DISCONNECT on all fds */
  u8 disc[2] = { 0xE0, 0x00 };
  for (int i = 0; i < ctx->fd_count; i++) {
    if (ctx->fds[i] >= 0)
      net_send(ctx->fds[i], ctx->timeout, (char *)disc, 2);
  }

  /* Free private state */
  if (ctx->priv) {
    mqtt_mp_priv_t *priv = (mqtt_mp_priv_t *)ctx->priv;
    if (priv->handshake_resp)
      ck_free(priv->handshake_resp);
    ck_free(priv);
    ctx->priv = NULL;
  }
}

/* ════════════════════════════════════════════════════════════════════
 * O2: Forward-differential query API
 *
 * Returns the combined forward-diff fingerprint for this execution.
 * If two broker instances produce different fwd_hash values for the
 * same input, a forwarding divergence has been detected.
 *
 * Called from mqtt_diff_analyze_responses() in afl-fuzz.c.
 * ════════════════════════════════════════════════════════════════════ */
u32 mqtt_mp_get_fwd_hash(mp_context_t *ctx) {
  if (!ctx || !ctx->priv) return 0;
  mqtt_mp_priv_t *priv = (mqtt_mp_priv_t *)ctx->priv;
  return priv->fwd_hash;
}

u32 mqtt_mp_get_fwd_count(mp_context_t *ctx) {
  if (!ctx || !ctx->priv) return 0;
  mqtt_mp_priv_t *priv = (mqtt_mp_priv_t *)ctx->priv;
  return priv->fwd_count;
}

/* ════════════════════════════════════════════════════════════════════
 * Static driver instance
 * ════════════════════════════════════════════════════════════════════ */
static const mp_driver_t g_mqtt_driver = {
  .name              = "MQTT",
  .fd_count          = 3,   /* sub, pub, ctrl */
  .open_connections  = mqtt_open_connections,
  .handshake         = mqtt_handshake,
  .role_for_message  = mqtt_role_for_message,
  .after_send        = mqtt_after_send,
  .drain_all         = mqtt_drain_all,
  .cleanup           = mqtt_cleanup,
};

const mp_driver_t *mp_driver_mqtt(void) {
  return &g_mqtt_driver;
}

/* ════════════════════════════════════════════════════════════════════
 * Driver registry — central dispatch.
 *
 * Returns the driver for the given protocol, or NULL if no
 * multi-party driver is available (→ single-fd path).
 * ════════════════════════════════════════════════════════════════════ */
const mp_driver_t *mp_driver_for_protocol(const char *proto) {
  if (!proto) return NULL;
  if (strcasecmp(proto, "MQTT") == 0) return mp_driver_mqtt();
  /* Future: if (strcasecmp(proto, "SIP") == 0) return mp_driver_sip(); */
  return NULL;
}
