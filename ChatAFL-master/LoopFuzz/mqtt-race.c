/* mqtt-race.c — MQTT Race Window Probe implementation.
 *
 * Provides concurrent multi-client scenario probing to detect race
 * conditions and timing-dependent non-compliance bugs in MQTT brokers.
 *
 * Architecture:
 *   Each race pattern creates 2-3 short-lived TCP connections to the
 *   target broker, uses pthread_barrier for precise synchronization,
 *   then checks for anomalous behavior (crash, unexpected forwarding,
 *   duplicate delivery, etc.).
 *
 * All patterns are modeled after MBFuzzer's documented bug triggers:
 *   Pattern 0: Session resume race (Mosquitto CWE-362/476)
 *   Pattern 1: Shared subscription duplicate delivery (EMQX CWE-672)
 *   Pattern 2: Will message delivery race
 *   Pattern 3: $SYS wildcard access timing (NanoMQ CWE-284)
 *
 * Compile: cc -c mqtt-race.c -o mqtt-race.o -lpthread
 */

#include "mqtt-race.h"
#include "alloc-inl.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>

/* ── External: net_send/net_recv from aflnet.c ── */
extern int net_send(int sockfd, struct timeval timeout,
                    char *mem, unsigned int len);
extern int net_recv(int sockfd, struct timeval timeout,
                    int poll_w, char **response_buf,
                    unsigned int *response_buf_size);

/* ── External: diff report from afl-fuzz.c ── */
/* We forward-declare the endpoint type to avoid circular includes */
typedef struct {
  u8 *ip;
  u32 port;
  char impl_name[32];
} mqtt_race_endpoint_t;

/* ── External: mqtt_save_diff_report (afl-fuzz.c) ── */
extern void mqtt_save_diff_report_ext(const char *diff_type,
                                       const char *detail);

/* ── Module state ──────────────────────────────────────────────── */
static mqtt_race_stats_t g_race_stats;
static u32 g_race_round_robin = 0;
static u8  g_race_initialized = 0;

/* Rate limiting: probe every N executions after first 500 warmup execs */
#define MQTT_RACE_PROBE_INTERVAL  50
#define MQTT_RACE_WARMUP_EXECS    500

/* Timeout for race probe connections (short — we don't want to block) */
#define RACE_TIMEOUT_USECS  200000  /* 200ms */
#define RACE_DRAIN_MS       5

/* ── Inline packet builders (duplicated from mp-driver-mqtt.c to
 *    avoid cross-module coupling — these are tiny ~20-byte packets) ── */

static u32 race_pack_connect(u8 *out, u32 cap, const char *cid, u8 clean) {
  u32 cid_len = (u32)strlen(cid);
  u32 rem = 10 + 2 + cid_len;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  out[0] = 0x10; out[1] = (u8)rem;
  out[2] = 0x00; out[3] = 0x04;
  out[4] = 'M'; out[5] = 'Q'; out[6] = 'T'; out[7] = 'T';
  out[8] = 0x04;
  out[9] = clean ? 0x02 : 0x00;  /* CleanSession flag */
  out[10] = 0x00; out[11] = 0x3C;
  out[12] = (u8)((cid_len >> 8) & 0xFF);
  out[13] = (u8)(cid_len & 0xFF);
  memcpy(out + 14, cid, cid_len);
  return 14 + cid_len;
}

static u32 race_pack_connect_will(u8 *out, u32 cap, const char *cid,
                                   const char *will_topic, const char *will_payload) {
  u32 cid_len = (u32)strlen(cid);
  u32 wt_len = (u32)strlen(will_topic);
  u32 wp_len = (u32)strlen(will_payload);
  u32 rem = 10 + 2 + cid_len + 2 + wt_len + 2 + wp_len;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  out[0] = 0x10; out[1] = (u8)rem;
  out[2] = 0x00; out[3] = 0x04;
  out[4] = 'M'; out[5] = 'Q'; out[6] = 'T'; out[7] = 'T';
  out[8] = 0x04;
  out[9] = 0x26;  /* CleanSession=1 | WillFlag=1 | WillQoS=1 */
  out[10] = 0x00; out[11] = 0x3C;
  u32 pos = 12;
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  out[pos++] = (u8)((wt_len >> 8) & 0xFF);
  out[pos++] = (u8)(wt_len & 0xFF);
  memcpy(out + pos, will_topic, wt_len); pos += wt_len;
  out[pos++] = (u8)((wp_len >> 8) & 0xFF);
  out[pos++] = (u8)(wp_len & 0xFF);
  memcpy(out + pos, will_payload, wp_len); pos += wp_len;
  return pos;
}

static u32 race_pack_subscribe(u8 *out, u32 cap, u16 pid,
                                const char *topic, u8 qos) {
  u32 tlen = (u32)strlen(topic);
  u32 rem = 2 + 2 + tlen + 1;
  if (!out || cap < (2 + rem) || tlen > 65535) return 0;
  out[0] = 0x82; out[1] = (u8)rem;
  out[2] = (u8)((pid >> 8) & 0xFF); out[3] = (u8)(pid & 0xFF);
  out[4] = (u8)((tlen >> 8) & 0xFF); out[5] = (u8)(tlen & 0xFF);
  memcpy(out + 6, topic, tlen);
  out[6 + tlen] = (u8)(qos & 0x03);
  return 7 + tlen;
}

static u32 race_pack_publish(u8 *out, u32 cap, const char *topic,
                              const char *payload, u8 qos, u8 retain,
                              u16 pkt_id) {
  u32 tlen = (u32)strlen(topic);
  u32 plen = (u32)strlen(payload);
  u32 rem = 2 + tlen + plen;
  if (qos > 0) rem += 2;
  if (!out || cap < (2 + rem) || tlen > 65535) return 0;
  out[0] = (u8)(0x30 | ((qos & 0x03) << 1) | (retain & 0x01));
  out[1] = (u8)rem;
  out[2] = (u8)((tlen >> 8) & 0xFF);
  out[3] = (u8)(tlen & 0xFF);
  memcpy(out + 4, topic, tlen);
  u32 pos = 4 + tlen;
  if (qos > 0) {
    out[pos++] = (u8)((pkt_id >> 8) & 0xFF);
    out[pos++] = (u8)(pkt_id & 0xFF);
  }
  memcpy(out + pos, payload, plen);
  return pos + plen;
}

static u32 race_pack_disconnect(u8 *out, u32 cap) {
  if (!out || cap < 2) return 0;
  out[0] = 0xE0; out[1] = 0x00;
  return 2;
}

/* ── TCP connection helper ─────────────────────────────────────── */
static int race_open_tcp(const char *ip, u32 port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) return -1;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
    struct hostent *he = gethostbyname(ip);
    if (!he || !he->h_addr_list[0]) { close(sockfd); return -1; }
    memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
  }

  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    for (int n = 0; n < 100; n++) {
      if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) break;
      usleep(500);
      if (n == 99) { close(sockfd); return -1; }
    }
  }

  int one = 1;
  setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = RACE_TIMEOUT_USECS;
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  return sockfd;
}

/* Helper: CONNECT + wait CONNACK */
static int race_mqtt_connect(int fd, const char *cid, u8 clean) {
  u8 pkt[64];
  u32 plen = race_pack_connect(pkt, sizeof(pkt), cid, clean);
  if (!plen) return -1;
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  if (net_send(fd, tv, (char *)pkt, plen) != (int)plen) return -1;
  char *resp = NULL; unsigned int rlen = 0;
  net_recv(fd, tv, RACE_DRAIN_MS, &resp, &rlen);
  int ok = (resp && rlen >= 4) ? 0 : -1;
  if (resp) ck_free(resp);
  return ok;
}

/* Helper: SUBSCRIBE + wait SUBACK */
static int race_mqtt_subscribe(int fd, const char *topic, u8 qos, u16 pid) {
  u8 pkt[128];
  u32 plen = race_pack_subscribe(pkt, sizeof(pkt), pid, topic, qos);
  if (!plen) return -1;
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  if (net_send(fd, tv, (char *)pkt, plen) != (int)plen) return -1;
  char *resp = NULL; unsigned int rlen = 0;
  net_recv(fd, tv, RACE_DRAIN_MS, &resp, &rlen);
  int ok = (resp && rlen >= 4) ? 0 : -1;
  if (resp) ck_free(resp);
  return ok;
}

/* Helper: PUBLISH (fire-and-forget for QoS 0, wait PUBACK for QoS 1) */
static int race_mqtt_publish(int fd, const char *topic, const char *payload,
                              u8 qos, u8 retain, u16 pid) {
  u8 pkt[256];
  u32 plen = race_pack_publish(pkt, sizeof(pkt), topic, payload, qos, retain, pid);
  if (!plen) return -1;
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  if (net_send(fd, tv, (char *)pkt, plen) != (int)plen) return -1;
  if (qos >= 1) {
    char *resp = NULL; unsigned int rlen = 0;
    net_recv(fd, tv, RACE_DRAIN_MS, &resp, &rlen);
    if (resp) ck_free(resp);
  }
  return 0;
}

/* Helper: drain and count forwarded PUBLISH on subscriber fd */
static int race_drain_forwards(int fd, int *out_count) {
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  char *buf = NULL; unsigned int blen = 0;
  net_recv(fd, tv, RACE_DRAIN_MS, &buf, &blen);
  /* Second drain for late arrivals */
  net_recv(fd, tv, 2, &buf, &blen);

  int count = 0;
  if (buf && blen >= 2) {
    u32 off = 0;
    while (off + 2 <= blen) {
      u8 ptype = ((u8)buf[off] >> 4) & 0x0F;
      /* Decode remaining length */
      u32 rem = 0, mult = 1, hb = 1;
      u32 roff = off + 1;
      while (roff < blen && hb <= 4) {
        u8 enc = (u8)buf[roff];
        rem += (enc & 0x7F) * mult;
        mult *= 128; hb++; roff++;
        if (!(enc & 0x80)) break;
      }
      u32 total = hb + rem;
      if (off + total > blen) break;
      if (ptype == 3) count++;  /* PUBLISH */
      off += total;
    }
  }
  if (buf) ck_free(buf);
  if (out_count) *out_count = count;
  return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Shared thread context for barrier-synchronized race patterns
 * ════════════════════════════════════════════════════════════════════ */
typedef struct {
  const char     *ip;
  u32             port;
  pthread_barrier_t *barrier;  /* synchronization point */
  int             anomaly;     /* set by thread if anomaly detected */
  int             fwd_count;   /* forwarded PUBLISH count (subscriber) */
  int             rc;          /* 0=ok, -1=connection/protocol error */
  /* Pattern-specific fields */
  const char     *topic;
  const char     *payload;
  const char     *client_id;
  u8              qos;
} race_thread_ctx_t;

/* ════════════════════════════════════════════════════════════════════
 * Pattern 0: Session Resume Race
 *
 * Models MBFuzzer's Mosquitto CWE-362/CWE-476 trigger:
 *   Thread A: CONNECT(persistent) → SUBSCRIBE → DISCONNECT → barrier →
 *             CONNECT(resume, CleanSession=0) → drain for redelivery
 *   Thread B: barrier → PUBLISH retained message
 *
 * Race window: The broker processes session resume (Thread A reconnect)
 * simultaneously with retained message delivery (Thread B publish).
 * If the broker's session pointer is accessed during the resume window,
 * a null-ptr deref or use-after-free can occur.
 * ════════════════════════════════════════════════════════════════════ */
static void *race_session_resume_sub(void *arg) {
  race_thread_ctx_t *ctx = (race_thread_ctx_t *)arg;
  ctx->rc = -1;

  /* Phase 1: Establish persistent session */
  int fd1 = race_open_tcp(ctx->ip, ctx->port);
  if (fd1 < 0) {
    /* P1-fix: unblock paired publisher at the barrier */
    pthread_barrier_wait(ctx->barrier);
    return NULL;
  }
  if (race_mqtt_connect(fd1, "race_sub_persist", 0) < 0) {
    close(fd1);
    /* P1-fix: unblock paired publisher at the barrier */
    pthread_barrier_wait(ctx->barrier);
    return NULL;
  }
  race_mqtt_subscribe(fd1, "#", 1, 1);

  /* Phase 2: Disconnect (session stays on broker) */
  u8 disc[2]; race_pack_disconnect(disc, sizeof(disc));
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  net_send(fd1, tv, (char *)disc, 2);
  close(fd1);

  /* Synchronize: both threads hit barrier simultaneously */
  pthread_barrier_wait(ctx->barrier);

  /* Phase 3: Reconnect with CleanSession=0 (session resume) */
  int fd2 = race_open_tcp(ctx->ip, ctx->port);
  if (fd2 < 0) return NULL;
  if (race_mqtt_connect(fd2, "race_sub_persist", 0) < 0) { close(fd2); return NULL; }
  race_mqtt_subscribe(fd2, "#", 1, 2);

  /* Drain for redelivered/retained messages */
  race_drain_forwards(fd2, &ctx->fwd_count);

  /* Graceful disconnect */
  net_send(fd2, tv, (char *)disc, 2);
  close(fd2);
  ctx->rc = 0;
  return NULL;
}

static void *race_session_resume_pub(void *arg) {
  race_thread_ctx_t *ctx = (race_thread_ctx_t *)arg;
  ctx->rc = -1;

  int fd = race_open_tcp(ctx->ip, ctx->port);
  if (fd < 0) {
    /* P1-fix: unblock paired subscriber at the barrier */
    pthread_barrier_wait(ctx->barrier);
    return NULL;
  }
  if (race_mqtt_connect(fd, "race_pub_retain", 1) < 0) {
    close(fd);
    /* P1-fix: unblock paired subscriber at the barrier */
    pthread_barrier_wait(ctx->barrier);
    return NULL;
  }

  /* Wait for subscriber to disconnect, then fire simultaneously */
  pthread_barrier_wait(ctx->barrier);

  /* Publish retained message — arrives at the broker exactly when
   * the subscriber is reconnecting with session resume */
  race_mqtt_publish(fd, "race/test", "RACE_DATA", 1, 1, 10);

  u8 disc[2]; race_pack_disconnect(disc, sizeof(disc));
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  net_send(fd, tv, (char *)disc, 2);
  close(fd);
  ctx->rc = 0;
  return NULL;
}

static int run_race_session_resume(const char *ip, u32 port) {
  pthread_barrier_t barrier;
  pthread_barrier_init(&barrier, NULL, 2);

  race_thread_ctx_t sub_ctx = { .ip = ip, .port = port, .barrier = &barrier };
  race_thread_ctx_t pub_ctx = { .ip = ip, .port = port, .barrier = &barrier };

  pthread_t t_sub, t_pub;
  pthread_create(&t_sub, NULL, race_session_resume_sub, &sub_ctx);
  pthread_create(&t_pub, NULL, race_session_resume_pub, &pub_ctx);
  pthread_join(t_sub, NULL);
  pthread_join(t_pub, NULL);
  pthread_barrier_destroy(&barrier);

  int anomaly = 0;
  /* If subscriber failed to reconnect (broker crashed), that's an anomaly */
  if (sub_ctx.rc != 0 || pub_ctx.rc != 0) {
    anomaly = 1;
    fprintf(stderr, "[O7-race] session_resume: connection failure "
            "(sub_rc=%d pub_rc=%d) — possible broker crash\n",
            sub_ctx.rc, pub_ctx.rc);
  }
  return anomaly;
}

/* ════════════════════════════════════════════════════════════════════
 * Pattern 1: Shared Subscription Duplicate Delivery
 *
 * Models MBFuzzer's EMQX CWE-672 trigger:
 *   Sub1 + Sub2 both subscribe to $share/grp/test
 *   Publisher sends QoS 1 message to test
 *   Correct: only ONE subscriber receives the message
 *   Bug: BOTH subscribers receive it (duplicate delivery)
 * ════════════════════════════════════════════════════════════════════ */
static int run_race_shared_sub(const char *ip, u32 port) {
  int sub1_fd = race_open_tcp(ip, port);
  int sub2_fd = race_open_tcp(ip, port);
  int pub_fd  = race_open_tcp(ip, port);
  if (sub1_fd < 0 || sub2_fd < 0 || pub_fd < 0) {
    if (sub1_fd >= 0) close(sub1_fd);
    if (sub2_fd >= 0) close(sub2_fd);
    if (pub_fd >= 0)  close(pub_fd);
    return 0;
  }

  /* All three connect */
  if (race_mqtt_connect(sub1_fd, "race_shared1", 1) < 0 ||
      race_mqtt_connect(sub2_fd, "race_shared2", 1) < 0 ||
      race_mqtt_connect(pub_fd,  "race_shared_p", 1) < 0)
    goto shared_cleanup;

  /* Both subscribers subscribe to shared subscription */
  race_mqtt_subscribe(sub1_fd, "$share/race_grp/test/race", 1, 1);
  race_mqtt_subscribe(sub2_fd, "$share/race_grp/test/race", 1, 2);

  /* Small delay to ensure subscriptions are registered */
  usleep(1000);

  /* Publish to the shared topic */
  race_mqtt_publish(pub_fd, "test/race", "SHARED_TEST", 1, 0, 20);

  /* Drain both subscribers */
  int count1 = 0, count2 = 0;
  race_drain_forwards(sub1_fd, &count1);
  race_drain_forwards(sub2_fd, &count2);

  int anomaly = 0;
  /* Shared subscription: exactly ONE subscriber should receive the message */
  if (count1 > 0 && count2 > 0) {
    anomaly = 1;
    fprintf(stderr, "[O7-race] shared_sub: DUPLICATE delivery "
            "(sub1=%d sub2=%d) — possible CWE-672\n", count1, count2);
  }

shared_cleanup:
  {
    u8 d[2] = { 0xE0, 0x00 };
    struct timeval t = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
    if (sub1_fd >= 0) { net_send(sub1_fd, t, (char *)d, 2); close(sub1_fd); }
    if (sub2_fd >= 0) { net_send(sub2_fd, t, (char *)d, 2); close(sub2_fd); }
    if (pub_fd >= 0)  { net_send(pub_fd, t, (char *)d, 2);  close(pub_fd); }
  }
  return anomaly;
}

/* ════════════════════════════════════════════════════════════════════
 * Pattern 2: Will Message Delivery Race
 *
 * Thread A: CONNECT with Will → barrier → abrupt TCP close (no DISCONNECT)
 * Thread B: SUBSCRIBE "#" → barrier → drain for Will message
 *
 * Race: The broker must detect A's abrupt disconnect and deliver the
 * Will message to B.  Timing issues in will processing can cause
 * null-ptr deref or missed will delivery.
 * ════════════════════════════════════════════════════════════════════ */
static void *race_will_sender(void *arg) {
  race_thread_ctx_t *ctx = (race_thread_ctx_t *)arg;
  ctx->rc = -1;

  int fd = race_open_tcp(ctx->ip, ctx->port);
  if (fd < 0) {
    /* P1-fix: MUST reach the barrier even on error, otherwise the
     * paired receiver thread blocks forever in pthread_barrier_wait.
     * The barrier is init'd with count=2 — if we bail early without
     * arriving, the receiver waits forever and pthread_join hangs. */
    pthread_barrier_wait(ctx->barrier);
    return NULL;
  }

  /* CONNECT with Will message */
  u8 pkt[128];
  u32 plen = race_pack_connect_will(pkt, sizeof(pkt), "race_will_sender",
                                     "will/race", "WILL_FIRED");
  if (!plen) { close(fd); return NULL; }
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  if (net_send(fd, tv, (char *)pkt, plen) != (int)plen) { close(fd); return NULL; }
  { char *r = NULL; unsigned int rl = 0;
    net_recv(fd, tv, RACE_DRAIN_MS, &r, &rl);
    if (r) ck_free(r); }

  /* Synchronize */
  pthread_barrier_wait(ctx->barrier);

  /* Abrupt disconnect: close TCP without sending DISCONNECT packet.
   * This triggers the broker's will delivery path. */
  close(fd);
  ctx->rc = 0;
  return NULL;
}

static void *race_will_receiver(void *arg) {
  race_thread_ctx_t *ctx = (race_thread_ctx_t *)arg;
  ctx->rc = -1;

  int fd = race_open_tcp(ctx->ip, ctx->port);
  if (fd < 0) {
    /* P1-fix: must unblock the paired sender at the barrier */
    pthread_barrier_wait(ctx->barrier);
    return NULL;
  }
  if (race_mqtt_connect(fd, "race_will_recv", 1) < 0) {
    close(fd);
    /* P1-fix: must unblock the paired sender at the barrier */
    pthread_barrier_wait(ctx->barrier);
    return NULL;
  }
  race_mqtt_subscribe(fd, "#", 0, 1);

  /* Synchronize — then drain for the will message */
  pthread_barrier_wait(ctx->barrier);

  /* Wait a bit for broker to detect the abrupt disconnect + will delivery */
  usleep(50000);  /* 50ms */

  race_drain_forwards(fd, &ctx->fwd_count);

  u8 disc[2] = { 0xE0, 0x00 };
  struct timeval tv = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
  net_send(fd, tv, (char *)disc, 2);
  close(fd);
  ctx->rc = 0;
  return NULL;
}

static int run_race_will_delivery(const char *ip, u32 port) {
  pthread_barrier_t barrier;
  pthread_barrier_init(&barrier, NULL, 2);

  race_thread_ctx_t sender_ctx = { .ip = ip, .port = port, .barrier = &barrier };
  race_thread_ctx_t recv_ctx   = { .ip = ip, .port = port, .barrier = &barrier };

  pthread_t t_sender, t_recv;
  pthread_create(&t_sender, NULL, race_will_sender, &sender_ctx);
  pthread_create(&t_recv,   NULL, race_will_receiver, &recv_ctx);
  pthread_join(t_sender, NULL);
  pthread_join(t_recv, NULL);
  pthread_barrier_destroy(&barrier);

  int anomaly = 0;
  if (sender_ctx.rc != 0 || recv_ctx.rc != 0) {
    anomaly = 1;
    fprintf(stderr, "[O7-race] will_delivery: connection failure — "
            "possible broker crash\n");
  }
  return anomaly;
}

/* ════════════════════════════════════════════════════════════════════
 * Pattern 3: $SYS Wildcard Access Race
 *
 * Models MBFuzzer's NanoMQ CWE-284 trigger:
 *   Sub subscribes to +/+/+ (multi-level wildcard)
 *   Pub publishes to $SYS/broker/status
 *   Correct: wildcard should NOT match $SYS topics (MQTT spec §4.7)
 *   Bug: broker forwards $SYS message to wildcard subscriber
 * ════════════════════════════════════════════════════════════════════ */
static int run_race_sys_wildcard(const char *ip, u32 port) {
  int sub_fd = race_open_tcp(ip, port);
  int pub_fd = race_open_tcp(ip, port);
  if (sub_fd < 0 || pub_fd < 0) {
    if (sub_fd >= 0) close(sub_fd);
    if (pub_fd >= 0) close(pub_fd);
    return 0;
  }

  if (race_mqtt_connect(sub_fd, "race_sys_sub", 1) < 0 ||
      race_mqtt_connect(pub_fd, "race_sys_pub", 1) < 0)
    goto sys_cleanup;

  /* Subscribe with multi-level wildcard that should NOT match $SYS */
  race_mqtt_subscribe(sub_fd, "+/+/+", 0, 1);
  usleep(1000);

  /* Publish to $SYS topic */
  race_mqtt_publish(pub_fd, "$SYS/broker/status", "SYS_SECRET", 0, 0, 0);
  usleep(2000);

  int count = 0;
  race_drain_forwards(sub_fd, &count);

  int anomaly = 0;
  if (count > 0) {
    anomaly = 1;
    fprintf(stderr, "[O7-race] sys_wildcard: $SYS message leaked to "
            "wildcard subscriber (count=%d) — possible CWE-284\n", count);
  }

sys_cleanup:
  {
    u8 d[2] = { 0xE0, 0x00 };
    struct timeval t = { .tv_sec = 0, .tv_usec = RACE_TIMEOUT_USECS };
    if (sub_fd >= 0) { net_send(sub_fd, t, (char *)d, 2); close(sub_fd); }
    if (pub_fd >= 0) { net_send(pub_fd, t, (char *)d, 2); close(pub_fd); }
  }
  return anomaly;
}

/* ════════════════════════════════════════════════════════════════════
 * Public API
 * ════════════════════════════════════════════════════════════════════ */

void mqtt_race_init(void) {
  memset(&g_race_stats, 0, sizeof(g_race_stats));
  g_race_round_robin = 0;
  g_race_initialized = 1;
}

int mqtt_race_should_probe(u64 total_execs) {
  if (!g_race_initialized) return 0;
  if (total_execs < MQTT_RACE_WARMUP_EXECS) return 0;
  return (total_execs % MQTT_RACE_PROBE_INTERVAL == 0);
}

int mqtt_race_probe(const char *ip, u32 port, int pattern) {
  if (!g_race_initialized) return 0;

  /* Select pattern */
  int pat = pattern;
  if (pat < 0 || pat >= MQTT_RACE_PATTERN_COUNT) {
    pat = (int)(g_race_round_robin % MQTT_RACE_PATTERN_COUNT);
    g_race_round_robin++;
  }

  g_race_stats.total_probes++;
  g_race_stats.pattern_hits[pat]++;

  int anomaly = 0;
  if (pat == MQTT_RACE_SESSION_RESUME)
    anomaly = run_race_session_resume(ip, port);
  else if (pat == MQTT_RACE_SHARED_SUB)
    anomaly = run_race_shared_sub(ip, port);
  else if (pat == MQTT_RACE_WILL_DELIVERY)
    anomaly = run_race_will_delivery(ip, port);
  else if (pat == MQTT_RACE_RETAIN_SUBSCRIBE)
    anomaly = run_race_sys_wildcard(ip, port);

  if (anomaly) {
    g_race_stats.anomalies_found++;
  }

  return anomaly;
}

mqtt_race_stats_t mqtt_race_get_stats(void) {
  return g_race_stats;
}
