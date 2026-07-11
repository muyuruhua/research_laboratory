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
#include <fcntl.h>       /* F_GETFL, F_SETFL, O_NONBLOCK */
#include <poll.h>        /* poll(), struct pollfd, POLLOUT */
#include <errno.h>       /* errno, EINPROGRESS */

/* ── External globals we need (defined in afl-fuzz.c) ── */
extern u32 local_port;
extern u8  mqtt_cross_session_enabled;  /* P2b: set in afl-fuzz.c init */
extern u8  mqtt_field_mutate_enabled;   /* P0+P2: gates v5 handshake */
extern u32 mqtt_fwd_drain_ms;           /* P8b: forwarding drain time (ms), self-adaptive */
extern u8  mqtt_fwd_drain_fixed;        /* P8b: 1 if user pinned via env var */

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

  /* V4-3: QoS handshake completion tracking */
  u32                   qos_acks;    /* number of QoS acks completed this exec */

  /* V5: Handshake phase — needed by cleanup for version-aware DISCONNECT */
  u8                    phase;
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

  /* P1-fix: Non-blocking connect with 5-second timeout.
   * The retry-loop connect(2) blocks for the kernel TCP timeout (20-120 s)
   * on unreachable brokers, hanging the entire fuzz loop.  We switch to
   * non-blocking connect + poll(2) so the call returns in bounded time. */
  {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) { close(sockfd); return -1; }
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (rc < 0) {
      if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLOUT;
        int pr = poll(&pfd, 1, 5000);  /* 5-second connect deadline */
        if (pr <= 0) { close(sockfd); return -1; }
        /* Verify the connection actually succeeded */
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0
            && so_error != 0) {
          close(sockfd);
          return -1;
        }
      } else {
        /* Immediate failure (e.g. network unreachable) */
        close(sockfd);
        return -1;
      }
    }

    fcntl(sockfd, F_SETFL, flags);  /* restore blocking mode */
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

/* V3-3: CONNECT with Will message — exercises mosquitto's will processing:
 *   handle__connect() will flag parsing + will topic/payload extraction
 *   context__send_will() triggered on client disconnect
 *   db__messages_queue() will message delivery to subscribers
 *   handle__publish() internal will publish path
 * Will topic "w", payload "1", QoS 0, Retain=0.  Minimal overhead (adds
 * 6 bytes to the CONNECT packet). */
static u32 pack_connect_will(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  /* Payload: client_id(2+len) + will_topic(2+1) + will_payload(2+1) */
  u32 rem = 10 + 2 + cid_len + 2 + 1 + 2 + 1;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  out[0] = 0x10; out[1] = (u8)rem;
  out[2] = 0x00; out[3] = 0x04;
  out[4] = 'M'; out[5] = 'Q'; out[6] = 'T'; out[7] = 'T';
  out[8] = 0x04;         /* Protocol level 4 (v3.1.1) */
  out[9] = 0x06;         /* Connect Flags: CleanSession=1 | WillFlag=1 | WillQoS=0 */
  out[10] = 0x00; out[11] = 0x3C;  /* Keep Alive = 60s */
  u32 pos = 12;
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  /* Will Topic: "w" (1 byte) */
  out[pos++] = 0x00; out[pos++] = 0x01; out[pos++] = 'w';
  /* Will Payload: "1" (1 byte) */
  out[pos++] = 0x00; out[pos++] = 0x01; out[pos++] = '1';
  return pos;
}

/* ════════════════════════════════════════════════════════════════════
 * V4-3: QoS acknowledgment packet builders for complete handshake.
 * These enable the subscriber to properly ACK forwarded QoS 1/2
 * messages, exercising the broker's outgoing message state machine:
 *   handle__pubackcomp(), handle__pubrec(), send__pubrel(),
 *   db__message_update_outgoing(), db__message_dequeue().
 * ════════════════════════════════════════════════════════════════════ */
static u32 pack_puback(u8 *out, u32 cap, u16 pkt_id) {
  if (!out || cap < 4) return 0;
  out[0] = 0x40; out[1] = 0x02;
  out[2] = (u8)((pkt_id >> 8) & 0xFF);
  out[3] = (u8)(pkt_id & 0xFF);
  return 4;
}

static u32 pack_pubrec(u8 *out, u32 cap, u16 pkt_id) {
  if (!out || cap < 4) return 0;
  out[0] = 0x50; out[1] = 0x02;
  out[2] = (u8)((pkt_id >> 8) & 0xFF);
  out[3] = (u8)(pkt_id & 0xFF);
  return 4;
}

static u32 pack_pubcomp(u8 *out, u32 cap, u16 pkt_id) {
  if (!out || cap < 4) return 0;
  out[0] = 0x70; out[1] = 0x02;
  out[2] = (u8)((pkt_id >> 8) & 0xFF);
  out[3] = (u8)(pkt_id & 0xFF);
  return 4;
}

/* V4-4: PUBLISH builder with retain/QoS support.
 * Used for retain priming in handshake and retain clearing in cleanup. */
static u32 pack_publish_simple(u8 *out, u32 cap, const char *topic,
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

/* V4-2: Alternative v5 CONNECT with different property configuration.
 * Used for version alternation to exercise different branches within
 * property__read_all() and connect__on_authorised().
 * Properties: small Receive Maximum (10), Maximum Packet Size (4096),
 * no Session Expiry, no Topic Alias — exercises different property
 * combination paths compared to pack_connect_v5(). */
static u32 pack_connect_v5_alt(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  u8 props[] = {
    0x21, 0x00, 0x0A,              /* Receive Maximum = 10 (small) */
    0x19, 0x01,                    /* Request Response Information */
    0x27, 0x00, 0x00, 0x10, 0x00,  /* Maximum Packet Size = 4096 */
  };
  u32 props_len = (u32)sizeof(props);
  u32 rem = 10 + 1 + props_len + 2 + cid_len;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  u32 pos = 0;
  out[pos++] = 0x10;
  out[pos++] = (u8)rem;
  out[pos++] = 0x00; out[pos++] = 0x04;
  out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'T'; out[pos++] = 'T';
  out[pos++] = 0x05;         /* Protocol Level 5 */
  out[pos++] = 0x02;         /* Connect Flags: Clean Start = 1 */
  out[pos++] = 0x00; out[pos++] = 0x3C;
  out[pos++] = (u8)props_len;
  memcpy(out + pos, props, props_len); pos += props_len;
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  return pos;
}

/* V5-1: v5 CONNECT with Will message AND Will properties.
 * Exercises property_broker.c → property__process_will() + handle_connect.c will__read().
 * Will properties: WILL_DELAY_INTERVAL, MESSAGE_EXPIRY_INTERVAL, CONTENT_TYPE,
 *   PAYLOAD_FORMAT_INDICATOR, RESPONSE_TOPIC, CORRELATION_DATA, USER_PROPERTY.
 * This single packet covers ~40 lines in property_broker.c and ~40 in handle_connect.c. */
static u32 pack_connect_v5_will(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  /* CONNECT properties (session-level) */
  u8 conn_props[] = {
    0x11, 0x00, 0x00, 0x01, 0x00,  /* Session Expiry Interval = 256 */
    0x21, 0x00, 0x40,              /* Receive Maximum = 64 */
    0x27, 0x00, 0x01, 0x00, 0x00,  /* Maximum Packet Size = 65536 */
  };
  u32 conn_props_len = (u32)sizeof(conn_props);

  /* Will properties (per-message) */
  u8 will_props[] = {
    0x18, 0x00, 0x00, 0x00, 0x3C,              /* Will Delay Interval = 60 */
    0x02, 0x00, 0x00, 0x0E, 0x10,              /* Message Expiry Interval = 3600 */
    0x01, 0x01,                                 /* Payload Format Indicator = UTF-8 */
    0x03, 0x00, 0x10,                           /* Content Type = "application/json" */
      'a','p','p','l','i','c','a','t','i','o','n','/','j','s','o','n',
    0x08, 0x00, 0x05,                           /* Response Topic = "r/rsp" */
      'r','/','r','s','p',
    0x09, 0x00, 0x04,                           /* Correlation Data = "cid1" */
      'c','i','d','1',
    0x26, 0x00, 0x03, 'k','e','y',             /* User Property = "key":"val" */
          0x00, 0x03, 'v','a','l',
  };
  u32 will_props_len = (u32)sizeof(will_props);

  /* Will topic = "w/v5" (4 bytes), Will payload = "alive" (5 bytes) */
  const char *will_topic = "w/v5";
  const char *will_payload = "alive";
  u32 wt_len = 4, wp_len = 5;

  /* Total remaining length:
   * Variable header: 10 (protocol) + 1 (conn_props_len) + conn_props
   * Payload: 2+cid_len + 1+will_props_len + will_props + 2+wt_len + 2+wp_len */
  u32 rem = 10 + 1 + conn_props_len + 2 + cid_len
          + 1 + will_props_len + 2 + wt_len + 2 + wp_len;
  if (!out || cap < (2 + rem) || cid_len > 23 || rem > 127) return 0;

  u32 pos = 0;
  out[pos++] = 0x10;             /* CONNECT */
  out[pos++] = (u8)rem;          /* remaining length */
  /* Variable header */
  out[pos++] = 0x00; out[pos++] = 0x04;
  out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'T'; out[pos++] = 'T';
  out[pos++] = 0x05;             /* Protocol Level 5 */
  out[pos++] = 0x2E;             /* Flags: CleanStart=1 | WillFlag=1 | WillQoS=1 | WillRetain=1 */
  out[pos++] = 0x00; out[pos++] = 0x3C; /* Keep Alive = 60s */
  /* CONNECT properties */
  out[pos++] = (u8)conn_props_len;
  memcpy(out + pos, conn_props, conn_props_len); pos += conn_props_len;
  /* Payload: Client ID */
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  /* Will properties */
  out[pos++] = (u8)will_props_len;
  memcpy(out + pos, will_props, will_props_len); pos += will_props_len;
  /* Will topic */
  out[pos++] = (u8)((wt_len >> 8) & 0xFF);
  out[pos++] = (u8)(wt_len & 0xFF);
  memcpy(out + pos, will_topic, wt_len); pos += wt_len;
  /* Will payload */
  out[pos++] = (u8)((wp_len >> 8) & 0xFF);
  out[pos++] = (u8)(wp_len & 0xFF);
  memcpy(out + pos, will_payload, wp_len); pos += wp_len;
  return pos;
}

/* V5-2: v3.1 CONNECT using "MQIsdp" protocol name.
 * Exercises handle__connect() v3.1 branch: protocol name "MQIsdp", version byte 3.
 * Covers ~10-15 lines in handle_connect.c's MQIsdp parsing path. */
static u32 pack_connect_v31(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  /* v3.1 variable header: protocol name "MQIsdp" (6 bytes) + version 3 */
  u32 rem = 12 + 2 + cid_len;  /* 2+6(MQIsdp) + version + flags + keepalive + clientid */
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  u32 pos = 0;
  out[pos++] = 0x10; out[pos++] = (u8)rem;
  out[pos++] = 0x00; out[pos++] = 0x06;  /* protocol name length = 6 */
  out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'I';
  out[pos++] = 's'; out[pos++] = 'd'; out[pos++] = 'p';
  out[pos++] = 0x03;         /* Protocol version 3 */
  out[pos++] = 0x02;         /* Connect Flags: CleanSession=1 */
  out[pos++] = 0x00; out[pos++] = 0x3C;  /* Keep Alive = 60s */
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  return pos;
}

/* V5-3: v5 CONNECT with zero-length client ID (auto-assign).
 * Exercises handle__connect() client_id_gen() and assigned_id logic.
 * Covers ~15 lines: zero-length CID handling + CONNACK ASSIGNED_CLIENT_IDENTIFIER. */
static u32 pack_connect_v5_zero_cid(u8 *out, u32 cap) {
  /* Properties: Session Expiry = 0 (required when zero CID + clean_start=1) */
  u8 props[] = {
    0x11, 0x00, 0x00, 0x00, 0x00,  /* Session Expiry Interval = 0 */
  };
  u32 props_len = (u32)sizeof(props);
  u32 rem = 10 + 1 + props_len + 2; /* variable header + 0-length client ID */
  if (!out || cap < (2 + rem)) return 0;
  u32 pos = 0;
  out[pos++] = 0x10; out[pos++] = (u8)rem;
  out[pos++] = 0x00; out[pos++] = 0x04;
  out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'T'; out[pos++] = 'T';
  out[pos++] = 0x05;         /* Protocol Level 5 */
  out[pos++] = 0x02;         /* Clean Start = 1 (required for zero-length CID) */
  out[pos++] = 0x00; out[pos++] = 0x3C;
  out[pos++] = (u8)props_len;
  memcpy(out + pos, props, props_len); pos += props_len;
  out[pos++] = 0x00; out[pos++] = 0x00;  /* Client ID length = 0 */
  return pos;
}

/* V5-4: CONNECT with username and password.
 * Exercises handle__connect() username/password reading paths.
 * Covers ~10-15 lines in flag combination handling. */
static u32 pack_connect_userpass(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  const char *user = "test";
  const char *pass = "pass";
  u32 ulen = 4, plen = 4;
  /* Flags: CleanSession=1 | UsernameFlag=1 | PasswordFlag=1 */
  u32 rem = 10 + 2 + cid_len + 2 + ulen + 2 + plen;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  u32 pos = 0;
  out[pos++] = 0x10; out[pos++] = (u8)rem;
  out[pos++] = 0x00; out[pos++] = 0x04;
  out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'T'; out[pos++] = 'T';
  out[pos++] = 0x04;         /* Protocol level 4 (v3.1.1) */
  out[pos++] = 0xC2;         /* Flags: CleanSession=1 | Username=1 | Password=1 */
  out[pos++] = 0x00; out[pos++] = 0x3C;
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  /* Username */
  out[pos++] = (u8)((ulen >> 8) & 0xFF);
  out[pos++] = (u8)(ulen & 0xFF);
  memcpy(out + pos, user, ulen); pos += ulen;
  /* Password */
  out[pos++] = (u8)((plen >> 8) & 0xFF);
  out[pos++] = (u8)(plen & 0xFF);
  memcpy(out + pos, pass, plen); pos += plen;
  return pos;
}

/* V5-5: v5 DISCONNECT with properties.
 * Exercises property_broker.c → property__process_disconnect() and
 * packet_mosq.c → packet__read() non-zero remaining length for DISCONNECT.
 * Session Expiry Interval property in DISCONNECT. */
static u32 pack_disconnect_v5(u8 *out, u32 cap) {
  /* Reason Code: 0x00 (Normal) + Properties: Session Expiry Interval */
  u8 props[] = {
    0x11, 0x00, 0x00, 0x0E, 0x10,  /* Session Expiry Interval = 3600 */
  };
  u32 props_len = (u32)sizeof(props);
  u32 rem = 1 + 1 + props_len;  /* reason_code + props_length + props */
  if (!out || cap < (2 + rem)) return 0;
  u32 pos = 0;
  out[pos++] = 0xE0;         /* DISCONNECT */
  out[pos++] = (u8)rem;
  out[pos++] = 0x00;         /* Reason Code: Normal */
  out[pos++] = (u8)props_len;
  memcpy(out + pos, props, props_len); pos += props_len;
  return pos;
}

/* V5-6: v5 CONNECT with username/password (v5 allows password without username).
 * Exercises handle__connect() v5-specific password-only path. */
static u32 pack_connect_v5_userpass(u8 *out, u32 cap, const char *cid) {
  u32 cid_len = (u32)strlen(cid);
  const char *pass = "v5pw";
  u32 plen = 4;
  u8 conn_props[] = {
    0x11, 0x00, 0x00, 0x00, 0x00,  /* Session Expiry Interval = 0 */
  };
  u32 conn_props_len = (u32)sizeof(conn_props);
  /* Flags: CleanStart=1 | PasswordFlag=1 (no UsernameFlag — v5 allows this) */
  u32 rem = 10 + 1 + conn_props_len + 2 + cid_len + 2 + plen;
  if (!out || cap < (2 + rem) || cid_len > 23) return 0;
  u32 pos = 0;
  out[pos++] = 0x10; out[pos++] = (u8)rem;
  out[pos++] = 0x00; out[pos++] = 0x04;
  out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'T'; out[pos++] = 'T';
  out[pos++] = 0x05;         /* Protocol Level 5 */
  out[pos++] = 0x42;         /* Flags: CleanStart=1 | PasswordFlag=1 (bit 6) */
  out[pos++] = 0x00; out[pos++] = 0x3C;
  out[pos++] = (u8)conn_props_len;
  memcpy(out + pos, conn_props, conn_props_len); pos += conn_props_len;
  out[pos++] = (u8)((cid_len >> 8) & 0xFF);
  out[pos++] = (u8)(cid_len & 0xFF);
  memcpy(out + pos, cid, cid_len); pos += cid_len;
  /* Password (no username) */
  out[pos++] = (u8)((plen >> 8) & 0xFF);
  out[pos++] = (u8)(plen & 0xFF);
  memcpy(out + pos, pass, plen); pos += plen;
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
   * V5: Expanded version alternation — 6 phases to exercise diverse CONNECT
   * handling paths in handle_connect.c & property_broker.c:
   *   Phase 0: sub=v5,           pub=v4(will),       ctrl=v4
   *   Phase 1: sub=v4,           pub=v4(will),       ctrl=v5_alt
   *   Phase 2: sub=v5,           pub=v5_will(props), ctrl=v31(MQIsdp)
   *   Phase 3: sub=v4,           pub=v5_will(props), ctrl=userpass
   *   Phase 4: sub=v5_zero_cid,  pub=v4(will),       ctrl=v5_userpass
   *   Phase 5: sub=v5,           pub=v5_will(props), ctrl=v5_alt
   * Each phase exercises different property/flag combinations to maximize
   * code path coverage across handle_connect.c, property_broker.c. */
  static u32 version_alt_counter = 0;
  u8 phase = (u8)(version_alt_counter % 6);
  version_alt_counter++;
  /* Track v5 usage for subscribe variant selection */
  u8 sub_is_v5 = (mqtt_field_mutate_enabled &&
                  (phase == 0 || phase == 2 || phase == 5));
  /* Phase 4 uses zero-cid v5 for sub — still v5 but different path */
  u8 sub_is_v5_zero_cid = (mqtt_field_mutate_enabled && phase == 4);
  priv->phase = phase;

  static const char *cids[3] = { "afl_sub", "afl_pub", "afl_ctrl" };
  for (int i = 0; i < ctx->fd_count; i++) {
    if (i == SUB_IDX) {
      if (sub_is_v5_zero_cid)
        pkt_len = pack_connect_v5_zero_cid(pkt, sizeof(pkt));
      else if (sub_is_v5)
        pkt_len = pack_connect_v5(pkt, sizeof(pkt), cids[i]);
      else
        pkt_len = pack_connect(pkt, sizeof(pkt), cids[i]);
    } else if (i == PUB_IDX) {
      /* Phases 2,3,5: v5 CONNECT with full Will properties */
      if (mqtt_field_mutate_enabled && (phase == 2 || phase == 3 || phase == 5))
        pkt_len = pack_connect_v5_will(pkt, sizeof(pkt), cids[i]);
      else
        pkt_len = pack_connect_will(pkt, sizeof(pkt), cids[i]); /* V3-3 */
    } else { /* CTRL_IDX */
      if (mqtt_field_mutate_enabled && (phase == 1 || phase == 5))
        pkt_len = pack_connect_v5_alt(pkt, sizeof(pkt), cids[i]);
      else if (mqtt_field_mutate_enabled && phase == 2)
        pkt_len = pack_connect_v31(pkt, sizeof(pkt), cids[i]);
      else if (mqtt_field_mutate_enabled && phase == 3)
        pkt_len = pack_connect_userpass(pkt, sizeof(pkt), cids[i]);
      else if (mqtt_field_mutate_enabled && phase == 4)
        pkt_len = pack_connect_v5_userpass(pkt, sizeof(pkt), cids[i]);
      else
        pkt_len = pack_connect(pkt, sizeof(pkt), cids[i]);
    }
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

  /* V4-4: Retained PUBLISH priming — send retained messages BEFORE subscribing.
   * This exercises mosquitto's retain__store() and db__messages_easy_queue().
   * When sub_fd subscribes to '#' afterwards, the broker delivers these
   * retained messages via retain__queue(), exercising the full retain path.
   * Topics: "r/test" (QoS 1 + retain), "r/sys" (QoS 0 + retain). */
  pkt_len = pack_publish_simple(pkt, sizeof(pkt), "r/test", "R1", 1, 1, 100);
  if (pkt_len > 0) {
    net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[PUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             &priv->handshake_resp, &priv->handshake_resp_len);
  }
  pkt_len = pack_publish_simple(pkt, sizeof(pkt), "r/sys", "R2", 0, 1, 0);
  if (pkt_len > 0) {
    net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[PUB_IDX], ctx->timeout, 1,
             &priv->handshake_resp, &priv->handshake_resp_len);
  }

  /* SUBSCRIBE on sub_fd to wildcard '#' (all topics)
   * V4-3: Use QoS 2 to enable full QoS 2 forwarding and handshake.
   * This allows the broker to forward messages at QoS 2, triggering the
   * complete PUBREC→PUBREL→PUBCOMP handshake in after_send().
   * Also exercises db__message_store() QoS 2 path and inflight management. */
  u8 sub_qos = 2;
  u8 use_v5_sub = sub_is_v5 || sub_is_v5_zero_cid;
  if (use_v5_sub)
    pkt_len = pack_subscribe_v5(pkt, sizeof(pkt), 1, "#", sub_qos);
  else
    pkt_len = pack_subscribe(pkt, sizeof(pkt), 1, "#", sub_qos);
  if (!pkt_len ||
      net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len) != (int)pkt_len)
    return -1;
  net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
           ctx->response_buf, (unsigned int *)ctx->response_buf_size);

  /* V3-5: Additional subscriptions to exercise subscription matching engine.
   * 'test/+' — single-level wildcard exercises topic_tok.c tokenization,
   *   sub__add() overlap handling, sub__search() '+' operator matching.
   * '$SYS/#' — system topic subscription exercises mosquitto's $ prefix
   *   special handling in sub__messages_queue() and sys_tree__update().
   * These trigger code paths that the wildcard '#' alone bypasses. */
  if (use_v5_sub)
    pkt_len = pack_subscribe_v5(pkt, sizeof(pkt), 2, "test/+", sub_qos);
  else
    pkt_len = pack_subscribe(pkt, sizeof(pkt), 2, "test/+", sub_qos);
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  pkt_len = pack_subscribe(pkt, sizeof(pkt), 3, "$SYS/#", 0);
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  /* P8: Shared subscription patterns — exercises mosquitto v2.x shared
   * subscription code paths: handle__subscribe() shared group parsing,
   * sub__add() '$share/group/filter' branch, sub__search() shared
   * delivery round-robin logic, and sub__messages_queue() shared group
   * distribution.  These paths are a major addition in v2.1.x and are
   * the root cause of the coverage gap vs MBFuzzer on v2.1.2.
   * Use v5 SUBSCRIBE for phases that support it (subscription ID prop). */
  if (use_v5_sub) {
    pkt_len = pack_subscribe_v5(pkt, sizeof(pkt), 4, "$share/grp1/test/+", sub_qos);
  } else {
    pkt_len = pack_subscribe(pkt, sizeof(pkt), 4, "$share/grp1/test/+", sub_qos);
  }
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  if (use_v5_sub) {
    pkt_len = pack_subscribe_v5(pkt, sizeof(pkt), 5, "$share/grp2/sensor/#", 1);
  } else {
    pkt_len = pack_subscribe(pkt, sizeof(pkt), 5, "$share/grp2/sensor/#", 1);
  }
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  /* ════════════════════════════════════════════════════════════════════
   * B1: Bridge-aware subscriptions — exercises MQTT bridge, topic remap,
   * and multi-hop forwarding code paths in mosquitto and other brokers.
   *
   * Bridge configuration in mosquitto uses topic patterns like:
   *   topic <pattern> [in|out|both] [qos] [local_prefix/] [remote_prefix/]
   *
   * These subscriptions exercise:
   *   - bridge__connect() connection establishment
   *   - bridge__on_connect() subscription exchange
   *   - Topic remap: local_prefix → remote_prefix translation in
   *     bridge__remap_topic_in() / bridge__remap_topic_out()
   *   - Multi-hop forwarding: message routing through bridged brokers
   *   - $SYS/broker/bridge/ status topic handling
   *   - Retained message propagation across bridge links
   *
   * Topic patterns chosen to cover common bridge configurations:
   *   "bridge/+"        — explicit bridge namespace (remap target)
   *   "remote/#"        — remote prefix patterns (remap source)
   *   "local/#"         — local prefix patterns (remap target)
   *   "$SYS/broker/#"   — broker status including bridge status topics
   * ════════════════════════════════════════════════════════════════════ */

  /* B1-1: Bridge namespace — catches messages forwarded through bridge links.
   * Exercises handle__subscribe() with bridge-typical topic patterns and
   * sub__messages_queue() for messages with bridge-prefixed topics. */
  if (use_v5_sub)
    pkt_len = pack_subscribe_v5(pkt, sizeof(pkt), 6, "bridge/+", sub_qos);
  else
    pkt_len = pack_subscribe(pkt, sizeof(pkt), 6, "bridge/+", sub_qos);
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  /* B1-2: Remote prefix pattern — simulates the remote side of a topic
   * remap rule.  When a bridge is configured with remote_prefix "remote/",
   * messages published to "remote/X" on the remote broker get remapped
   * to "local/X" locally.  This subscription captures the remote side. */
  if (use_v5_sub)
    pkt_len = pack_subscribe_v5(pkt, sizeof(pkt), 7, "remote/#", 1);
  else
    pkt_len = pack_subscribe(pkt, sizeof(pkt), 7, "remote/#", 1);
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  /* B1-3: Local prefix pattern — the local side of remap.
   * Messages arriving from bridge with local_prefix "local/" appear here. */
  pkt_len = pack_subscribe(pkt, sizeof(pkt), 8, "local/#", 1);
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  /* B1-4: Broker status topics including bridge status.
   * $SYS/broker/connection/<bridge_name>/state reports bridge up/down.
   * Exercises sys_tree.c → sys_tree__update_*() bridge status paths. */
  pkt_len = pack_subscribe(pkt, sizeof(pkt), 9, "$SYS/broker/#", 0);
  if (pkt_len > 0) {
    net_send(ctx->fds[SUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  /* B1-5: Publish to bridge/remap topics from pub_fd to trigger
   * cross-topic forwarding paths.  This exercises:
   *   - db__messages_queue() with bridge-prefixed topics
   *   - bridge__remap_topic_out() when bridge is configured
   *   - Retained message delivery for bridge topics */
  pkt_len = pack_publish_simple(pkt, sizeof(pkt), "bridge/test", "BRG1", 1, 0, 101);
  if (pkt_len > 0) {
    net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[PUB_IDX], ctx->timeout, ctx->poll_wait_msecs,
             &priv->handshake_resp, &priv->handshake_resp_len);
    /* Drain forwarded message on sub_fd */
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, 2,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  pkt_len = pack_publish_simple(pkt, sizeof(pkt), "remote/data", "REM1", 0, 0, 0);
  if (pkt_len > 0) {
    net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[PUB_IDX], ctx->timeout, 1,
             &priv->handshake_resp, &priv->handshake_resp_len);
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, 2,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }

  /* B1-6: Retained message on bridge topic — exercises retain__store()
   * for bridge-prefixed topics + subsequent delivery on bridge subscribe. */
  pkt_len = pack_publish_simple(pkt, sizeof(pkt), "bridge/retained", "BR_RET", 0, 1, 0);
  if (pkt_len > 0) {
    net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)pkt, pkt_len);
    net_recv(ctx->fds[PUB_IDX], ctx->timeout, 1,
             &priv->handshake_resp, &priv->handshake_resp_len);
  }

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
    /* V3-1-adaptive: Self-tuning forwarding drain.
     * Uses mqtt_fwd_drain_ms (starts at 3, auto-tuned to 3-6).
     * Retry = drain_ms - 1 (min 1ms). */
    u32 drain_ms = mqtt_fwd_drain_ms > 0 ? mqtt_fwd_drain_ms : 3;
    u32 retry_ms = drain_ms > 1 ? drain_ms - 1 : 1;
    net_recv(ctx->fds[SUB_IDX], ctx->timeout, (int)drain_ms,
             &fwd_buf, &fwd_len);
    if (fwd_len > 0)
      net_recv(ctx->fds[SUB_IDX], ctx->timeout, (int)retry_ms,
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

            /* V4-3: Complete QoS handshake for forwarded PUBLISH.
             * Exercises broker's outgoing message state machine:
             *   QoS 1: PUBACK  → handle__pubackcomp()
             *   QoS 2: PUBREC  → handle__pubrec()
             *          (drain) → send__pubrel()
             *          PUBCOMP → handle__pubcomp() + db__message_dequeue() */
            if (e->fwd_qos > 0) {
              u32 pid_off = body_off + 2 + tlen;
              if (pid_off + 1 < fwd_len) {
                u16 fwd_pid = (u16)(((u8)fwd_buf[pid_off] << 8) |
                                    (u8)fwd_buf[pid_off + 1]);
                u8 ack[4];
                u32 al;
                if (e->fwd_qos == 1) {
                  al = pack_puback(ack, sizeof(ack), fwd_pid);
                  if (al > 0)
                    net_send(ctx->fds[SUB_IDX], ctx->timeout,
                             (char *)ack, al);
                } else if (e->fwd_qos == 2) {
                  al = pack_pubrec(ack, sizeof(ack), fwd_pid);
                  if (al > 0) {
                    net_send(ctx->fds[SUB_IDX], ctx->timeout,
                             (char *)ack, al);
                    char *rel_buf = NULL;
                    unsigned int rel_len = 0;
                    net_recv(ctx->fds[SUB_IDX], ctx->timeout, 1,
                             &rel_buf, &rel_len);
                    al = pack_pubcomp(ack, sizeof(ack), fwd_pid);
                    if (al > 0)
                      net_send(ctx->fds[SUB_IDX], ctx->timeout,
                               (char *)ack, al);
                    if (rel_buf) ck_free(rel_buf);
                  }
                }
                priv->qos_acks++;
              }
            }
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

    /* P8b self-adaptive drain tuning (only if not fixed by env var).
     * Strategy: if the fwd buffer saturated (fwd_count == max), the
     * broker likely has complex routing (shared subs) and we're
     * missing messages → increase drain by 1ms (cap 6ms).
     * If we've had 200+ consecutive low-fwd calls (fwd_count ≤ 1),
     * the broker's routing is simple → decrease drain by 1ms (floor 2ms).
     * This converges to the right value within ~200 executions. */
    if (priv && !mqtt_fwd_drain_fixed) {
      static u32 quiet_streak = 0;
      if (priv->fwd_count >= MQTT_FWD_DIFF_MAX) {
        if (mqtt_fwd_drain_ms < 6) mqtt_fwd_drain_ms++;
        quiet_streak = 0;
      } else if (priv->fwd_count <= 1) {
        quiet_streak++;
        if (quiet_streak >= 200 && mqtt_fwd_drain_ms > 2) {
          mqtt_fwd_drain_ms--;
          quiet_streak = 0;
        }
      } else {
        quiet_streak = 0;
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
  /* V3-1b-rev: Configurable drain on sub_fd (= mqtt_fwd_drain_ms - 1,
   * min 2ms) to catch late forwarded PUBLISHes. */
  { u32 dm = mqtt_fwd_drain_ms > 2 ? mqtt_fwd_drain_ms - 1 : 2;
    net_recv(ctx->fds[SUB_IDX],  ctx->timeout, (int)dm,
             ctx->response_buf, (unsigned int *)ctx->response_buf_size);
  }
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

  /* V4-4: Clear retained messages — exercises retain__clean() / retain__remove().
   * An empty-payload PUBLISH with retain=1 tells the broker to remove
   * any retained message for that topic. This exercises a different code
   * path from retain__store() (which was exercised in handshake). */
  if (ctx->fds[PUB_IDX] >= 0) {
    u8 rpkt[32];
    u32 rlen;
    rlen = pack_publish_simple(rpkt, sizeof(rpkt), "r/test", "", 0, 1, 0);
    if (rlen > 0)
      net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)rpkt, rlen);
    rlen = pack_publish_simple(rpkt, sizeof(rpkt), "r/sys", "", 0, 1, 0);
    if (rlen > 0)
      net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)rpkt, rlen);
    /* B1-cleanup: Clear bridge-related retained messages */
    rlen = pack_publish_simple(rpkt, sizeof(rpkt), "bridge/retained", "", 0, 1, 0);
    if (rlen > 0)
      net_send(ctx->fds[PUB_IDX], ctx->timeout, (char *)rpkt, rlen);
  }

  /* Graceful DISCONNECT on all fds.
   * V5: For phases that used v5 CONNECT on ctrl_fd (1,4,5), send a v5
   * DISCONNECT with Session Expiry Interval property → exercises
   * property__process_disconnect() in property_broker.c (~15 lines). */
  {
    mqtt_mp_priv_t *priv = (mqtt_mp_priv_t *)ctx->priv;
    u8 v5_disc_phase = (priv && mqtt_field_mutate_enabled &&
                        (priv->phase == 1 || priv->phase == 4 || priv->phase == 5));
    for (int i = 0; i < ctx->fd_count; i++) {
      if (ctx->fds[i] < 0) continue;
      if (i == CTRL_IDX && v5_disc_phase) {
        u8 dpkt[16];
        u32 dlen = pack_disconnect_v5(dpkt, sizeof(dpkt));
        if (dlen > 0)
          net_send(ctx->fds[i], ctx->timeout, (char *)dpkt, dlen);
      } else {
        u8 disc[2] = { 0xE0, 0x00 };
        net_send(ctx->fds[i], ctx->timeout, (char *)disc, 2);
      }
    }
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
