/* mp-driver.h — Multi-Party Driver interface for protocol fuzzing.
 *
 * Generalizes the "open N connections → handshake → route messages by
 * role → drain forwarding target → cleanup" skeleton so that each
 * protocol only provides a thin set of callbacks while
 * send_over_network() keeps the loop logic protocol-agnostic.
 *
 * Design principles:
 *   1. Open-Closed: new protocols add a driver .c file and register it;
 *      the skeleton in afl-fuzz.c never changes.
 *   2. Zero-cost for non-MP protocols: mp_driver_for_protocol() returns
 *      NULL → single-fd path is taken, exactly as before.
 *   3. Graceful fallback: if open_connections() or handshake() fails,
 *      the skeleton falls back to single-fd path.
 *
 * Terminology:
 *   fd_count — number of concurrent connections the driver needs.
 *   role     — integer 0..fd_count-1, meaning is driver-defined.
 *              By convention role 0 is the "control" channel.
 *   fds[]    — array of fd_count file descriptors, allocated by the
 *              skeleton, populated by open_connections().
 */

#ifndef __MP_DRIVER_H
#define __MP_DRIVER_H

#include <sys/time.h>   /* struct timeval */
#include "types.h"      /* u8, u32, s32 */

/* ────────────────────────────────────────────────────────────────────
 * Forward declarations (types defined in main translation unit)
 * ──────────────────────────────────────────────────────────────────── */
struct mp_driver;

/* ────────────────────────────────────────────────────────────────────
 * mp_context_t — per-execution runtime context passed to every callback.
 *
 * The skeleton fills in these fields before calling any callback.
 * Callbacks may read/write them freely.
 * ──────────────────────────────────────────────────────────────────── */
typedef struct {
  int            *fds;              /* array of fd_count open fds          */
  int             fd_count;         /* number of fds                       */
  struct timeval  timeout;          /* socket send/recv timeout            */
  s32             poll_wait_msecs;  /* poll wait for net_recv              */
  const char     *server_ip;       /* target IP string                    */
  u32             server_port;      /* target port                         */

  /* Shared response accumulation buffer — same global pointers that the
   * single-fd path uses.  Callbacks should call net_recv() with these. */
  char          **response_buf;       /* &response_buf      (global ptr)  */
  int            *response_buf_size;  /* &response_buf_size (global int)  */

  /* Private per-driver opaque state (e.g., handshake_resp for MQTT).
   * Allocated in handshake(), freed in cleanup(). */
  void           *priv;
} mp_context_t;

/* ────────────────────────────────────────────────────────────────────
 * mp_driver_t — virtual function table for a multi-party protocol.
 *
 * All function pointers are mandatory (non-NULL).
 * ──────────────────────────────────────────────────────────────────── */
typedef struct mp_driver {
  const char *name;       /* human-readable, e.g. "MQTT", "SIP" */
  int         fd_count;   /* how many concurrent fds this driver needs */

  /* ── open_connections ──
   * Open fd_count TCP/UDP connections and fill ctx->fds[0..fd_count-1].
   * Return 0 on success, -1 on failure (skeleton will fallback).
   * The skeleton has already allocated ctx->fds with fd_count slots. */
  int  (*open_connections)(mp_context_t *ctx);

  /* ── handshake ──
   * Perform protocol-level session establishment on every fd
   * (e.g. MQTT CONNECT + SUBSCRIBE on subscriber fd).
   * Return 0 on success, -1 on failure → goto cleanup. */
  int  (*handshake)(mp_context_t *ctx);

  /* ── role_for_message ──
   * Given a raw message buffer, return a role index 0..fd_count-1
   * that determines which fd to send this message on.
   * Return -1 if this message should be SKIPPED entirely
   * (e.g., CONNECT / DISCONNECT packets that the handshake already
   * handles). */
  int  (*role_for_message)(mp_context_t *ctx,
                           const unsigned char *msg, u32 msg_len);

  /* ── after_send ──
   * Called after each successful send+recv on target_fd.
   * Gives the driver a chance to drain *other* fds for forwarded data.
   * role = the role that was just sent to.
   * Return 0 normally; -1 to abort the message loop (rare). */
  int  (*after_send)(mp_context_t *ctx, int role);

  /* ── drain_all ──
   * Final drain of all fds after the message loop ends (or on error).
   * Typically calls net_recv() on every fd one last time. */
  void (*drain_all)(mp_context_t *ctx);

  /* ── cleanup ──
   * Send graceful disconnects, free ctx->priv, do any
   * protocol-specific post-processing (e.g. mqtt_probe_cluster_differences).
   * The skeleton will close all fds after this returns. */
  void (*cleanup)(mp_context_t *ctx);

} mp_driver_t;

/* ────────────────────────────────────────────────────────────────────
 * Driver registry — returns the driver for the given protocol name,
 * or NULL if no multi-party driver exists for this protocol.
 *
 * This is the ONLY function the skeleton calls to discover drivers.
 * New protocols register themselves by adding a case here.
 * ──────────────────────────────────────────────────────────────────── */
const mp_driver_t *mp_driver_for_protocol(const char *protocol_name);

/* ────────────────────────────────────────────────────────────────────
 * Built-in driver accessors (one per protocol that implements MP).
 * Each lives in its own .c file.
 * ──────────────────────────────────────────────────────────────────── */
const mp_driver_t *mp_driver_mqtt(void);
/* const mp_driver_t *mp_driver_sip(void);   — future */

#endif /* __MP_DRIVER_H */
