/* mqtt-connpool.h — MQTT secondary broker pool for O1+O2 optimizations.
 *
 * O1 (Streamlined Secondary Execution):
 *   - Pre-parsed broker metadata eliminates per-execution env var parsing
 *   - Lightweight replay path bypasses full mp_driver_t lifecycle
 *   - Centralized health tracking with automatic failure back-off
 *
 * O2 (Heterogeneous Broker Differential):
 *   - Each entry tracks broker implementation name (mosquitto, nanomq, …)
 *   - Cross-implementation divergences receive boosted differential scores
 *   - Env var format: "impl@tcp://host:port,impl@tcp://host:port,…"
 *
 * Architecture:
 *   Entry 0 of CHATAFL_MQTT_BROKERS is the primary (SUT under fork server).
 *   The pool stores entries 1..N as "secondary" differential brokers.
 *   TCP connections are established and torn down per execution — MQTT
 *   DISCONNECT triggers server-side TCP close, so true persistence is
 *   infeasible.  The pool's value is in metadata caching, streamlined
 *   code path, and O2 implementation-aware differential boosting.
 */

#ifndef __MQTT_CONNPOOL_H
#define __MQTT_CONNPOOL_H

#include "types.h"
#include "mqtt-differential.h"
#include <sys/time.h>

#define MQTT_POOL_MAX_ENTRIES  16
#define MQTT_POOL_IMPL_LEN    64

/* Consecutive failure limit before an entry is skipped. */
#define MQTT_POOL_MAX_CONSEC_FAIL 10

/* ────────────────────────────────────────────────────────────────────
 * Per-broker metadata and lifetime statistics.
 * ──────────────────────────────────────────────────────────────────── */
typedef struct {
  char ip[256];                       /* Resolved IP or hostname           */
  u32  port;                          /* TCP port                          */
  char impl[MQTT_POOL_IMPL_LEN];     /* O2: broker implementation name    */
  u64  total_executions;              /* Lifetime successful executions    */
  u64  total_failures;                /* Lifetime failures                 */
  u32  consecutive_failures;          /* Consecutive failures (reset on ok)*/
} mqtt_pool_entry_t;

/* ────────────────────────────────────────────────────────────────────
 * Connection pool — secondary broker registry + execution helpers.
 * ──────────────────────────────────────────────────────────────────── */
typedef struct {
  mqtt_pool_entry_t entries[MQTT_POOL_MAX_ENTRIES];
  u32             count;              /* Number of secondary entries       */
  struct timeval  timeout;            /* Socket send/recv timeout          */
  s32             poll_wait_msecs;    /* poll() wait for net_recv          */
  char            primary_impl[MQTT_POOL_IMPL_LEN]; /* O2: primary impl  */
} mqtt_conn_pool_t;

/* ────────────────────────────────────────────────────────────────────
 * Initialize pool from CHATAFL_MQTT_BROKERS env var.
 *
 * Format: "impl@tcp://host:port,impl@tcp://host:port,…"
 * Legacy: "tcp://host:port,tcp://host:port" (impl = "unknown")
 *
 * Entry 0 → primary impl stored in pool->primary_impl (NOT in entries[]).
 * Entries 1..N → stored in pool->entries[0..count-1] as secondaries.
 *
 * Returns: count of secondary entries (pool->count).
 *          0 if env var unset or has < 2 entries.
 * ──────────────────────────────────────────────────────────────────── */
int mqtt_pool_init(mqtt_conn_pool_t *pool,
                   u32 socket_timeout_usecs,
                   s32 poll_wait_msecs);

/* ────────────────────────────────────────────────────────────────────
 * Execute test case on a secondary broker (lightweight path).
 *
 * Opens 3 TCP connections, performs minimal MQTT v3.1.1 handshake,
 * replays kl_messages with role routing (sub/pub/ctrl), collects
 * response, builds signature, parses fields, and closes connections.
 *
 * Parameters:
 *   pool       — initialized pool
 *   idx        — index into pool->entries[] (0..count-1)
 *   out_sig    — if non-NULL, receives FNV-1a signature (caller frees)
 *   out_fields — if non-NULL, receives parsed fields for differential
 *
 * Returns: 0 on success, -1 on failure (entry stats updated).
 *          Skips entries with consecutive_failures >= MAX_CONSEC_FAIL.
 * ──────────────────────────────────────────────────────────────────── */
int mqtt_pool_exec_secondary(mqtt_conn_pool_t *pool, u32 idx,
                             char **out_sig,
                             mqtt_response_fields_t *out_fields);

/* ────────────────────────────────────────────────────────────────────
 * Check if secondary[idx] has a different implementation than primary.
 * Returns: 1 if cross-implementation, 0 if same or either is "unknown".
 * ──────────────────────────────────────────────────────────────────── */
u8 mqtt_pool_is_cross_impl(const mqtt_conn_pool_t *pool, u32 idx);

/* ────────────────────────────────────────────────────────────────────
 * Reset consecutive failure counter for an entry (e.g., after a
 * broker restart is detected).
 * ──────────────────────────────────────────────────────────────────── */
void mqtt_pool_reset_failures(mqtt_conn_pool_t *pool, u32 idx);

/* ────────────────────────────────────────────────────────────────────
 * Clean up pool (no persistent resources to free, but zeroes stats).
 * ──────────────────────────────────────────────────────────────────── */
void mqtt_pool_destroy(mqtt_conn_pool_t *pool);

#endif /* __MQTT_CONNPOOL_H */
