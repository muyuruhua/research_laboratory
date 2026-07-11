/* mqtt-race.h — MQTT Race Window Probe for concurrent scenario fuzzing.
 *
 * Bridges the architectural gap between LoopFuzz's serial 3-fd model
 * and MBFuzzer's Petri-net parallel scheduling by adding a dedicated
 * post-execution race probe phase using pthreads.
 *
 * Design rationale:
 *   MBFuzzer (USENIX Security 2025) discovers 73 bugs (20 memory +
 *   53 non-compliance) using N independent Senders with Petri-net
 *   dependency-aware scheduling.  Key bug classes require TRUE
 *   concurrency that serial 3-fd role routing cannot achieve:
 *     - CWE-362: Session resume + retained publish race (Mosquitto)
 *     - CWE-672: Shared subscription duplicate delivery (EMQX)
 *     - CWE-284: $SYS topic access via wildcard timing (NanoMQ)
 *
 *   This module runs AFTER the normal serial message loop, creating
 *   separate TCP connections and using pthread barriers for precise
 *   timing synchronization.  Each race pattern is a self-contained
 *   scenario that exercises specific broker concurrency logic.
 *
 * OCP compliance:
 *   - Pure extension: new files (mqtt-race.h/c), no existing code modified
 *   - Called from MQTT-gated path in afl-fuzz.c via simple function call
 *   - Zero impact on FTP/RTSP/SIP/SMTP protocols
 *   - Integrates with existing mqtt_save_diff_report() for output
 *
 * Threading safety:
 *   - All probe state is stack-local or in probe-private heap allocations
 *   - No writes to global fuzzer state (trace_bits, kl_messages, etc.)
 *   - Only side effect: mqtt_save_diff_report() calls (serialized internally)
 */

#ifndef _MQTT_RACE_H
#define _MQTT_RACE_H

#include "types.h"

/* ── Race pattern identifiers ────────────────────────────────────── */
#define MQTT_RACE_SESSION_RESUME    0  /* disconnect+reconnect vs retained publish */
#define MQTT_RACE_SHARED_SUB       1  /* duplicate delivery in shared subscriptions */
#define MQTT_RACE_WILL_DELIVERY    2  /* abrupt disconnect will vs normal publish */
#define MQTT_RACE_RETAIN_SUBSCRIBE 3  /* $SYS retained publish vs wildcard subscribe */
#define MQTT_RACE_PATTERN_COUNT    4

/* ── Statistics ─────────────────────────────────────────────────── */
typedef struct {
  u32 total_probes;
  u32 anomalies_found;        /* crashes + divergences */
  u32 pattern_hits[MQTT_RACE_PATTERN_COUNT];
} mqtt_race_stats_t;

/* ── Public API ─────────────────────────────────────────────────── */

/* Initialize the race probe module.  Call once from main(). */
void mqtt_race_init(void);

/* Execute a race probe against the target broker.
 *
 * ip/port      : target broker address (primary broker)
 * pattern      : which race pattern to run, or -1 for round-robin auto-select
 *
 * Returns 1 if an anomaly (crash / unexpected response) was detected.
 *
 * Thread safety: This function spawns internal pthreads but joins them
 * all before returning.  Safe to call from the main fuzzing loop. */
int mqtt_race_probe(const char *ip, u32 port, int pattern);

/* Rate-limiting gate: returns 1 if a race probe should run this execution.
 * Default: once every MQTT_RACE_PROBE_INTERVAL executions after warmup. */
int mqtt_race_should_probe(u64 total_execs);

/* Retrieve cumulative statistics. */
mqtt_race_stats_t mqtt_race_get_stats(void);

#endif /* _MQTT_RACE_H */
