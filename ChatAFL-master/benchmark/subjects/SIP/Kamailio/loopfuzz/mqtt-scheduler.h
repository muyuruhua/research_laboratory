/* mqtt-scheduler.h — Q-Learning message type scheduler + UCB1 bandit
 *                     for MQTT-aware fuzzing in LoopFuzz.
 *
 * Two complementary schedulers, both protocol-gated (MQTT only):
 *
 *   1. Q-Learning Message Scheduler
 *      - Maps (IPSM state, packet type) → expected reward.
 *      - Uses Softmax with temperature annealing for action selection.
 *      - Learns which MQTT packet types yield new coverage in each
 *        protocol state (e.g., SUBSCRIBE is productive after CONNACK).
 *      - Inspired by MBFuzzer's q_learning.py Softmax Q-table.
 *
 *   2. UCB1 Bandit Arm Selector
 *      - Selects among four MQTT havoc strategies:
 *          Arm 0: Replace region with generated packet
 *          Arm 1: Insert generated packet
 *          Arm 2: Field-aware byte-level mutation
 *          Arm 3: Skip (rely on generic havoc only)
 *      - Balances exploration/exploitation via Upper Confidence Bound.
 *
 * Zero impact on other text protocols — all calls are gated by
 * mqtt_field_mutate_enabled.
 */

#ifndef _MQTT_SCHEDULER_H
#define _MQTT_SCHEDULER_H

#include "types.h"

/* ═══════════════════════════════════════════════════════════════════
 * Section 1: Q-Learning Message Type Scheduler
 * ═══════════════════════════════════════════════════════════════════ */

#define MQTT_QL_MAX_STATES  32   /* Max distinct IPSM states tracked */
#define MQTT_QL_N_ACTIONS   11   /* 11 client-sendable MQTT packet types:
                                  * CONNECT, PUBLISH, SUBSCRIBE,
                                  * UNSUBSCRIBE, PINGREQ, DISCONNECT,
                                  * PUBACK, PUBREC, PUBREL, PUBCOMP, AUTH */

typedef struct {
  double q[MQTT_QL_MAX_STATES][MQTT_QL_N_ACTIONS];       /* Q-value table */
  u32    count[MQTT_QL_MAX_STATES][MQTT_QL_N_ACTIONS];    /* attempt count */
  double alpha;        /* learning rate (default 0.1) */
  double gamma;        /* discount factor (default 0.8) */
  double tau;          /* Softmax temperature (starts 2.0) */
  double tau_min;      /* annealing floor (default 0.3) */
  double tau_decay;    /* per-update decay (default 0.9999) */
  u32    total_updates;
} mqtt_ql_t;

/* ═══════════════════════════════════════════════════════════════════
 * Section 2: UCB1 Multi-Armed Bandit
 * ═══════════════════════════════════════════════════════════════════ */

#define MQTT_BANDIT_N_ARMS  4    /* replace / insert / field / skip */

typedef struct {
  u32    attempts[MQTT_BANDIT_N_ARMS];
  double rewards[MQTT_BANDIT_N_ARMS];
  u32    total;
} mqtt_bandit_t;

/* ═══════════════════════════════════════════════════════════════════
 * Section 3: API
 * ═══════════════════════════════════════════════════════════════════ */

/* Q-Learning */
void mqtt_ql_init(mqtt_ql_t *ql);
u8   mqtt_ql_select(mqtt_ql_t *ql, u32 state_idx);  /* returns pkt_type constant */
void mqtt_ql_update(mqtt_ql_t *ql, u32 state_idx, u8 pkt_type, double reward);

/* UCB1 Bandit */
void mqtt_bandit_init(mqtt_bandit_t *b);
u32  mqtt_bandit_select(mqtt_bandit_t *b);  /* returns arm index 0-3 */
void mqtt_bandit_update(mqtt_bandit_t *b, u32 arm, double reward);

/* Packet type ↔ action index mapping */
u32 mqtt_pkt_to_action(u8 pkt_type);
u8  mqtt_action_to_pkt(u32 action);

#endif /* _MQTT_SCHEDULER_H */
