/* mqtt-scheduler.c — Q-Learning + UCB1 bandit for MQTT fuzzing.
 *
 * Implementation of the schedulers declared in mqtt-scheduler.h.
 * Mirrors MBFuzzer's q_learning.py Softmax Q-table architecture
 * while fitting naturally into LoopFuzz's C codebase.
 */

#include "mqtt-scheduler.h"
#include "mqtt-generate.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * Section 1: Action ↔ Packet-Type Mapping
 *
 * Indices 0-10 map to the 11 client-sendable MQTT packet types,
 * matching the order in mqtt-generate.c's client_types[].
 * ═══════════════════════════════════════════════════════════════════ */

static const u8 action_to_pkt_map[MQTT_QL_N_ACTIONS] = {
  MQTG_CONNECT,      /* 0 → 1  */
  MQTG_PUBLISH,      /* 1 → 3  */
  MQTG_SUBSCRIBE,    /* 2 → 8  */
  MQTG_UNSUBSCRIBE,  /* 3 → 10 */
  MQTG_PINGREQ,      /* 4 → 12 */
  MQTG_DISCONNECT,   /* 5 → 14 */
  MQTG_PUBACK,       /* 6 → 4  */
  MQTG_PUBREC,       /* 7 → 5  */
  MQTG_PUBREL,       /* 8 → 6  */
  MQTG_PUBCOMP,      /* 9 → 7  */
  MQTG_AUTH,         /* 10 → 15 */
};

u32 mqtt_pkt_to_action(u8 pkt_type) {
  for (u32 i = 0; i < MQTT_QL_N_ACTIONS; i++)
    if (action_to_pkt_map[i] == pkt_type) return i;
  return 1; /* fallback to PUBLISH (most common) */
}

u8 mqtt_action_to_pkt(u32 action) {
  if (action >= MQTT_QL_N_ACTIONS) return MQTG_PUBLISH;
  return action_to_pkt_map[action];
}

/* ═══════════════════════════════════════════════════════════════════
 * Section 2: Q-Learning Message Type Scheduler
 *
 * Softmax action selection with temperature annealing.
 * Q-update rule: Q(s,a) ← Q(s,a) + α [r + γ·max_a' Q(s,a') − Q(s,a)]
 *
 * Because the IPSM state doesn't change within a single havoc loop
 * iteration, next_state ≈ current_state.  The γ·max term still
 * provides valuable gradient toward higher-reward actions.
 * ═══════════════════════════════════════════════════════════════════ */

void mqtt_ql_init(mqtt_ql_t *ql) {
  memset(ql, 0, sizeof(*ql));
  ql->alpha     = 0.10;   /* learning rate — responsive but stable */
  ql->gamma     = 0.80;   /* discount — value future rewards */
  ql->tau       = 2.00;   /* initial Softmax temperature — high exploration */
  ql->tau_min   = 0.30;   /* temperature floor — always some randomness */
  ql->tau_decay = 0.9999; /* slow anneal ≈ 5000 updates to halve */
  ql->total_updates = 0;

  /* Optimistic initialization: small positive Q-values encourage
   * exploration of untried actions (UCB-like effect). */
  for (u32 s = 0; s < MQTT_QL_MAX_STATES; s++)
    for (u32 a = 0; a < MQTT_QL_N_ACTIONS; a++)
      ql->q[s][a] = 0.1;
}

u8 mqtt_ql_select(mqtt_ql_t *ql, u32 state_idx) {
  if (state_idx >= MQTT_QL_MAX_STATES) state_idx = 0;

  /* ── Warmup: round-robin so every action is tried at least once ── */
  u32 state_total = 0;
  for (u32 a = 0; a < MQTT_QL_N_ACTIONS; a++)
    state_total += ql->count[state_idx][a];

  if (state_total < MQTT_QL_N_ACTIONS) {
    return action_to_pkt_map[state_total];
  }

  /* ── Softmax selection (numerically stable via max subtraction) ── */
  double probs[MQTT_QL_N_ACTIONS];
  double max_q = -1e30;
  for (u32 a = 0; a < MQTT_QL_N_ACTIONS; a++)
    if (ql->q[state_idx][a] > max_q) max_q = ql->q[state_idx][a];

  double sum = 0.0;
  for (u32 a = 0; a < MQTT_QL_N_ACTIONS; a++) {
    probs[a] = exp((ql->q[state_idx][a] - max_q) / ql->tau);
    sum += probs[a];
  }

  /* Weighted random selection */
  double r = (double)(random() % 10000) / 10000.0;
  double cumul = 0.0;
  for (u32 a = 0; a < MQTT_QL_N_ACTIONS; a++) {
    cumul += probs[a] / sum;
    if (r <= cumul) return action_to_pkt_map[a];
  }
  return action_to_pkt_map[MQTT_QL_N_ACTIONS - 1]; /* numerical safety */
}

void mqtt_ql_update(mqtt_ql_t *ql, u32 state_idx, u8 pkt_type, double reward) {
  if (state_idx >= MQTT_QL_MAX_STATES) state_idx = 0;
  u32 a = mqtt_pkt_to_action(pkt_type);

  /* max Q(s, a') for the same state (next_state ≈ current_state) */
  double max_next_q = -1e30;
  for (u32 i = 0; i < MQTT_QL_N_ACTIONS; i++)
    if (ql->q[state_idx][i] > max_next_q)
      max_next_q = ql->q[state_idx][i];

  /* Q-Learning update: Q(s,a) ← Q(s,a) + α[r + γ·max - Q(s,a)] */
  double target = reward + ql->gamma * max_next_q;
  ql->q[state_idx][a] += ql->alpha * (target - ql->q[state_idx][a]);

  ql->count[state_idx][a]++;
  ql->total_updates++;

  /* Temperature annealing */
  if (ql->tau > ql->tau_min)
    ql->tau *= ql->tau_decay;
}

/* ═══════════════════════════════════════════════════════════════════
 * Section 3: UCB1 Multi-Armed Bandit
 *
 * Selects among MQTT havoc arms:
 *   Arm 0: Replace region with generated MQTT packet
 *   Arm 1: Insert generated MQTT packet
 *   Arm 2: Field-aware byte-level mutation
 *   Arm 3: Skip (let generic havoc work alone)
 *   Arm 4: Corpus-splice + field-aware mutation (O7: plateau)
 *   Arm 5: SUBSCRIBE→PUBLISH pair injection (B1-companion)
 *
 * UCB1 score = exploit + explore
 *   exploit = avg_reward = rewards[arm] / attempts[arm]
 *   explore = sqrt(2 · ln(total) / attempts[arm])
 * ═══════════════════════════════════════════════════════════════════ */

void mqtt_bandit_init(mqtt_bandit_t *b) {
  memset(b, 0, sizeof(*b));
  /* O5: Bias the skip arm (arm 3) with a low-reward prior so UCB1
   * doesn't waste early exploration on generic havoc, which is
   * largely ineffective for binary MQTT packets.  The other arms
   * start with optimistic priors that encourage exploration. */
  b->attempts[0] = 1; b->rewards[0] = 0.5;  /* replace: optimistic */
  b->attempts[1] = 1; b->rewards[1] = 0.5;  /* insert:  optimistic */
  b->attempts[2] = 1; b->rewards[2] = 0.5;  /* field:   optimistic */
  b->attempts[3] = 1; b->rewards[3] = 0.05; /* skip:    pessimistic */
  b->attempts[4] = 1; b->rewards[4] = 0.4;  /* corpus-splice: moderate */
  b->attempts[5] = 1; b->rewards[5] = 0.75; /* sub-pub pair: boosted for shared-sub forwarding paths */
  b->total = 6;
}

u32 mqtt_bandit_select(mqtt_bandit_t *b) {
  /* Warmup: try each arm at least once */
  for (u32 i = 0; i < MQTT_BANDIT_N_ARMS; i++)
    if (b->attempts[i] == 0) return i;

  double best_score = -1.0;
  u32    best_arm   = 0;
  double log_total  = log((double)b->total);

  for (u32 i = 0; i < MQTT_BANDIT_N_ARMS; i++) {
    double exploit = b->rewards[i] / (double)b->attempts[i];
    double explore = sqrt(2.0 * log_total / (double)b->attempts[i]);
    double score   = exploit + explore;
    if (score > best_score) {
      best_score = score;
      best_arm   = i;
    }
  }
  return best_arm;
}

void mqtt_bandit_update(mqtt_bandit_t *b, u32 arm, double reward) {
  if (arm >= MQTT_BANDIT_N_ARMS) return;
  b->attempts[arm]++;
  b->rewards[arm] += reward;
  b->total++;
}
