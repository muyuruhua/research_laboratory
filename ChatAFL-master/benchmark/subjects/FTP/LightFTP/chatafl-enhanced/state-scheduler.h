#ifndef __STATE_SCHEDULER_H
#define __STATE_SCHEDULER_H

#include "types.h"
#include "verifier.h"
#include "aflnet.h"
#include <json-c/json.h>

/*
 * State-aware Scheduling (inspired by USENIX'22 Stateful Greybox Fuzzing)
 * 
 * Instead of pure coverage feedback, use state rarity and transitions:
 * - Prioritize seeds that reach rare (low visitation) states
 * - Track state transitions to detect plateau
 * - When plateau: ask LLM to generate sequences leading to low-coverage states
 */

typedef struct {
    unsigned int state_id;
    float rarity;              // 1.0 / (1 + visitation_count)
    float coverage;            // code coverage at this state
    int incoming_transition_count;  // how many distinct messages reach this?
    int outgoing_transition_count;  // how many states reachable from this?
} state_stats_t;

typedef struct {
    unsigned int state_a;
    unsigned int state_b;
    char *triggering_message;
    int frequency;
    float coverage_delta;
    int is_rare;               // transition rarely triggered?
} rare_transition_t;

typedef struct {
    state_transition_tree_t *stt;
    state_stats_t *state_stats;
    int state_stats_count;
    
    rare_transition_t *rare_transitions;
    int rare_transition_count;
    
    int plateau_counter;       // if coverage flat for N iterations → trigger LLM
    int plateau_threshold;
    float last_coverage;       // coverage at last check
} state_scheduler_t;

/* ============ Scheduling Functions ============ */

/**
 * @brief Initialize state-aware scheduler
 */
void state_scheduler_init(
    state_scheduler_t *scheduler,
    int plateau_threshold
);

/**
 * @brief Update state rarity statistics after fuzzing round
 */
void update_state_rarity(
    state_scheduler_t *scheduler
);

/**
 * @brief Compute rarity score (inverse of visitation frequency)
 * Higher = rarer = higher priority
 */
float compute_state_rarity(
    const state_transition_tree_t *stt,
    unsigned int state_id
);

/**
 * @brief Identify rare transitions (transitions rarely triggered)
 * Updates scheduler->rare_transitions
 */
void identify_rare_transitions(
    state_scheduler_t *scheduler,
    float rarity_threshold
);

/**
 * @brief Select next seed using state rarity + coverage feedback
 * 
 * @param scheduler  state scheduler context
 * @param queue_head  AFL queue head
 * @param rarity_weight  0.0-1.0: how much to weight rarity vs coverage
 *                       0.5 = 50% rarity, 50% coverage
 * 
 * @return selected seed (or NULL if queue empty)
 */
struct queue_entry *select_seed_by_state_rarity(
    state_scheduler_t *scheduler,
    struct queue_entry *queue_head,
    float rarity_weight
);

/**
 * @brief Detect plateau: has coverage stalled?
 * @return 1 if plateau detected, 0 otherwise
 */
int detect_coverage_plateau(
    state_scheduler_t *scheduler,
    float current_coverage
);

/**
 * @brief Reset plateau counter when coverage increases
 */
void reset_plateau_counter(state_scheduler_t *scheduler);

/**
 * @brief Construct prompt asking LLM to reach specific state
 * Used when plateau detected and coverage is stalled
 * 
 * @param protocol_name   e.g., "RTSP"
 * @param target_state_id  the low-coverage state to target
 * @param stt              state transition tree for context
 * @param verified_grammars  library of verified message grammars
 * 
 * @return Prompt string asking "how to reach state X?" (caller frees)
 */
char *construct_state_targeting_prompt(
    const char *protocol_name,
    unsigned int target_state_id,
    const state_transition_tree_t *stt,
    json_object *verified_grammars
);

/**
 * @brief Log state scheduling decision
 */
void log_scheduling_decision(
    const struct queue_entry *selected_seed,
    float selected_rarity,
    float selected_coverage
);

/**
 * @brief Get state with minimum coverage (for targeting)
 */
unsigned int get_lowest_coverage_state(
    state_scheduler_t *scheduler
);

/**
 * @brief Export STT to visualization format (GraphViz)
 */
void export_stt_graphviz(
    const state_scheduler_t *scheduler,
    const char *output_file
);

/**
 * @brief Free scheduler
 */
void state_scheduler_cleanup(state_scheduler_t *scheduler);

#endif // __STATE_SCHEDULER_H
