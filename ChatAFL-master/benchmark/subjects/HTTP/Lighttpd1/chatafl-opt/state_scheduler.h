#ifndef __STATE_SCHEDULER_H
#define __STATE_SCHEDULER_H

#include "hypothesis.h"
#include "verifier.h"
#include "cegar.h"
#include "klist.h"
#include "kvec.h"
#include <stdint.h>

/* State-Aware Scheduler Module
 * Implements Stateful Greybox Fuzzing principles (USENIX'22)
 * Key idea: Use State Transition Tree (STT) to guide exploration
 */

// State node in the state transition tree
typedef struct state_node {
    char *state_name;             // e.g., "USER_SENT", "PASS_REQUIRED"
    int visit_count;              // How many times visited
    double coverage_score;        // Normalized coverage contribution
    uint64_t coverage_bitmap[65536]; // Coverage achieved in this state
    struct state_node **children; // Child states
    int child_count;
    int child_capacity;
    char **transition_messages;   // Messages that trigger transitions
    int *transition_counts;       // Frequency of each transition
    time_t last_visited;
    bool is_rare;                 // Rare state flag
    double priority_score;        // Scheduling priority
} state_node_t;

// State transition tree
typedef struct {
    state_node_t *root;
    khash_t(strMap) *state_index;  // Map state_name -> state_node_t*
    int total_states;
    int total_transitions;
    time_t created_at;
} state_transition_tree_t;

// Scheduler context
typedef struct {
    state_transition_tree_t *stt;
    cegar_context_t *cegar_ctx;
    char *protocol_name;
    
    // Scheduling policy parameters
    double rare_state_boost;       // Priority multiplier for rare states
    double coverage_weight;        // Weight for coverage score
    double recency_weight;         // Weight for recent visits
    int plateau_threshold;         // Execs without new coverage -> plateau
    int execs_since_new_coverage;
    
    // LLM-guided sequence generation
    bool llm_assist_enabled;
    int llm_trigger_threshold;     // Plateau execs before LLM assist
    
    // Statistics
    int total_executions;
    int state_discoveries;
    int llm_assists;
    double avg_state_coverage;
} scheduler_context_t;

// Initialize scheduler
scheduler_context_t *init_scheduler(const char *protocol_name,
                                   cegar_context_t *cegar_ctx);

// Initialize state transition tree
state_transition_tree_t *init_state_tree(const char *initial_state);

// Add or update state node
state_node_t *add_or_update_state(state_transition_tree_t *stt,
                                 const char *state_name,
                                 uint64_t *coverage);

// Record state transition
void record_transition(state_transition_tree_t *stt,
                      const char *from_state,
                      const char *to_state,
                      const char *message);

// Compute priority scores for all states
void compute_state_priorities(scheduler_context_t *ctx);

// Select next state to explore (core scheduling decision)
state_node_t *select_next_state(scheduler_context_t *ctx);

// Generate message sequence to reach target state
char **generate_sequence_to_state(scheduler_context_t *ctx,
                                 state_node_t *target_state,
                                 int *sequence_length);

// LLM-assisted sequence generation (triggered on plateau)
char **llm_generate_sequence_to_state(scheduler_context_t *ctx,
                                     const char *target_state,
                                     const char *current_state,
                                     int *sequence_length);

// Detect plateau (no new coverage for N executions)
bool is_plateau(scheduler_context_t *ctx);

// Update scheduler state after execution
void update_scheduler(scheduler_context_t *ctx,
                     const char *from_state,
                     const char *to_state,
                     const char *message,
                     uint64_t *new_coverage,
                     bool new_coverage_found);

// Identify rare states (low visit count)
void identify_rare_states(scheduler_context_t *ctx);

// Calculate state diversity score
double calculate_state_diversity(state_transition_tree_t *stt);

// Export STT for visualization/debugging
void export_state_tree(state_transition_tree_t *stt, const char *output_path);

// Free functions
void free_state_node(state_node_t *node);
void free_state_tree(state_transition_tree_t *stt);
void free_scheduler_context(scheduler_context_t *ctx);

// Statistics
void print_scheduler_statistics(scheduler_context_t *ctx);
void print_state_tree(state_transition_tree_t *stt);

// Helper: construct LLM prompt for sequence generation
char *construct_sequence_generation_prompt(const char *protocol_name,
                                          const char *current_state,
                                          const char *target_state,
                                          const char *known_transitions);

// Helper: parse state from execution trace
char *infer_state_from_trace(const char *protocol_name,
                            const char **message_sequence,
                            int sequence_length,
                            const char *final_response);

#endif /* __STATE_SCHEDULER_H */
