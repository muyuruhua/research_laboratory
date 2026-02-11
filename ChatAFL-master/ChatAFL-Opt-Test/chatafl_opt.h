#ifndef __CHATAFL_OPT_H
#define __CHATAFL_OPT_H

#include "hypothesis.h"
#include "verifier.h"
#include "cegar.h"
#include "state_scheduler.h"

/* ChatAFL-Opt Integration Layer
 * Connects Hypothesis → Verifier → CEGAR → Scheduler in a closed loop
 */

// Global context for ChatAFL-Opt
typedef struct {
    hypothesis_context_t *hypothesis_ctx;
    verification_context_t *verifier_ctx;
    cegar_context_t *cegar_ctx;
    scheduler_context_t *scheduler_ctx;
    
    // Data flow tracking
    char *current_state;
    char *previous_state;
    uint64_t current_coverage[65536];
    bool coverage_updated;
    
    // Integration statistics
    int total_hypotheses_generated;
    int total_verifications;
    int total_refinements;
    int total_state_updates;
    
    // Caching for performance
    khash_t(verify_cache) *verification_cache;
    khash_t(refine_cache) *refinement_cache;
    
    // Configuration
    bool enable_verification;
    bool enable_cegar;
    bool enable_state_scheduling;
    
} chatafl_opt_context_t;

// Initialize ChatAFL-Opt system
chatafl_opt_context_t *init_chatafl_opt(const char *protocol_name,
                                       const char *sut_host,
                                       int sut_port,
                                       const char *rfc_context);

// Main integration function: Generate, Verify, Refine, Schedule
// This is called from AFL's fuzzing loop
char *chatafl_opt_generate_message(chatafl_opt_context_t *ctx,
                                   const char *message_type,
                                   const char *current_state);

// Feedback loop: Update system based on execution result
void chatafl_opt_feedback(chatafl_opt_context_t *ctx,
                         const char *message,
                         const char *server_response,
                         uint64_t *new_coverage,
                         bool new_coverage_found);

// Data flow: Hypothesis → Verifier
verification_result_t *dataflow_hypothesis_to_verifier(chatafl_opt_context_t *ctx,
                                                       grammar_hypothesis_t *hypothesis,
                                                       const char *generated_message);

// Data flow: Verifier → CEGAR
grammar_hypothesis_t *dataflow_verifier_to_cegar(chatafl_opt_context_t *ctx,
                                                grammar_hypothesis_t *hypothesis,
                                                verification_result_t *verification);

// Data flow: CEGAR → Scheduler
void dataflow_cegar_to_scheduler(chatafl_opt_context_t *ctx,
                                grammar_hypothesis_t *refined_hypothesis,
                                verification_result_t *final_verification);

// Data flow: Scheduler → Hypothesis (for LLM-guided sequence generation)
char **dataflow_scheduler_to_hypothesis(chatafl_opt_context_t *ctx,
                                       const char *target_state,
                                       int *sequence_length);

// Full pipeline execution: Generate → Verify → Refine → Update
bool execute_full_pipeline(chatafl_opt_context_t *ctx,
                          const char *message_type,
                          char **out_message,
                          verification_result_t **out_verification);

// Verify data flow connectivity
bool verify_dataflow_connectivity(chatafl_opt_context_t *ctx);

// Export system state for debugging/reproducibility
void export_system_state(chatafl_opt_context_t *ctx, const char *output_dir);

// Statistics and monitoring
void print_integration_statistics(chatafl_opt_context_t *ctx);

// Cleanup
void free_chatafl_opt_context(chatafl_opt_context_t *ctx);

#endif /* __CHATAFL_OPT_H */
