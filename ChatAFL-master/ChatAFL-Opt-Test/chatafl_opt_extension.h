#ifndef __CHATAFL_OPT_EXTENSION_H
#define __CHATAFL_OPT_EXTENSION_H

#include "fuzzer_extension.h"
#include "hypothesis.h"
#include "verifier.h"
#include "cegar.h"
#include "state_scheduler.h"

/* ============================================================================
 * ChatAFL-Opt Extension - Pluggable Implementation
 * ============================================================================
 * 
 * This file implements ChatAFL-Opt as a fuzzer extension that can be
 * registered without modifying afl-fuzz.c.
 * 
 * Module Integration:
 * 1. Hypothesis Module: Generates grammar hypotheses (triggered on plateau)
 * 2. Verifier Module: Validates hypotheses (after execution)
 * 3. CEGAR Module: Refines failed hypotheses (on verification failure)
 * 4. State Scheduler: Tracks state transitions (on new coverage)
 * 5. Integration Layer: Coordinates all modules (before mutation)
 */

/* ChatAFL-Opt private context */
typedef struct {
    /* Module contexts */
    hypothesis_context_t *hypothesis_ctx;
    verification_context_t *verifier_ctx;
    cegar_context_t *cegar_ctx;
    scheduler_context_t *scheduler_ctx;
    
    /* State tracking */
    uint64_t last_coverage_update;     // Last exec count when coverage increased
    uint32_t execs_since_new_coverage; // Execs without new coverage
    uint32_t plateau_threshold;        // Threshold for plateau detection
    
    /* Statistics */
    uint32_t hypotheses_generated;
    uint32_t verifications_performed;
    uint32_t refinements_applied;
    uint32_t state_updates;
    uint32_t llm_assists;
    
    /* Performance monitoring (microseconds) */
    uint64_t time_in_verification_us;
    uint64_t time_in_cegar_us;
    uint64_t time_in_scheduler_us;
    uint64_t time_in_hypothesis_us;
    
    /* Configuration */
    bool enable_hypothesis_generation;
    bool enable_verification;
    bool enable_cegar;
    bool enable_state_scheduling;
    double verification_sampling_rate; // Sample 10% of executions to verify
    
} chatafl_opt_private_t;

/* ============================================================================
 * Extension Registration Function
 * ============================================================================ */

/* Register ChatAFL-Opt extension with the fuzzer */
fuzzer_extension_t* get_chatafl_opt_extension(void);

/* ============================================================================
 * Module-Specific Hook Implementations
 * ============================================================================ */

/* Hypothesis Module: Generate protocol grammar hypotheses */
void chatafl_opt_on_plateau(extension_context_t *ctx,
                            uint32_t execs_without_progress,
                            uint32_t plateau_threshold);

/* Verifier Module: Validate messages after execution */
void chatafl_opt_after_execution(extension_context_t *ctx,
                                uint8_t *trace_bits, uint32_t trace_len,
                                uint8_t fault_type,
                                char *server_response, int response_code);

/* CEGAR Module: Refine hypotheses on verification failure */
void chatafl_opt_on_verification_failure(extension_context_t *ctx,
                                        verification_result_t *vr,
                                        grammar_hypothesis_t *hypothesis);

/* State Scheduler: Update state tree on new coverage */
void chatafl_opt_on_new_coverage(extension_context_t *ctx,
                                uint64_t *new_bits, uint32_t new_bits_count);

/* Integration Layer: Coordinate modules before mutation */
void chatafl_opt_before_mutation(extension_context_t *ctx,
                                uint8_t **in_buf, uint32_t *in_len,
                                uint32_t *mutation_strategy);

/* ============================================================================
 * Lifecycle Callbacks
 * ============================================================================ */

int chatafl_opt_init(extension_context_t *ctx);
void chatafl_opt_cleanup(extension_context_t *ctx);

/* ============================================================================
 * Statistics and Reporting
 * ============================================================================ */

void chatafl_opt_print_stats(extension_context_t *ctx);
void chatafl_opt_export_state(extension_context_t *ctx, const char *out_dir);

#endif /* __CHATAFL_OPT_EXTENSION_H */
