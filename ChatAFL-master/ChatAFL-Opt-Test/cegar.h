#ifndef __CEGAR_H
#define __CEGAR_H

#include "hypothesis.h"
#include "verifier.h"
#include "klist.h"

/* CEGAR (Counterexample-Guided Abstraction Refinement) Module
 * Implements the feedback loop: hypothesis → verification → refinement
 * Key innovation: Constrained LLM refinement to reduce hallucination
 */

// Refinement strategy
typedef enum {
    REFINE_FIELD_VALUE,     // Adjust field value constraints
    REFINE_FIELD_LENGTH,    // Adjust length constraints
    REFINE_FIELD_TYPE,      // Change field type
    REFINE_FIELD_PATTERN,   // Fix regex pattern
    REFINE_DEPENDENCY,      // Fix field dependencies
    REFINE_DELIMITER,       // Fix message delimiters
    REFINE_HEADER,          // Add/remove header fields
    REFINE_STRUCTURE        // Restructure message format
} refinement_strategy_t;

// Refinement directive (limits LLM freedom)
typedef struct {
    refinement_strategy_t strategy;
    char *target_field;           // Which field to modify
    char *constraint_type;        // What aspect to change
    char *evidence;               // Evidence from counterexample
    int max_changes;              // Limit number of modifications
} refinement_directive_t;

// Refinement history entry
typedef struct {
    grammar_hypothesis_t *old_hypothesis;
    grammar_hypothesis_t *new_hypothesis;
    verification_result_t *counterexample;
    refinement_directive_t *directive;
    bool success;                 // Did refinement pass verification?
    time_t refined_at;
} refinement_history_t;

// Forward declare free function for klist
void free_refinement_history(refinement_history_t *rh);

// KLIST for refinement history
#define __refinement_hist_free(x)
KLIST_INIT(refine_hist, refinement_history_t *, __refinement_hist_free)

// CEGAR context
typedef struct {
    hypothesis_context_t *hypo_ctx;
    verification_context_t *verify_ctx;
    kl_refine_hist_t *refinement_history; // Track all refinements
    khash_t(strMap) *refinement_count; // Count refinements per message type
    int max_refinement_attempts;       // Prevent infinite loops
    double success_rate;               // Track overall success rate
} cegar_context_t;

// Initialize CEGAR context
cegar_context_t *init_cegar_context(hypothesis_context_t *hypo_ctx,
                                   verification_context_t *verify_ctx);

// Main CEGAR loop: verify and refine until success or max attempts
grammar_hypothesis_t *cegar_refine_until_valid(cegar_context_t *ctx,
                                               grammar_hypothesis_t *initial_hypothesis,
                                               const char *test_message);

// Analyze counterexample and determine refinement directive
refinement_directive_t *analyze_counterexample(verification_result_t *vr,
                                              grammar_hypothesis_t *hypothesis);

// Apply refinement directive via constrained LLM prompt
grammar_hypothesis_t *apply_refinement(cegar_context_t *ctx,
                                      grammar_hypothesis_t *old_hypothesis,
                                      refinement_directive_t *directive,
                                      verification_result_t *counterexample);

// Field-level differential analysis
char *compute_field_diff(const char *expected, const char *actual);

// Construct constrained LLM prompt (key anti-hallucination technique)
char *construct_constrained_refinement_prompt(grammar_hypothesis_t *hypothesis,
                                             refinement_directive_t *directive,
                                             const char *counterexample,
                                             const char *minimal_diff);

// Deduplication: check if refinement was already attempted
bool is_duplicate_refinement(cegar_context_t *ctx,
                            grammar_hypothesis_t *hypothesis,
                            refinement_directive_t *directive);

// Cost control: estimate API cost and decide whether to continue
bool should_continue_refinement(cegar_context_t *ctx,
                               const char *message_type,
                               int current_attempts);

// Free functions
void free_refinement_directive(refinement_directive_t *rd);
void free_refinement_history(refinement_history_t *rh);
void free_cegar_context(cegar_context_t *ctx);

// Statistics and logging
void log_refinement_attempt(cegar_context_t *ctx,
                           refinement_history_t *history);

void print_cegar_statistics(cegar_context_t *ctx);

// Cache for LLM responses (prevent duplicate API calls)
KHASH_MAP_INIT_STR(refine_cache, char *)

char *lookup_refinement_cache(khash_t(refine_cache) *cache,
                             const char *prompt_hash);

void update_refinement_cache(khash_t(refine_cache) *cache,
                            const char *prompt_hash,
                            const char *response);

#endif /* __CEGAR_H */
