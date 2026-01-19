#ifndef __CEGAR_REFINEMENT_H
#define __CEGAR_REFINEMENT_H

#include "verifier.h"
#include <json-c/json.h>

/*
 * CEGAR Refinement Loop: Counterexample-Guided Abstraction Refinement
 * 
 * When verification fails, feed the failure back to LLM with constraints:
 * "Only patch field X" or "Only modify production rule Y"
 * 
 * This reduces hallucination and ensures focused, reproducible refinement.
 */

typedef struct {
    unsigned char *original_message;
    size_t original_len;
    int failed_field_idx;          // which field caused the failure (-1 = unknown)
    parsed_fields_t *parsed_fields; // parsed field structure for refinement
    response_t failure_response;
    char *failure_classification;  // "parse_error", "400_bad_request", "missing_field", etc.
    int retry_count;
    time_t timestamp;
} cegar_failure_t;

typedef struct {
    json_object *patched_grammar;  // modified grammar rule
    int field_idx_patched;         // which field was modified
    char *patch_description;       // human-readable patch (for logging)
    int patch_confidence;          // LLM confidence (1-5 scale)
} cegar_patch_t;

typedef struct {
    cegar_failure_t *failures;
    int failure_count;
    cegar_patch_t *successful_patches;
    int patch_count;
    char *cache_file;              // for reproducibility: cache/{hash(counterexample)}
} cegar_context_t;

/* ============ CEGAR Functions ============ */

/**
 * @brief Initialize CEGAR context
 */
void cegar_init(const char *cache_dir);

/**
 * @brief Construct a constrained prompt for LLM
 * Limits LLM to patching specific field or production rule
 * 
 * @param protocol_name  e.g., "RTSP", "FTP", "MQTT"
 * @param counterexample  the failed message + response
 * @param fields         parsed fields from original message
 * @param field_to_fix   only allow patching this field (-1 = auto-detect)
 * @param prev_grammar   the grammar that failed (for context)
 * 
 * @return Prompt string (caller must free)
 */
char *construct_cegar_prompt(
    const char *protocol_name,
    const cegar_failure_t *counterexample,
    const parsed_fields_t *fields,
    int field_to_fix,
    json_object *prev_grammar
);

/**
 * @brief Parse LLM's response into a structured patch
 * Expects JSON or structured format from LLM
 * 
 * @param llm_response       raw LLM output
 * @param unused_param       unused parameter for backward compatibility
 * @return Allocated patch structure or NULL on parse error
 */
cegar_patch_t *parse_cegar_patch(
    const char *llm_response,
    cegar_patch_t **unused_param
);

/**
 * @brief Apply patch to original message and re-verify
 * 
 * @param patch           the grammar patch from LLM
 * @param original_msg    the original failed message
 * @param vctx            verifier context for re-checking
 * @return 1 if patched message now passes verification, 0 otherwise
 */
int apply_and_verify_patch(
    const cegar_patch_t *patch,
    const unsigned char *original_msg,
    size_t msg_len,
    verifier_config_t *vctx
);

/**
 * @brief Cache CEGAR result for reproducibility
 * Stores: hash(counterexample) → successful patch
 * 
 * @param cache_key      e.g., hash of failing message
 * @param patch          successful patch to cache
 * @return 0 on success
 */
int cache_cegar_patch(
    const char *cache_key,
    const cegar_patch_t *patch
);

/**
 * @brief Lookup cached patch
 * @return patch if found, NULL otherwise
 */
cegar_patch_t *lookup_cached_patch(const char *cache_key);

/**
 * @brief Try field-by-field refinement
 * If LLM can't patch field X, try field X+1, etc.
 * 
 * @param counterexample  the failure
 * @param prev_grammar    the original grammar
 * @param max_tries       max fields to try
 * @return successful patch, or NULL if all fields fail
 */
cegar_patch_t *iterative_field_refinement(
    const cegar_failure_t *counterexample,
    json_object *prev_grammar,
    int max_tries,
    const char *protocol_name
);

/**
 * @brief Log CEGAR action for debugging
 */
void log_cegar_attempt(
    const cegar_failure_t *failure,
    const cegar_patch_t *patch,
    int success
);

/**
 * @brief Cache CEGAR result for reproducibility
 * Stores: hash(counterexample) → successful patch
 */
void cache_cegar_result(
    cegar_failure_t *counterexample,
    cegar_patch_t *successful_patch
);

/**
 * @brief Lookup cached CEGAR result
 * @return cached patch if found, NULL if not cached
 */
cegar_patch_t *lookup_cached_cegar_result(
    cegar_failure_t *counterexample
);

/**
 * @brief Free CEGAR patch structure
 */
void free_cegar_patch(cegar_patch_t *patch);

/**
 * @brief Free CEGAR structures
 */
void cegar_cleanup(void);

#endif // __CEGAR_REFINEMENT_H
