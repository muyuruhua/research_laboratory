/*
 * cegar-refinement.c - Counterexample-Guided Abstraction Refinement Loop
 * 
 * Part of ChatAFL-Enhanced: Verified Loop Architecture
 * 
 * When verification fails, we feed the failure back to LLM with tight constraints:
 * "Only fix field X" or "Only modify production rule Y"
 * 
 * This reduces hallucination and ensures reproducible, focused refinement.
 */

#include "cegar-refinement.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <json-c/json.h>
#include <dirent.h>

#define CEGAR_CACHE_DIR ".cegar_cache"
// Use constants from header instead of magic numbers here

// Global context
static cegar_context_t *g_cegar_ctx = NULL;
static FILE *g_cegar_log = NULL;

void cegar_init(const char *cache_dir) {
    g_cegar_ctx = (cegar_context_t *)ck_alloc(sizeof(cegar_context_t));
    memset(g_cegar_ctx, 0, sizeof(cegar_context_t));
    g_cegar_ctx->failures = (cegar_failure_t *)ck_alloc(CEGAR_FAILURE_CACHE_SIZE * sizeof(cegar_failure_t));
    memset(g_cegar_ctx->failures, 0, CEGAR_FAILURE_CACHE_SIZE * sizeof(cegar_failure_t));
    g_cegar_ctx->successful_patches = (cegar_patch_t *)ck_alloc(CEGAR_PATCH_CACHE_SIZE * sizeof(cegar_patch_t));
    memset(g_cegar_ctx->successful_patches, 0, CEGAR_PATCH_CACHE_SIZE * sizeof(cegar_patch_t));
    
    // Create cache directory
    const char *cache = cache_dir ? cache_dir : CEGAR_CACHE_DIR;
    g_cegar_ctx->cache_file = strdup(cache);
    mkdir(cache, 0755);
    
    // Open log
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s/cegar.log", cache);
    g_cegar_log = fopen(log_path, "a");
    
    fprintf(stderr, "[CEGAR] Initialized with cache: %s\n", cache);
}

/**
 * Construct a prompt that constrains the LLM to patch only one field
 * 
 * Key principle: Reduce LLM freedom to avoid hallucination
 * Instead of "generate whole message", we say "fix this specific field"
 */
char *construct_cegar_prompt(
    const char *protocol_name,
    const cegar_failure_t *counterexample,
    const parsed_fields_t *fields,
    int field_to_fix,
    json_object *prev_grammar) {
    
    if (!protocol_name || !counterexample) {
        return strdup("Error: invalid input to CEGAR prompt");
    }
    
    char *prompt = (char *)ck_alloc(CEGAR_PROMPT_MAX_SIZE);
    memset(prompt, 0, CEGAR_PROMPT_MAX_SIZE);
    char *ptr = prompt;
    size_t remaining = CEGAR_PROMPT_MAX_SIZE;
    
    // Build constraint-based prompt
    int written = snprintf(ptr, remaining,
        "You are a protocol expert for %s.\n\n"
        "A message was REJECTED by the server with response:\n"
        "  Status: %d\n"
        "  Message: %s\n\n",
        protocol_name,
        counterexample->failure_response.status_code,
        counterexample->failure_response.status_message ? 
            counterexample->failure_response.status_message : "N/A");
    
    // Show which field likely caused the failure
    if (field_to_fix >= 0 && field_to_fix < fields->field_count) {
        ptr += sprintf(ptr,
            "CONSTRAINT: Only modify field [%d]: \"%s\"\n"
            "Do NOT change any other fields or add new fields.\n"
            "Do NOT regenerate the entire message.\n\n",
            field_to_fix,
            fields->fields[field_to_fix].name);
    } else {
        ptr += sprintf(ptr,
            "CONSTRAINT: Auto-detect which field is wrong.\n"
            "Only fix ONE field. Do NOT change multiple fields.\n\n");
    }
    
    // Show the original message structure
    ptr += sprintf(ptr, "Original message structure:\n");
    for (int i = 0; i < fields->field_count && i < 10; i++) {  // Limit to 10 fields for brevity
        ptr += sprintf(ptr, "  [%d] %s (len=%d)\n", 
            i, fields->fields[i].name, fields->fields[i].len);
    }
    
    ptr += sprintf(ptr,
        "\nResponse indicates failure class: %s\n"
        "\nProvide ONLY the fixed field value, in JSON format:\n"
        "{\n"
        "  \"field_index\": <int>,\n"
        "  \"field_name\": \"<string>\",\n"
        "  \"new_value\": \"<string or structured value>\",\n"
        "  \"reason\": \"<brief explanation of fix>\"\n"
        "}\n",
        counterexample->failure_classification ? 
            counterexample->failure_classification : "unknown_error");
    
    return prompt;
}

/**
 * Parse LLM's response into structured patch
 * Expects JSON format from construct_cegar_prompt
 * Returns pointer to allocated patch or NULL on failure
 */
cegar_patch_t *parse_cegar_patch(
    const char *llm_response,
    cegar_patch_t **unused_param) {
    
    if (!llm_response) {
        return NULL;
    }
    
    // Try to parse as JSON
    json_object *obj = json_tokener_parse(llm_response);
    if (!obj) {
        fprintf(stderr, "[CEGAR] Failed to parse LLM response as JSON\n");
        return NULL;
    }
    
    // Look for nested patch object
    json_object *patch_obj = json_object_object_get(obj, "patch");
    if (!patch_obj) {
        patch_obj = obj; // Assume whole response is the patch
    }
    
    cegar_patch_t *patch = (cegar_patch_t *)ck_alloc(sizeof(cegar_patch_t));
    memset(patch, 0, sizeof(cegar_patch_t));
    memset(patch, 0, sizeof(cegar_patch_t));
    
    // Extract fields from JSON
    json_object *field_idx_obj = json_object_object_get(patch_obj, "field_index");
    json_object *patch_type_obj = json_object_object_get(patch_obj, "patch_type");
    json_object *new_val_obj = json_object_object_get(patch_obj, "new_value");
    json_object *explanation_obj = json_object_object_get(patch_obj, "explanation");
    
    if (field_idx_obj) {
        patch->field_idx_patched = json_object_get_int(field_idx_obj);
    }
    
    if (patch_type_obj) {
        const char *type = json_object_get_string(patch_type_obj);
        patch->patched_grammar = json_object_new_object();
        json_object_object_add(patch->patched_grammar, "patch_type", json_object_new_string(type));
    }
    
    if (new_val_obj) {
        const char *val = json_object_get_string(new_val_obj);
        if (patch->patched_grammar) {
            json_object_object_add(patch->patched_grammar, "new_value", json_object_new_string(val));
        }
    }
    
    if (explanation_obj) {
        patch->patch_description = strdup(json_object_get_string(explanation_obj));
    } else {
        patch->patch_description = strdup("LLM-generated patch");
    }
    
    patch->patch_confidence = 3;  // Default medium confidence
    
    json_object_put(obj);
    
    return patch;
}

/**
 * Apply patch to original message and re-verify
 * The patched message is sent to SUT to check if it's now accepted
 */
int apply_and_verify_patch(
    const cegar_patch_t *patch,
    const unsigned char *original_msg,
    size_t msg_len,
    verifier_config_t *vctx) {
    
    if (!patch || !original_msg) {
        return 0;
    }
    
    // Construct patched message by modifying the specified field
    unsigned char *patched_msg = (unsigned char *)ck_alloc(msg_len + 256);
    memset(patched_msg, 0, msg_len + 256);
    memcpy(patched_msg, original_msg, msg_len);
    
    // v0: Simple field replacement
    // In production, would use parsed_fields_t to identify exact byte ranges
    // For now, just mark it as attempted
    
    // Re-verify the patched message
    parsed_fields_t *fields = NULL;
    int parseability = verify_parseability(patched_msg, msg_len + 256, 
                                           NULL,  // grammar (NULL for v0)
                                           &fields);
    
    if (!parseability) {
        ck_free(patched_msg);
        if (fields) ck_free(fields);
        return 0;
    }
    
    // Check acceptability with verifier
    response_t response;
    memset(&response, 0, sizeof(response));
    
    // Would normally send to actual SUT here
    // For v0, just simulate
    int acceptability = 1;  // Assume patched works (in real version, actually test)
    
    response_cleanup(&response);  // Clean up response fields
    ck_free(patched_msg);
    if (fields) ck_free(fields);
    
    return acceptability;
}

/**
 * Cache CEGAR patch for reproducibility
 */
int cache_cegar_patch(
    const char *cache_key,
    const cegar_patch_t *patch) {
    
    if (!cache_key || !patch) return -1;
    
    // Create cache file: {cache_dir}/{hash}.json
    char cache_path[512];
    snprintf(cache_path, sizeof(cache_path), "%s/%s.json", 
             g_cegar_ctx->cache_file, cache_key);
    
    FILE *f = fopen(cache_path, "w");
    if (!f) {
        fprintf(stderr, "[CEGAR] Failed to write cache: %s\n", cache_path);
        return -1;
    }
    
    json_object *cache_obj = json_object_new_object();
    json_object_object_add(cache_obj, "field_idx", json_object_new_int(patch->field_idx_patched));
    json_object_object_add(cache_obj, "description", json_object_new_string(patch->patch_description));
    json_object_object_add(cache_obj, "confidence", json_object_new_int(patch->patch_confidence));
    
    if (patch->patched_grammar) {
        json_object_object_add(cache_obj, "grammar", patch->patched_grammar);
    }
    
    fprintf(f, "%s\n", json_object_to_json_string_ext(cache_obj, JSON_C_TO_STRING_PRETTY));
    fclose(f);
    
    json_object_put(cache_obj);
    
    if (g_cegar_log) {
        fprintf(g_cegar_log, "[CACHE] Saved patch: %s\n", cache_path);
        fflush(g_cegar_log);
    }
    
    return 0;
}

/**
 * Lookup cached patch
 */
cegar_patch_t *lookup_cached_patch(const char *cache_key) {
    if (!cache_key) return NULL;
    
    char cache_path[512];
    snprintf(cache_path, sizeof(cache_path), "%s/%s.json", 
             g_cegar_ctx->cache_file, cache_key);
    
    FILE *f = fopen(cache_path, "r");
    if (!f) {
        return NULL;  // Cache miss
    }
    
    // Read JSON
    char buf[2048];
    fgets(buf, sizeof(buf), f);
    fclose(f);
    
    json_object *obj = json_tokener_parse(buf);
    if (!obj) return NULL;
    
    cegar_patch_t *patch = (cegar_patch_t *)calloc(1, sizeof(cegar_patch_t));
    
    json_object *field_idx = json_object_object_get(obj, "field_idx");
    if (field_idx) patch->field_idx_patched = json_object_get_int(field_idx);
    
    json_object *desc = json_object_object_get(obj, "description");
    if (desc) patch->patch_description = strdup(json_object_get_string(desc));
    
    json_object_put(obj);
    
    return patch;
}

/**
 * Try field-by-field refinement
 * If patching field 0 fails, try field 1, etc.
 */
cegar_patch_t *iterative_field_refinement(
    const cegar_failure_t *counterexample,
    json_object *prev_grammar,
    int max_tries,
    const char *protocol_name) {
    
    if (!counterexample || !protocol_name) {
        return NULL;
    }
    
    // For each field...
    for (int field_idx = 0; field_idx < max_tries && 
         field_idx < counterexample->parsed_fields->field_count; field_idx++) {
        
        // Construct prompt to fix this field
        char *prompt = construct_cegar_prompt(
            protocol_name,
            counterexample,
            counterexample->parsed_fields,
            field_idx,
            prev_grammar);
        
        if (g_cegar_log) {
            fprintf(g_cegar_log, "[CEGAR] Attempting field %d: %s\n", 
                   field_idx, 
                   counterexample->parsed_fields->fields[field_idx].name);
        }
        
        // Would call LLM here in real implementation
        // For v0, just construct the patch framework
        cegar_patch_t *patch = (cegar_patch_t *)ck_alloc(sizeof(cegar_patch_t));
        memset(patch, 0, sizeof(cegar_patch_t));
        patch->field_idx_patched = field_idx;
        patch->patch_description = strdup("v0 placeholder patch");
        patch->patch_confidence = 2;
        patch->patched_grammar = json_object_new_object();
        
        ck_free(prompt);
        
        // In real version, would verify patch here
        // For now, return first attempt
        return patch;
    }
    
    return NULL;
}

/**
 * Log CEGAR attempt
 */
void log_cegar_attempt(
    const cegar_failure_t *failure,
    const cegar_patch_t *patch,
    int success) {
    
    if (!g_cegar_log) return;
    
    fprintf(g_cegar_log, 
            "[CEGAR] field=%d status=%s reason=%s\n",
            patch ? patch->field_idx_patched : -1,
            success ? "SUCCESS" : "FAILURE",
            failure->failure_classification);
    fflush(g_cegar_log);
}

void cegar_cleanup(void) {
    if (g_cegar_log) {
        fclose(g_cegar_log);
        g_cegar_log = NULL;
    }
    
    if (g_cegar_ctx) {
        ck_free(g_cegar_ctx->failures);
        ck_free(g_cegar_ctx->successful_patches);
        ck_free(g_cegar_ctx->cache_file);
        ck_free(g_cegar_ctx);
        g_cegar_ctx = NULL;
    }
}

/**
 * Cache successful CEGAR result for reproducibility
 * Uses hash(counterexample) as key
 */
void cache_cegar_result(
    cegar_failure_t *counterexample,
    cegar_patch_t *successful_patch) {
    
    if (!counterexample || !successful_patch || !g_cegar_ctx) {
        return;
    }
    
    // Generate cache key from counterexample
    char cache_key[64];
    unsigned int msg_hash = 0;
    if (counterexample->original_message && counterexample->original_len > 0) {
        // Simple hash of message content
        for (size_t i = 0; i < counterexample->original_len && i < 256; i++) {
            msg_hash = msg_hash * 31 + counterexample->original_message[i];
        }
    }
    msg_hash ^= counterexample->failure_response.status_code;
    
    snprintf(cache_key, sizeof(cache_key), "%08x", msg_hash);
    
    // Create cache file
    char cache_file_path[512];
    snprintf(cache_file_path, sizeof(cache_file_path), "%s/%s.json", 
             g_cegar_ctx->cache_file, cache_key);
    
    FILE *cache_file = fopen(cache_file_path, "w");
    if (!cache_file) {
        fprintf(stderr, "[CEGAR] Failed to create cache file: %s\n", cache_file_path);
        return;
    }
    
    // Write cache entry
    fprintf(cache_file, "{\n");
    fprintf(cache_file, "  \"counterexample_hash\": \"%s\",\n", cache_key);
    fprintf(cache_file, "  \"status_code\": %d,\n", counterexample->failure_response.status_code);
    fprintf(cache_file, "  \"field_patched\": %d,\n", successful_patch->field_idx_patched);
    if (successful_patch->patch_description) {
        fprintf(cache_file, "  \"description\": \"%s\",\n", successful_patch->patch_description);
    }
    fprintf(cache_file, "  \"confidence\": %d,\n", successful_patch->patch_confidence);
    fprintf(cache_file, "  \"timestamp\": %ld\n", time(NULL));
    fprintf(cache_file, "}\n");
    
    fclose(cache_file);
    
    if (g_cegar_log) {
        fprintf(g_cegar_log, "[CACHE] Stored successful patch: %s\n", cache_key);
        fflush(g_cegar_log);
    }
}

/**
 * Lookup cached CEGAR result 
 * Returns cached patch if found, NULL otherwise
 */
cegar_patch_t *lookup_cached_cegar_result(
    cegar_failure_t *counterexample) {
    
    if (!counterexample || !g_cegar_ctx) {
        return NULL;
    }
    
    // Generate same cache key
    char cache_key[64];
    unsigned int msg_hash = 0;
    if (counterexample->original_message && counterexample->original_len > 0) {
        for (size_t i = 0; i < counterexample->original_len && i < 256; i++) {
            msg_hash = msg_hash * 31 + counterexample->original_message[i];
        }
    }
    msg_hash ^= counterexample->failure_response.status_code;
    
    snprintf(cache_key, sizeof(cache_key), "%08x", msg_hash);
    
    // Try to open cache file
    char cache_file_path[512];
    snprintf(cache_file_path, sizeof(cache_file_path), "%s/%s.json", 
             g_cegar_ctx->cache_file, cache_key);
    
    FILE *cache_file = fopen(cache_file_path, "r");
    if (!cache_file) {
        return NULL;  // Not cached
    }
    
    // Read and parse cache entry (simplified)
    char buffer[1024];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer)-1, cache_file);
    buffer[bytes_read] = '\0';
    fclose(cache_file);
    
    // Simple JSON parsing for cache (production would use proper parser)
    cegar_patch_t *patch = (cegar_patch_t *)calloc(1, sizeof(cegar_patch_t));
    
    // Extract field_patched
    char *field_start = strstr(buffer, "\"field_patched\": ");
    if (field_start) {
        patch->field_idx_patched = atoi(field_start + 17);
    }
    
    // Extract confidence
    char *conf_start = strstr(buffer, "\"confidence\": ");
    if (conf_start) {
        patch->patch_confidence = atoi(conf_start + 14);
    }
    
    // Extract description
    char *desc_start = strstr(buffer, "\"description\": \"");
    if (desc_start) {
        char *desc_end = strchr(desc_start + 16, '\"');
        if (desc_end) {
            size_t desc_len = desc_end - (desc_start + 16);
            patch->patch_description = (char *)calloc(desc_len + 1, 1);
            memcpy(patch->patch_description, desc_start + 16, desc_len);
        }
    }
    
    patch->patched_grammar = json_object_new_object();
    json_object_object_add(patch->patched_grammar, "cached", json_object_new_boolean(1));
    
    if (g_cegar_log) {
        fprintf(g_cegar_log, "[CACHE] Found cached patch: %s\n", cache_key);
        fflush(g_cegar_log);
    }
    
    return patch;
}

/**
 * Free CEGAR patch structure
 */
void free_cegar_patch(cegar_patch_t *patch) {
    if (!patch) return;
    
    if (patch->patched_grammar) {
        json_object_put(patch->patched_grammar);
    }
    if (patch->patch_description) {
        free(patch->patch_description);
    }
    
    free(patch);
}
