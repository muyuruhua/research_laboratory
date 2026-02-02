/*
 * verified-loop.c - Integration of Verifier + CEGAR + State Scheduler
 * 
 * This is the main verified loop that orchestrates the three core modules
 * to form a cohesive system for LLM-guided protocol fuzzing with verification.
 */

#include "verifier.h"
#include "cegar-refinement.h"
#include "state-scheduler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

typedef struct {
    char *protocol_name;
    char *sut_host;
    int sut_port;
    
    verifier_config_t verifier_cfg;
    state_scheduler_t state_sched;
    
    int total_messages_tested;
    int total_verified;
    int total_failures;
    int total_patches;
} verified_loop_t;

/**
 * Main verified loop iteration:
 * 
 * For each LLM-generated message:
 *   1. VERIFY: Check parseability, acceptability, state reachability, coverage gain
 *   2. If all checks pass → Add to verified corpus
 *   3. If any check fails → CEGAR refinement loop
 *      3a. Construct constrained patch prompt
 *      3b. Get LLM to fix specific field
 *      3c. Re-verify patched message
 *      3d. Cache successful patch
 *   4. STATE SCHEDULER: Track state rarity, detect plateau
 *   5. If plateau → Ask LLM to target rare states
 */
int verified_loop_process_message(
    verified_loop_t *ctx,
    const unsigned char *message,
    size_t msg_len,
    json_object *grammar,
    json_object *verified_grammars) {
    
    if (!ctx || !message || msg_len == 0) {
        return -1;
    }
    
    ctx->total_messages_tested++;
    
    fprintf(stderr, "\n[VERIFIED-LOOP] Processing message #%d\n", ctx->total_messages_tested);
    
    // ========== PHASE 1: VERIFICATION ==========
    fprintf(stderr, "[VERIFIED-LOOP] Phase 1: Verification\n");
    
    // Check 1: Parseability
    parsed_fields_t *fields = NULL;
    int parseability = verify_parseability(message, msg_len, grammar, &fields);
    fprintf(stderr, "  ✓ Parseability: %s\n", parseability ? "PASS" : "FAIL");
    
    if (!parseability) {
        fprintf(stderr, "[VERIFIED-LOOP] Message not parseable → CEGAR refinement\n");
        
        // Create counterexample for CEGAR
        cegar_failure_t failure;
        memset(&failure, 0, sizeof(failure));
        failure.original_message = (unsigned char *)calloc(msg_len, 1);
        memcpy(failure.original_message, message, msg_len);
        failure.original_len = msg_len;
        failure.failure_classification = strdup("parse_error");
        failure.parsed_fields = fields;
        
        // Try CEGAR refinement
        cegar_patch_t *patch = iterative_field_refinement(
            &failure, grammar, MAX_FIELDS, ctx->protocol_name);
        
        if (patch) {
            ctx->total_patches++;
            fprintf(stderr, "  ✓ CEGAR: Generated patch for field %d\n", patch->field_idx_patched);
            
            // Would verify patched message here
            free(patch);
        } else {
            ctx->total_failures++;
            fprintf(stderr, "  ✗ CEGAR: All field patches failed\n");
        }
        
        free(failure.original_message);
        free(failure.failure_classification);
        return -1;
    }
    
    // Check 2: Acceptability
    response_t response;
    memset(&response, 0, sizeof(response));
    int acceptability = verify_acceptability(
        ctx->sut_host, ctx->sut_port,
        message, msg_len, &response, 5000);  // 5s timeout
    fprintf(stderr, "  ✓ Acceptability: %s (status=%d)\n",
            acceptability ? "PASS" : "FAIL", response.status_code);
    
    if (!acceptability) {
        fprintf(stderr, "[VERIFIED-LOOP] Message rejected by SUT → CEGAR refinement\n");
        
        cegar_failure_t failure;
        memset(&failure, 0, sizeof(failure));
        failure.original_message = (unsigned char *)calloc(msg_len, 1);
        memcpy(failure.original_message, message, msg_len);
        failure.original_len = msg_len;
        failure.failure_response = response;
        
        char failure_class[64];
        snprintf(failure_class, sizeof(failure_class), "status_%d", response.status_code);
        failure.failure_classification = strdup(failure_class);
        failure.parsed_fields = fields;
        
        cegar_patch_t *patch = iterative_field_refinement(
            &failure, grammar, MAX_FIELDS, ctx->protocol_name);
        
        if (patch) {
            ctx->total_patches++;
            fprintf(stderr, "  ✓ CEGAR: Generated patch\n");
            free(patch);
        } else {
            ctx->total_failures++;
            fprintf(stderr, "  ✗ CEGAR: Patch failed\n");
        }
        
        free(failure.original_message);
        free(failure.failure_classification);
        response_cleanup(&response);  // Clean up response fields
        return -1;
    }
    
    // Check 3 & 4: State reachability + Coverage gain
    // (Would need response codes from server here)
    unsigned int dummy_state_seq[] = {response.status_code};
    int is_new_state = 0;
    int state_reachable = verify_state_reachability(
        dummy_state_seq, 1,
        ctx->verifier_cfg.stt, &is_new_state);
    fprintf(stderr, "  ✓ State Reachability: %s (new=%d)\n",
            state_reachable ? "PASS" : "FAIL", is_new_state);
    
    float coverage_gain = calculate_coverage_gain(ctx->verifier_cfg.stt, &response);
    fprintf(stderr, "  ✓ Coverage Gain: %.3f\n", coverage_gain);
    
    // ========== PHASE 2: ACCEPTANCE & LOGGING ==========
    fprintf(stderr, "[VERIFIED-LOOP] Phase 2: Acceptance\n");
    
    // All checks passed → Add to verified corpus
    if (parseability && acceptability && state_reachable) {
        ctx->total_verified++;
        fprintf(stderr, "  ✓ Message ACCEPTED to verified corpus\n");
        
        // Log verification result
        char msg_hex[128];
        snprintf(msg_hex, sizeof(msg_hex), "%02x%02x%02x...",
                message[0], message[1], message[2]);
        log_verification_result(msg_hex, parseability, acceptability, state_reachable, &response);
        
        // Log CEGAR success (no patching needed)
        cegar_failure_t dummy_failure;
        memset(&dummy_failure, 0, sizeof(dummy_failure));
        dummy_failure.failure_classification = strdup("none");
        log_cegar_attempt(&dummy_failure, NULL, 1);
        free(dummy_failure.failure_classification);
    }
    
    // ========== PHASE 3: STATE SCHEDULING ==========
    fprintf(stderr, "[VERIFIED-LOOP] Phase 3: State Scheduling\n");
    
    update_state_transition_tree(ctx->state_sched.stt, dummy_state_seq, 1, "message");
    update_state_rarity(&ctx->state_sched);
    
    // Check for plateau
    float current_coverage = coverage_gain;  // Simplified; would use actual coverage
    if (detect_coverage_plateau(&ctx->state_sched, current_coverage)) {
        fprintf(stderr, "  ⚠ PLATEAU DETECTED! Triggering state-targeted generation\n");
        
        // Get lowest-coverage state
        unsigned int target_state = get_lowest_coverage_state(&ctx->state_sched);
        
        // Construct prompt for LLM
        char *state_prompt = construct_state_targeting_prompt(
            ctx->protocol_name, target_state,
            ctx->state_sched.stt, verified_grammars);
        
        fprintf(stderr, "  → Asking LLM to reach state 0x%x\n", target_state);
        fprintf(stderr, "  → Prompt: (first 100 chars) %.100s...\n", state_prompt);
        
        // Would call LLM here with state_prompt
        // ...
        
        free(state_prompt);
    }
    
    if (fields) free(fields);
    response_cleanup(&response);  // Clean up response fields
    return 0;
}

/**
 * Initialize verified loop
 */
verified_loop_t *verified_loop_init(
    const char *protocol_name,
    const char *sut_host,
    int sut_port,
    const char *log_dir) {
    
    verified_loop_t *ctx = (verified_loop_t *)calloc(1, sizeof(verified_loop_t));
    ctx->protocol_name = strdup(protocol_name);
    ctx->sut_host = strdup(sut_host);
    ctx->sut_port = sut_port;
    
    // Initialize sub-modules
    char log_path[256];
    
    // Verifier
    snprintf(log_path, sizeof(log_path), "%s/verifier.log", log_dir);
    ctx->verifier_cfg.enable_logging = 1;
    ctx->verifier_cfg.debug_mode = 0;
    ctx->verifier_cfg.log_file = strdup(log_path);
    ctx->verifier_cfg.stt = (state_transition_tree_t *)calloc(1, sizeof(state_transition_tree_t));
    ctx->verifier_cfg.stt->nodes = (state_node_t *)calloc(4096, sizeof(state_node_t));
    verifier_init(&ctx->verifier_cfg);
    
    // State Scheduler
    state_scheduler_init(&ctx->state_sched, 50);
    ctx->state_sched.stt = ctx->verifier_cfg.stt;
    
    // CEGAR
    snprintf(log_path, sizeof(log_path), "%s", log_dir);
    cegar_init(log_path);
    
    fprintf(stderr, "[VERIFIED-LOOP] Initialized for protocol=%s sut=%s:%d\n",
            protocol_name, sut_host, sut_port);
    
    return ctx;
}

void verified_loop_cleanup(verified_loop_t *ctx) {
    if (!ctx) return;
    
    fprintf(stderr, "\n[VERIFIED-LOOP] Summary:\n");
    fprintf(stderr, "  Total messages tested: %d\n", ctx->total_messages_tested);
    fprintf(stderr, "  Messages verified: %d (%.1f%%)\n",
            ctx->total_verified,
            ctx->total_messages_tested > 0 ?
                100.0f * ctx->total_verified / ctx->total_messages_tested : 0.0f);
    fprintf(stderr, "  CEGAR patches applied: %d\n", ctx->total_patches);
    fprintf(stderr, "  Total failures: %d\n", ctx->total_failures);
    
    verifier_cleanup();
    cegar_cleanup();
    state_scheduler_cleanup(&ctx->state_sched);
    
    free(ctx->protocol_name);
    free(ctx->sut_host);
    free(ctx->verifier_cfg.log_file);
    free(ctx->verifier_cfg.stt->nodes);
    free(ctx->verifier_cfg.stt);
    free(ctx);
}

/**
 * Example usage / test
 */
int main(int argc, char *argv[]) {
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "ChatAFL-Enhanced: Verified Loop v0.1\n");
    fprintf(stderr, "========================================\n\n");
    
    // Initialize verified loop
    verified_loop_t *vloop = verified_loop_init(
        "RTSP",        // protocol
        "127.0.0.1",   // SUT host
        554,           // SUT port
        ".vloop_logs"  // log directory
    );
    
    // Create dummy message for testing
    const char *test_message = "DESCRIBE rtsp://example.com/video RTSP/1.0\r\n"
                              "CSeq: 1\r\n"
                              "Content-Length: 0\r\n"
                              "\r\n";
    
    // Create dummy grammar
    json_object *grammar = json_object_new_object();
    json_object_object_add(grammar, "start", json_object_new_string("request"));
    json_object_object_add(grammar, "version", json_object_new_string("RTSP/1.0"));
    
    json_object *verified_grammars = json_object_new_object();
    
    // Process message through verified loop
    fprintf(stderr, "\nProcessing test message...\n");
    verified_loop_process_message(vloop, (const unsigned char *)test_message,
                                 strlen(test_message), grammar, verified_grammars);
    
    // Cleanup
    verified_loop_cleanup(vloop);
    json_object_put(grammar);
    json_object_put(verified_grammars);
    
    fprintf(stderr, "\nVerified loop test complete.\n");
    return 0;
}
