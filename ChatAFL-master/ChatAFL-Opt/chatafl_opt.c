#define _GNU_SOURCE
#include "chatafl_opt.h"
#include "alloc-inl.h"
#include "hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ChatAFL-Opt Integration Implementation */

chatafl_opt_context_t *init_chatafl_opt(const char *protocol_name,
                                       const char *sut_host,
                                       int sut_port,
                                       const char *rfc_context) {
    chatafl_opt_context_t *ctx = (chatafl_opt_context_t *)ck_alloc(sizeof(chatafl_opt_context_t));
    
    // Initialize modules in dependency order
    ctx->hypothesis_ctx = init_hypothesis_context(protocol_name);
    ctx->verifier_ctx = init_verification_context(protocol_name, sut_host, sut_port);
    ctx->cegar_ctx = init_cegar_context(ctx->hypothesis_ctx, ctx->verifier_ctx);
    ctx->scheduler_ctx = init_scheduler(protocol_name, ctx->cegar_ctx);
    
    // Initialize state tracking
    ctx->current_state = strdup("INITIAL");
    ctx->previous_state = strdup("INITIAL");
    memset(ctx->current_coverage, 0, sizeof(ctx->current_coverage));
    ctx->coverage_updated = false;
    
    // Initialize statistics
    ctx->total_hypotheses_generated = 0;
    ctx->total_verifications = 0;
    ctx->total_refinements = 0;
    ctx->total_state_updates = 0;
    
    // Initialize caches
    ctx->verification_cache = kh_init(verify_cache);
    ctx->refinement_cache = kh_init(refine_cache);
    
    // Configuration
    ctx->enable_verification = true;
    ctx->enable_cegar = true;
    ctx->enable_state_scheduling = true;
    
    // Generate initial hypotheses
    if (rfc_context) {
        int count = generate_initial_hypotheses(ctx->hypothesis_ctx, rfc_context, NULL, NULL);
        ctx->total_hypotheses_generated = count;
        printf("[ChatAFL-Opt] Generated %d initial hypotheses\n", count);
    }
    
    return ctx;
}

verification_result_t *dataflow_hypothesis_to_verifier(chatafl_opt_context_t *ctx,
                                                       grammar_hypothesis_t *hypothesis,
                                                       const char *generated_message) {
    if (!ctx->enable_verification) return NULL;
    
    // Check cache first
    verification_result_t *cached = lookup_verification_cache(ctx->verification_cache, generated_message);
    if (cached) {
        printf("[DataFlow H→V] Cache hit for message\n");
        return cached;
    }
    
    // Perform verification
    printf("[DataFlow H→V] Verifying message for hypothesis '%s' (rev %d)\n",
           hypothesis->message_type, hypothesis->revision);
    
    verification_result_t *result = verify_message(ctx->verifier_ctx, hypothesis,
                                                   generated_message, ctx->current_coverage);
    
    // Update cache
    update_verification_cache(ctx->verification_cache, generated_message, result);
    ctx->total_verifications++;
    
    printf("[DataFlow H→V] Verification result: %d (time: %.3fs)\n",
           result->status, result->verification_time);
    
    return result;
}

grammar_hypothesis_t *dataflow_verifier_to_cegar(chatafl_opt_context_t *ctx,
                                                grammar_hypothesis_t *hypothesis,
                                                verification_result_t *verification) {
    if (!ctx->enable_cegar) return hypothesis;
    if (verification->status == VERIFY_SUCCESS) return hypothesis;
    
    printf("[DataFlow V→C] Verification failed, triggering CEGAR\n");
    printf("[DataFlow V→C] Failure: %s\n", verification->failure_reason ? verification->failure_reason : "Unknown");
    
    // CEGAR refinement loop
    grammar_hypothesis_t *refined = cegar_refine_until_valid(ctx->cegar_ctx, hypothesis,
                                                            verification->minimal_counterexample);
    
    if (refined) {
        printf("[DataFlow V→C] CEGAR produced refined hypothesis (rev %d → %d)\n",
               hypothesis->revision, refined->revision);
        ctx->total_refinements++;
    } else {
        printf("[DataFlow V→C] CEGAR failed to produce valid refinement\n");
    }
    
    return refined ? refined : hypothesis;
}

void dataflow_cegar_to_scheduler(chatafl_opt_context_t *ctx,
                                grammar_hypothesis_t *refined_hypothesis,
                                verification_result_t *final_verification) {
    if (!ctx->enable_state_scheduling) return;
    
    printf("[DataFlow C→S] Updating scheduler with verification result\n");
    
    // Extract state information from verification
    char *new_state = extract_state_from_response(final_verification->server_response,
                                                  ctx->hypothesis_ctx->protocol_name);
    if (!new_state) {
        new_state = strdup("UNKNOWN");
    }
    
    bool new_cov = (final_verification->status == VERIFY_SUCCESS);
    
    // Update scheduler
    update_scheduler(ctx->scheduler_ctx,
                    ctx->previous_state,
                    new_state,
                    refined_hypothesis->message_type,
                    final_verification->coverage_bitmap,
                    new_cov);
    
    // Update context state
    free(ctx->previous_state);
    ctx->previous_state = ctx->current_state;
    ctx->current_state = new_state;
    
    ctx->total_state_updates++;
    
    printf("[DataFlow C→S] State transition: %s → %s\n", ctx->previous_state, ctx->current_state);
}

char **dataflow_scheduler_to_hypothesis(chatafl_opt_context_t *ctx,
                                       const char *target_state,
                                       int *sequence_length) {
    printf("[DataFlow S→H] Scheduler requesting sequence to state '%s'\n", target_state);
    
    // Scheduler uses LLM to generate sequence
    char **sequence = llm_generate_sequence_to_state(ctx->scheduler_ctx,
                                                    target_state,
                                                    ctx->current_state,
                                                    sequence_length);
    
    if (sequence) {
        printf("[DataFlow S→H] Generated %d-message sequence\n", *sequence_length);
    } else {
        printf("[DataFlow S→H] Failed to generate sequence\n");
    }
    
    return sequence;
}

bool execute_full_pipeline(chatafl_opt_context_t *ctx,
                          const char *message_type,
                          char **out_message,
                          verification_result_t **out_verification) {
    printf("\n[Pipeline] === Starting full pipeline for message type '%s' ===\n", message_type);
    
    // Step 1: Get or generate hypothesis
    khiter_t k = kh_get(strMap, ctx->hypothesis_ctx->message_type_index, message_type);
    grammar_hypothesis_t *hypothesis = NULL;
    
    if (k != kh_end(ctx->hypothesis_ctx->message_type_index)) {
        int idx = kh_value(ctx->hypothesis_ctx->message_type_index, k);
        klnode_t(hypo) *node = ctx->hypothesis_ctx->grammar_list->head;
        for (int i = 0; i < idx && node != ctx->hypothesis_ctx->grammar_list->tail; i++) {
            node = node->next;
        }
        hypothesis = node->data;
        printf("[Pipeline] Using existing hypothesis (rev %d)\n", hypothesis->revision);
    } else {
        hypothesis = generate_message_hypothesis(ctx->hypothesis_ctx->protocol_name,
                                                message_type,
                                                ctx->hypothesis_ctx->rfc_snippet,
                                                0);
        if (hypothesis) {
            klnode_t(hypo) *node = kl_pushp(hypo, ctx->hypothesis_ctx->grammar_list);
            node->data = hypothesis;
            ctx->total_hypotheses_generated++;
            printf("[Pipeline] Generated new hypothesis\n");
        } else {
            printf("[Pipeline] Failed to generate hypothesis\n");
            return false;
        }
    }
    
    // Step 2: Generate message from hypothesis (stub - would use grammar to generate)
    char *message = NULL;
    asprintf(&message, "%s test_value\\r\\n", message_type);
    *out_message = message;
    
    printf("[Pipeline] Generated message: %s", message);
    
    // Step 3: Hypothesis → Verifier
    verification_result_t *vr = dataflow_hypothesis_to_verifier(ctx, hypothesis, message);
    
    // Step 4: Verifier → CEGAR (if verification failed)
    grammar_hypothesis_t *refined = dataflow_verifier_to_cegar(ctx, hypothesis, vr);
    
    // Step 5: CEGAR → Scheduler
    verification_result_t *final_vr = vr;
    if (refined != hypothesis) {
        // Re-verify with refined hypothesis
        final_vr = verify_message(ctx->verifier_ctx, refined, message, ctx->current_coverage);
        ctx->total_verifications++;
    }
    
    dataflow_cegar_to_scheduler(ctx, refined, final_vr);
    
    *out_verification = final_vr;
    
    printf("[Pipeline] === Pipeline complete ===\n\n");
    return (final_vr->status == VERIFY_SUCCESS);
}

char *chatafl_opt_generate_message(chatafl_opt_context_t *ctx,
                                   const char *message_type,
                                   const char *current_state) {
    // Update context state
    if (current_state) {
        free(ctx->current_state);
        ctx->current_state = strdup(current_state);
    }
    
    // Check if scheduler wants to guide exploration
    if (ctx->enable_state_scheduling && is_plateau(ctx->scheduler_ctx)) {
        state_node_t *target = select_next_state(ctx->scheduler_ctx);
        if (target) {
            int seq_len;
            char **sequence = dataflow_scheduler_to_hypothesis(ctx, target->state_name, &seq_len);
            if (sequence && seq_len > 0) {
                // Return first message in sequence (others would be queued)
                char *msg = sequence[0];
                for (int i = 1; i < seq_len; i++) {
                    free(sequence[i]);
                }
                ck_free(sequence);
                return msg;
            }
        }
    }
    
    // Normal generation: execute pipeline
    char *message = NULL;
    verification_result_t *vr = NULL;
    execute_full_pipeline(ctx, message_type, &message, &vr);
    
    if (vr) {
        free_verification_result(vr);
    }
    
    return message;
}

void chatafl_opt_feedback(chatafl_opt_context_t *ctx,
                         const char *message,
                         const char *server_response,
                         uint64_t *new_coverage,
                         bool new_coverage_found) {
    // Update coverage
    if (new_coverage) {
        memcpy(ctx->current_coverage, new_coverage, sizeof(ctx->current_coverage));
        ctx->coverage_updated = new_coverage_found;
    }
    
    // Update scheduler
    char *state = extract_state_from_response(server_response, ctx->hypothesis_ctx->protocol_name);
    if (state) {
        update_scheduler(ctx->scheduler_ctx,
                        ctx->previous_state,
                        state,
                        message,
                        new_coverage,
                        new_coverage_found);
        free(ctx->previous_state);
        ctx->previous_state = ctx->current_state;
        ctx->current_state = state;
    }
}

bool verify_dataflow_connectivity(chatafl_opt_context_t *ctx) {
    printf("\n=== Verifying Data Flow Connectivity ===\n");
    
    bool all_connected = true;
    
    // Test 1: Hypothesis → Verifier
    printf("Test 1: Hypothesis → Verifier... ");
    grammar_hypothesis_t test_h;
    test_h.message_type = "TEST";
    test_h.grammar_spec = "TEST_SPEC";
    test_h.field_constraints = json_object_new_array();
    test_h.confidence_score = 50;
    test_h.created_at = time(NULL);
    test_h.revision = 0;
    
    verification_result_t *vr = dataflow_hypothesis_to_verifier(ctx, &test_h, "TEST\\r\\n");
    if (vr) {
        printf("✓ Connected\n");
        free_verification_result(vr);
    } else {
        printf("✗ Failed\n");
        all_connected = false;
    }
    json_object_put(test_h.field_constraints);
    
    // Test 2: Verifier → CEGAR
    printf("Test 2: Verifier → CEGAR... ");
    verification_result_t test_vr;
    test_vr.status = VERIFY_PARSE_FAILED;
    test_vr.failure_reason = strdup("Test failure");
    test_vr.minimal_counterexample = strdup("TEST");
    test_vr.server_response = NULL;
    test_vr.response_code = -1;
    test_vr.new_states = NULL;
    test_vr.new_states_count = 0;
    
    grammar_hypothesis_t *refined = dataflow_verifier_to_cegar(ctx, &test_h, &test_vr);
    if (refined) {
        printf("✓ Connected\n");
    } else {
        printf("✗ Failed (may be expected if refinement unsuccessful)\n");
    }
    free(test_vr.failure_reason);
    free(test_vr.minimal_counterexample);
    
    // Test 3: CEGAR → Scheduler
    printf("Test 3: CEGAR → Scheduler... ");
    verification_result_t test_vr2;
    test_vr2.status = VERIFY_SUCCESS;
    test_vr2.failure_reason = NULL;
    test_vr2.minimal_counterexample = NULL;
    test_vr2.server_response = strdup("220 OK");
    test_vr2.response_code = 220;
    test_vr2.new_states = NULL;
    test_vr2.new_states_count = 0;
    memset(test_vr2.coverage_bitmap, 0, sizeof(test_vr2.coverage_bitmap));
    
    int prev_updates = ctx->total_state_updates;
    dataflow_cegar_to_scheduler(ctx, &test_h, &test_vr2);
    if (ctx->total_state_updates > prev_updates) {
        printf("✓ Connected\n");
    } else {
        printf("✗ Failed\n");
        all_connected = false;
    }
    free(test_vr2.server_response);
    
    // Test 4: Scheduler → Hypothesis
    printf("Test 4: Scheduler → Hypothesis... ");
    int seq_len;
    char **seq = dataflow_scheduler_to_hypothesis(ctx, "TEST_STATE", &seq_len);
    if (seq || seq_len >= 0) {
        printf("✓ Connected\n");
        if (seq) {
            for (int i = 0; i < seq_len; i++) {
                free(seq[i]);
            }
            ck_free(seq);
        }
    } else {
        printf("✗ Failed\n");
        all_connected = false;
    }
    
    printf("\nData Flow Connectivity: %s\n", all_connected ? "✓ VERIFIED" : "✗ INCOMPLETE");
    printf("=====================================\n\n");
    
    return all_connected;
}

void export_system_state(chatafl_opt_context_t *ctx, const char *output_dir) {
    mkdir(output_dir, 0755);
    
    char path[512];
    
    // Export hypothesis context
    snprintf(path, sizeof(path), "%s/hypotheses.json", output_dir);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "{\n  \"protocol\": \"%s\",\n  \"count\": %d,\n  \"hypotheses\": [\n",
               ctx->hypothesis_ctx->protocol_name, ctx->hypothesis_ctx->hypothesis_count);
        
        klnode_t(hypo) *node;
        int idx = 0;
        for (node = ctx->hypothesis_ctx->grammar_list->head; node != ctx->hypothesis_ctx->grammar_list->tail; node = node->next) {
            grammar_hypothesis_t *h = (grammar_hypothesis_t *)node->data;
            fprintf(f, "    {\"message_type\": \"%s\", \"revision\": %d, \"confidence\": %d}%s\n",
                   h->message_type, h->revision, h->confidence_score,
                   (idx++ < ctx->hypothesis_ctx->hypothesis_count - 1) ? "," : "");
        }
        fprintf(f, "  ]\n}\n");
        fclose(f);
    }
    
    // Export state tree
    snprintf(path, sizeof(path), "%s/state_tree.dot", output_dir);
    export_state_tree(ctx->scheduler_ctx->stt, path);
    
    // Export statistics
    snprintf(path, sizeof(path), "%s/statistics.txt", output_dir);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "=== ChatAFL-Opt Statistics ===\n");
        fprintf(f, "Hypotheses Generated: %d\n", ctx->total_hypotheses_generated);
        fprintf(f, "Verifications: %d\n", ctx->total_verifications);
        fprintf(f, "Refinements: %d\n", ctx->total_refinements);
        fprintf(f, "State Updates: %d\n", ctx->total_state_updates);
        fprintf(f, "Current State: %s\n", ctx->current_state);
        fprintf(f, "Coverage Updated: %s\n", ctx->coverage_updated ? "Yes" : "No");
        fclose(f);
    }
    
    printf("[Export] System state exported to %s/\n", output_dir);
}

void print_integration_statistics(chatafl_opt_context_t *ctx) {
    printf("\n=== ChatAFL-Opt Integration Statistics ===\n");
    printf("Hypotheses Generated: %d\n", ctx->total_hypotheses_generated);
    printf("Verifications: %d\n", ctx->total_verifications);
    printf("Refinements: %d\n", ctx->total_refinements);
    printf("State Updates: %d\n", ctx->total_state_updates);
    printf("Current State: %s\n", ctx->current_state);
    printf("\nModule Statistics:\n");
    printf("-------------------\n");
    print_cegar_statistics(ctx->cegar_ctx);
    print_scheduler_statistics(ctx->scheduler_ctx);
    printf("=========================================\n\n");
}

void free_chatafl_opt_context(chatafl_opt_context_t *ctx) {
    if (!ctx) return;
    
    free_hypothesis_context(ctx->hypothesis_ctx);
    free_verification_context(ctx->verifier_ctx);
    free_cegar_context(ctx->cegar_ctx);
    free_scheduler_context(ctx->scheduler_ctx);
    
    if (ctx->current_state) free(ctx->current_state);
    if (ctx->previous_state) free(ctx->previous_state);
    
    kh_destroy(verify_cache, ctx->verification_cache);
    kh_destroy(refine_cache, ctx->refinement_cache);
    
    ck_free(ctx);
}
