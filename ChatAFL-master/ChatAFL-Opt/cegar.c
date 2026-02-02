#define _GNU_SOURCE
#include "cegar.h"
#include "chat-llm.h"
#include "alloc-inl.h"
#include "hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* CEGAR Implementation */

cegar_context_t *init_cegar_context(hypothesis_context_t *hypo_ctx,
                                   verification_context_t *verify_ctx) {
    cegar_context_t *ctx = (cegar_context_t *)ck_alloc(sizeof(cegar_context_t));
    ctx->hypo_ctx = hypo_ctx;
    ctx->verify_ctx = verify_ctx;
    ctx->refinement_history = kl_init(hypo);
    ctx->refinement_count = kh_init(strMap);
    ctx->max_refinement_attempts = 5; // Prevent infinite loops
    ctx->success_rate = 0.0;
    return ctx;
}

refinement_directive_t *analyze_counterexample(verification_result_t *vr,
                                              grammar_hypothesis_t *hypothesis) {
    if (!vr || !hypothesis) return NULL;
    
    refinement_directive_t *directive = (refinement_directive_t *)ck_alloc(sizeof(refinement_directive_t));
    
    // Determine refinement strategy based on failure type
    switch (vr->status) {
        case VERIFY_PARSE_FAILED:
            directive->strategy = REFINE_FIELD_PATTERN;
            directive->constraint_type = strdup("pattern");
            directive->evidence = strdup(vr->failure_reason ? vr->failure_reason : "Parse failure");
            // Extract which field failed from failure_reason
            if (vr->failure_reason && strstr(vr->failure_reason, "Field '")) {
                const char *start = strstr(vr->failure_reason, "Field '") + 7;
                const char *end = strchr(start, '\'');
                if (end) {
                    directive->target_field = strndup(start, end - start);
                } else {
                    directive->target_field = strdup("UNKNOWN");
                }
            } else {
                directive->target_field = strdup("UNKNOWN");
            }
            break;
            
        case VERIFY_ACCEPT_FAILED:
            directive->strategy = REFINE_FIELD_VALUE;
            directive->constraint_type = strdup("value_range");
            if (vr->response_code >= 400) {
                asprintf(&directive->evidence, "Server rejected with code %d: %s",
                        vr->response_code, vr->server_response ? vr->server_response : "");
            } else {
                directive->evidence = strdup("Server did not accept message");
            }
            directive->target_field = strdup("ALL"); // May need to refine multiple fields
            break;
            
        case VERIFY_STATE_FAILED:
            directive->strategy = REFINE_DEPENDENCY;
            directive->constraint_type = strdup("state_dependency");
            directive->evidence = strdup("No new state reached");
            directive->target_field = strdup("sequence");
            break;
            
        case VERIFY_COVERAGE_FAILED:
            directive->strategy = REFINE_STRUCTURE;
            directive->constraint_type = strdup("message_structure");
            directive->evidence = strdup("No coverage gain");
            directive->target_field = strdup("STRUCTURE");
            break;
            
        default:
            directive->strategy = REFINE_FIELD_VALUE;
            directive->constraint_type = strdup("generic");
            directive->evidence = strdup("Unknown failure");
            directive->target_field = strdup("UNKNOWN");
    }
    
    directive->max_changes = 1; // Constrain to single change
    return directive;
}

char *construct_constrained_refinement_prompt(grammar_hypothesis_t *hypothesis,
                                             refinement_directive_t *directive,
                                             const char *counterexample,
                                             const char *minimal_diff) {
    char *prompt = NULL;
    
    const char *strategy_desc = "";
    switch (directive->strategy) {
        case REFINE_FIELD_VALUE:
            strategy_desc = "Adjust the value constraints (min/max/enum) for field";
            break;
        case REFINE_FIELD_LENGTH:
            strategy_desc = "Adjust the length constraints (min_length/max_length) for field";
            break;
        case REFINE_FIELD_PATTERN:
            strategy_desc = "Fix the regex pattern for field";
            break;
        case REFINE_DELIMITER:
            strategy_desc = "Fix message delimiters or terminators";
            break;
        case REFINE_HEADER:
            strategy_desc = "Add or modify header field";
            break;
        default:
            strategy_desc = "Make minimal adjustment to field";
    }
    
    asprintf(&prompt,
        "[{\"role\": \"system\", \"content\": \"You are a precision grammar refinement expert. Make EXACTLY ONE minimal change.\"}, "
        "{\"role\": \"user\", \"content\": \"Grammar (revision %d):\\n```json\\n%s\\n```\\n\\n"
        "FAILED Test Case:\\n%s\\n\\n"
        "Failure Evidence:\\n%s\\n\\n"
        "Minimal Diff:\\n%s\\n\\n"
        "STRICT CONSTRAINT: %s '%s' ONLY. Change nothing else.\\n"
        "Provide ONLY the updated field definition in JSON format.\\n\\n"
        "Example response:\\n```json\\n{\\\"name\\\": \\\"%s\\\", \\\"pattern\\\": \\\"new_pattern\\\", ...}\\n```\"}]",
        hypothesis->revision,
        hypothesis->grammar_spec,
        counterexample ? counterexample : "Not provided",
        directive->evidence,
        minimal_diff ? minimal_diff : "Not computed",
        strategy_desc,
        directive->target_field,
        directive->target_field);
    
    return prompt;
}

grammar_hypothesis_t *apply_refinement(cegar_context_t *ctx,
                                      grammar_hypothesis_t *old_hypothesis,
                                      refinement_directive_t *directive,
                                      verification_result_t *counterexample) {
    char *minimal = counterexample->minimal_counterexample;
    if (!minimal && counterexample->server_response) {
        minimal = counterexample->server_response;
    }
    
    char *prompt = construct_constrained_refinement_prompt(old_hypothesis, directive,
                                                          minimal, NULL);
    
    // Use very low temperature for deterministic refinement
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 2, 0.1);
    free(prompt);
    
    if (!response) return NULL;
    
    // Parse response and update field in hypothesis
    json_object *jobj = json_tokener_parse(response);
    free(response);
    
    if (!jobj) return NULL;
    
    // Create refined hypothesis (deep copy old + apply changes)
    grammar_hypothesis_t *refined = (grammar_hypothesis_t *)ck_alloc(sizeof(grammar_hypothesis_t));
    refined->message_type = strdup(old_hypothesis->message_type);
    refined->grammar_spec = strdup(old_hypothesis->grammar_spec); // Will update below
    refined->field_constraints = json_object_get(old_hypothesis->field_constraints);
    refined->confidence_score = old_hypothesis->confidence_score;
    refined->created_at = time(NULL);
    refined->revision = old_hypothesis->revision + 1;
    
    // Update specific field from LLM response
    json_object *name_obj;
    if (json_object_object_get_ex(jobj, "name", &name_obj)) {
        const char *field_name = json_object_get_string(name_obj);
        
        // Find and update field in field_constraints
        if (json_object_is_type(refined->field_constraints, json_type_array)) {
            int len = json_object_array_length(refined->field_constraints);
            for (int i = 0; i < len; i++) {
                json_object *field = json_object_array_get_idx(refined->field_constraints, i);
                json_object *fn_obj;
                if (json_object_object_get_ex(field, "name", &fn_obj)) {
                    if (strcmp(json_object_get_string(fn_obj), field_name) == 0) {
                        // Replace this field with new definition
                        json_object_array_put_idx(refined->field_constraints, i, jobj);
                        break;
                    }
                }
            }
        }
    }
    
    // Update grammar_spec string representation (simplified)
    free(refined->grammar_spec);
    refined->grammar_spec = json_object_to_json_string_ext(refined->field_constraints,
                                                           JSON_C_TO_STRING_PRETTY);
    refined->grammar_spec = strdup(refined->grammar_spec);
    
    return refined;
}

grammar_hypothesis_t *cegar_refine_until_valid(cegar_context_t *ctx,
                                               grammar_hypothesis_t *initial_hypothesis,
                                               const char *test_message) {
    grammar_hypothesis_t *current = initial_hypothesis;
    int attempts = 0;
    
    while (attempts < ctx->max_refinement_attempts) {
        // Verify current hypothesis
        verification_result_t *vr = verify_message(ctx->verify_ctx, current,
                                                   test_message, NULL);
        
        if (vr->status == VERIFY_SUCCESS) {
            free_verification_result(vr);
            return current; // Success!
        }
        
        // Analyze failure and create refinement directive
        refinement_directive_t *directive = analyze_counterexample(vr, current);
        
        // Check for duplicate refinement
        if (is_duplicate_refinement(ctx, current, directive)) {
            free_refinement_directive(directive);
            free_verification_result(vr);
            return NULL; // Stuck in loop
        }
        
        // Check cost control
        if (!should_continue_refinement(ctx, current->message_type, attempts)) {
            free_refinement_directive(directive);
            free_verification_result(vr);
            return NULL; // Cost limit exceeded
        }
        
        // Apply refinement
        grammar_hypothesis_t *refined = apply_refinement(ctx, current, directive, vr);
        
        // Log refinement attempt
        refinement_history_t *history = (refinement_history_t *)ck_alloc(sizeof(refinement_history_t));
        history->old_hypothesis = current;
        history->new_hypothesis = refined;
        history->counterexample = vr;
        history->directive = directive;
        history->success = (refined != NULL);
        history->refined_at = time(NULL);
        
        klnode_t(hypo) *node = kl_pushp(hypo, ctx->refinement_history);
        node->data = history;
        
        log_refinement_attempt(ctx, history);
        
        if (!refined) {
            return NULL; // Refinement failed
        }
        
        current = refined;
        attempts++;
    }
    
    return NULL; // Max attempts exceeded
}

bool is_duplicate_refinement(cegar_context_t *ctx,
                            grammar_hypothesis_t *hypothesis,
                            refinement_directive_t *directive) {
    // Check if we've tried this exact refinement before
    klnode_t(hypo) *node;
    for (node = ctx->refinement_history->head; node != ctx->refinement_history->tail; node = node->next) {
        refinement_history_t *hist = (refinement_history_t *)node->data;
        if (hist->old_hypothesis == hypothesis &&
            hist->directive->strategy == directive->strategy &&
            strcmp(hist->directive->target_field, directive->target_field) == 0) {
            return true;
        }
    }
    return false;
}

bool should_continue_refinement(cegar_context_t *ctx,
                               const char *message_type,
                               int current_attempts) {
    // Cost control: limit refinements per message type
    khiter_t k = kh_get(strMap, ctx->refinement_count, message_type);
    int count = 0;
    if (k != kh_end(ctx->refinement_count)) {
        count = kh_value(ctx->refinement_count, k);
    }
    
    // Update count
    if (k == kh_end(ctx->refinement_count)) {
        int ret;
        k = kh_put(strMap, ctx->refinement_count, strdup(message_type), &ret);
    }
    kh_value(ctx->refinement_count, k) = count + 1;
    
    // Allow up to 10 total refinements per message type
    return count < 10;
}

void log_refinement_attempt(cegar_context_t *ctx, refinement_history_t *history) {
    // Log to stdout/file for debugging
    printf("[CEGAR] Refinement attempt: %s rev%d -> rev%d, strategy=%d, success=%d\n",
           history->old_hypothesis->message_type,
           history->old_hypothesis->revision,
           history->new_hypothesis ? history->new_hypothesis->revision : -1,
           history->directive->strategy,
           history->success);
}

void print_cegar_statistics(cegar_context_t *ctx) {
    printf("\n=== CEGAR Statistics ===\n");
    printf("Total refinements: %lu\n", ctx->refinement_history->size);
    
    int successes = 0;
    klnode_t(hypo) *node;
    for (node = ctx->refinement_history->head; node != ctx->refinement_history->tail; node = node->next) {
        refinement_history_t *hist = (refinement_history_t *)node->data;
        if (hist->success) successes++;
    }
    
    ctx->success_rate = ctx->refinement_history->size > 0 ?
                       (double)successes / (double)ctx->refinement_history->size : 0.0;
    printf("Success rate: %.2f%%\n", ctx->success_rate * 100.0);
    
    printf("Refinements by message type:\n");
    khiter_t k;
    for (k = kh_begin(ctx->refinement_count); k != kh_end(ctx->refinement_count); ++k) {
        if (kh_exist(ctx->refinement_count, k)) {
            printf("  %s: %d\n", kh_key(ctx->refinement_count, k), kh_value(ctx->refinement_count, k));
        }
    }
    printf("========================\n\n");
}

void free_refinement_directive(refinement_directive_t *rd) {
    if (!rd) return;
    if (rd->target_field) free(rd->target_field);
    if (rd->constraint_type) free(rd->constraint_type);
    if (rd->evidence) free(rd->evidence);
    ck_free(rd);
}

void free_refinement_history(refinement_history_t *rh) {
    if (!rh) return;
    // Note: hypotheses are managed by hypothesis_context
    free_verification_result(rh->counterexample);
    free_refinement_directive(rh->directive);
    ck_free(rh);
}

void free_cegar_context(cegar_context_t *ctx) {
    if (!ctx) return;
    
    klnode_t(hypo) *node;
    for (node = ctx->refinement_history->head; node != ctx->refinement_history->tail; node = node->next) {
        free_refinement_history((refinement_history_t *)node->data);
    }
    kl_destroy(hypo, ctx->refinement_history);
    
    khiter_t k;
    for (k = kh_begin(ctx->refinement_count); k != kh_end(ctx->refinement_count); ++k) {
        if (kh_exist(ctx->refinement_count, k)) {
            free((char *)kh_key(ctx->refinement_count, k));
        }
    }
    kh_destroy(strMap, ctx->refinement_count);
    
    ck_free(ctx);
}

char *lookup_refinement_cache(khash_t(refine_cache) *cache, const char *prompt_hash) {
    if (!cache || !prompt_hash) return NULL;
    khiter_t k = kh_get(refine_cache, cache, prompt_hash);
    if (k != kh_end(cache)) {
        return kh_value(cache, k);
    }
    return NULL;
}

void update_refinement_cache(khash_t(refine_cache) *cache,
                            const char *prompt_hash,
                            const char *response) {
    if (!cache || !prompt_hash || !response) return;
    int ret;
    khiter_t k = kh_put(refine_cache, cache, strdup(prompt_hash), &ret);
    kh_value(cache, k) = strdup(response);
}

char *compute_field_diff(const char *expected, const char *actual) {
    // Simple diff implementation
    if (!expected || !actual) return NULL;
    
    char *diff = NULL;
    if (strcmp(expected, actual) == 0) {
        diff = strdup("No difference");
    } else {
        asprintf(&diff, "Expected: %s\nActual: %s", expected, actual);
    }
    return diff;
}
