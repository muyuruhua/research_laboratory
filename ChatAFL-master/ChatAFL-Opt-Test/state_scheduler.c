#define _GNU_SOURCE
#include "state_scheduler.h"
#include "chat-llm.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* State-Aware Scheduler Implementation */

scheduler_context_t *init_scheduler(const char *protocol_name,
                                   cegar_context_t *cegar_ctx) {
    scheduler_context_t *ctx = (scheduler_context_t *)ck_alloc(sizeof(scheduler_context_t));
    ctx->protocol_name = strdup(protocol_name);
    ctx->cegar_ctx = cegar_ctx;
    ctx->stt = init_state_tree("INITIAL");
    
    // Scheduling policy parameters (tunable)
    ctx->rare_state_boost = 2.0;
    ctx->coverage_weight = 0.6;
    ctx->recency_weight = 0.4;
    ctx->plateau_threshold = 1000;
    ctx->execs_since_new_coverage = 0;
    
    ctx->llm_assist_enabled = true;
    ctx->llm_trigger_threshold = 500;
    
    ctx->total_executions = 0;
    ctx->state_discoveries = 0;
    ctx->llm_assists = 0;
    ctx->avg_state_coverage = 0.0;
    
    return ctx;
}

state_transition_tree_t *init_state_tree(const char *initial_state) {
    state_transition_tree_t *stt = (state_transition_tree_t *)ck_alloc(sizeof(state_transition_tree_t));
    
    stt->root = (state_node_t *)ck_alloc(sizeof(state_node_t));
    stt->root->state_name = strdup(initial_state);
    stt->root->visit_count = 0;
    stt->root->coverage_score = 0.0;
    memset(stt->root->coverage_bitmap, 0, sizeof(stt->root->coverage_bitmap));
    stt->root->children = NULL;
    stt->root->child_count = 0;
    stt->root->child_capacity = 0;
    stt->root->transition_messages = NULL;
    stt->root->transition_counts = NULL;
    stt->root->last_visited = time(NULL);
    stt->root->is_rare = false;
    stt->root->priority_score = 1.0;
    
    stt->state_index = kh_init(strMap);
    int ret;
    khiter_t k = kh_put(strMap, stt->state_index, stt->root->state_name, &ret);
    kh_value(stt->state_index, k) = (intptr_t)stt->root;
    
    stt->total_states = 1;
    stt->total_transitions = 0;
    stt->created_at = time(NULL);
    
    return stt;
}

state_node_t *add_or_update_state(state_transition_tree_t *stt,
                                 const char *state_name,
                                 uint64_t *coverage) {
    khiter_t k = kh_get(strMap, stt->state_index, state_name);
    
    if (k != kh_end(stt->state_index)) {
        // State exists, update it
        state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
        node->visit_count++;
        node->last_visited = time(NULL);
        
        if (coverage) {
            // Merge coverage
            for (int i = 0; i < 65536; i++) {
                node->coverage_bitmap[i] |= coverage[i];
            }
            
            // Recalculate coverage score
            uint64_t bits = 0;
            for (int i = 0; i < 65536; i++) {
                bits += __builtin_popcountll(node->coverage_bitmap[i]);
            }
            node->coverage_score = (double)bits;
        }
        
        return node;
    } else {
        // New state, create it
        state_node_t *node = (state_node_t *)ck_alloc(sizeof(state_node_t));
        node->state_name = strdup(state_name);
        node->visit_count = 1;
        node->coverage_score = 0.0;
        memset(node->coverage_bitmap, 0, sizeof(node->coverage_bitmap));
        
        if (coverage) {
            memcpy(node->coverage_bitmap, coverage, sizeof(node->coverage_bitmap));
            uint64_t bits = 0;
            for (int i = 0; i < 65536; i++) {
                bits += __builtin_popcountll(node->coverage_bitmap[i]);
            }
            node->coverage_score = (double)bits;
        }
        
        node->children = NULL;
        node->child_count = 0;
        node->child_capacity = 0;
        node->transition_messages = NULL;
        node->transition_counts = NULL;
        node->last_visited = time(NULL);
        node->is_rare = true; // New states are rare by default
        node->priority_score = 10.0; // High priority for new states
        
        int ret;
        k = kh_put(strMap, stt->state_index, node->state_name, &ret);
        kh_value(stt->state_index, k) = (intptr_t)node;
        
        stt->total_states++;
        
        return node;
    }
}

void record_transition(state_transition_tree_t *stt,
                      const char *from_state,
                      const char *to_state,
                      const char *message) {
    khiter_t k_from = kh_get(strMap, stt->state_index, from_state);
    khiter_t k_to = kh_get(strMap, stt->state_index, to_state);
    
    if (k_from == kh_end(stt->state_index) || k_to == kh_end(stt->state_index)) {
        return; // States don't exist
    }
    
    state_node_t *from_node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k_from);
    state_node_t *to_node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k_to);
    
    // Check if transition already exists
    bool found = false;
    for (int i = 0; i < from_node->child_count; i++) {
        if (from_node->children[i] == to_node) {
            from_node->transition_counts[i]++;
            found = true;
            break;
        }
    }
    
    if (!found) {
        // Add new transition
        if (from_node->child_count >= from_node->child_capacity) {
            from_node->child_capacity = from_node->child_capacity == 0 ? 4 : from_node->child_capacity * 2;
            from_node->children = (state_node_t **)ck_realloc(from_node->children,
                                                              from_node->child_capacity * sizeof(state_node_t *));
            from_node->transition_messages = (char **)ck_realloc(from_node->transition_messages,
                                                                from_node->child_capacity * sizeof(char *));
            from_node->transition_counts = (int *)ck_realloc(from_node->transition_counts,
                                                            from_node->child_capacity * sizeof(int));
        }
        
        from_node->children[from_node->child_count] = to_node;
        from_node->transition_messages[from_node->child_count] = strdup(message);
        from_node->transition_counts[from_node->child_count] = 1;
        from_node->child_count++;
        
        stt->total_transitions++;
    }
}

void compute_state_priorities(scheduler_context_t *ctx) {
    state_transition_tree_t *stt = ctx->stt;
    time_t now = time(NULL);
    
    // Normalize coverage scores
    double max_coverage = 1.0;
    khiter_t k;
    for (k = kh_begin(stt->state_index); k != kh_end(stt->state_index); ++k) {
        if (kh_exist(stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
            if (node->coverage_score > max_coverage) {
                max_coverage = node->coverage_score;
            }
        }
    }
    
    // Compute priority for each state
    for (k = kh_begin(stt->state_index); k != kh_end(stt->state_index); ++k) {
        if (kh_exist(stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
            
            // Normalized coverage score (higher is better)
            double norm_coverage = max_coverage > 0 ? node->coverage_score / max_coverage : 0.0;
            
            // Recency score (less recent = higher priority)
            double recency = 1.0 / (1.0 + (now - node->last_visited));
            
            // Visit frequency score (less visited = higher priority)
            double freq_score = 1.0 / (1.0 + node->visit_count);
            
            // Combined priority
            node->priority_score = ctx->coverage_weight * norm_coverage +
                                  ctx->recency_weight * recency +
                                  0.5 * freq_score;
            
            // Boost for rare states
            if (node->is_rare) {
                node->priority_score *= ctx->rare_state_boost;
            }
        }
    }
}

state_node_t *select_next_state(scheduler_context_t *ctx) {
    compute_state_priorities(ctx);
    identify_rare_states(ctx);
    
    state_node_t *best = NULL;
    double best_score = -1.0;
    
    khiter_t k;
    for (k = kh_begin(ctx->stt->state_index); k != kh_end(ctx->stt->state_index); ++k) {
        if (kh_exist(ctx->stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(ctx->stt->state_index, k);
            if (node->priority_score > best_score) {
                best_score = node->priority_score;
                best = node;
            }
        }
    }
    
    return best;
}

void identify_rare_states(scheduler_context_t *ctx) {
    // Calculate median visit count
    int *visit_counts = (int *)ck_alloc(ctx->stt->total_states * sizeof(int));
    int idx = 0;
    
    khiter_t k;
    for (k = kh_begin(ctx->stt->state_index); k != kh_end(ctx->stt->state_index); ++k) {
        if (kh_exist(ctx->stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(ctx->stt->state_index, k);
            visit_counts[idx++] = node->visit_count;
        }
    }
    
    // Sort to find median
    for (int i = 0; i < idx - 1; i++) {
        for (int j = i + 1; j < idx; j++) {
            if (visit_counts[i] > visit_counts[j]) {
                int temp = visit_counts[i];
                visit_counts[i] = visit_counts[j];
                visit_counts[j] = temp;
            }
        }
    }
    
    int median = idx > 0 ? visit_counts[idx / 2] : 0;
    ck_free(visit_counts);
    
    // Mark states with visit count below median as rare
    for (k = kh_begin(ctx->stt->state_index); k != kh_end(ctx->stt->state_index); ++k) {
        if (kh_exist(ctx->stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(ctx->stt->state_index, k);
            node->is_rare = (node->visit_count < median);
        }
    }
}

char *construct_sequence_generation_prompt(const char *protocol_name,
                                          const char *current_state,
                                          const char *target_state,
                                          const char *known_transitions) {
    char *prompt = NULL;
    asprintf(&prompt,
        "[{\"role\": \"system\", \"content\": \"You are a protocol state machine expert.\"}, "
        "{\"role\": \"user\", \"content\": \"Protocol: %s\\n\\n"
        "Current State: %s\\nTarget State: %s\\n\\n"
        "Known Transitions:\\n%s\\n\\n"
        "Generate a minimal message sequence to reach the target state from current state.\\n"
        "Response format: JSON array of message strings [\\\"MSG1\\\", \\\"MSG2\\\", ...]\"}]",
        protocol_name, current_state, target_state,
        known_transitions ? known_transitions : "None");
    return prompt;
}

char **llm_generate_sequence_to_state(scheduler_context_t *ctx,
                                     const char *target_state,
                                     const char *current_state,
                                     int *sequence_length) {
    // Build known transitions string
    char *transitions_str = NULL;
    size_t str_size = 0;
    FILE *mem_stream = open_memstream(&transitions_str, &str_size);
    
    khiter_t k;
    for (k = kh_begin(ctx->stt->state_index); k != kh_end(ctx->stt->state_index); ++k) {
        if (kh_exist(ctx->stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(ctx->stt->state_index, k);
            for (int i = 0; i < node->child_count; i++) {
                fprintf(mem_stream, "%s --[%s]--> %s (count: %d)\n",
                       node->state_name,
                       node->transition_messages[i],
                       node->children[i]->state_name,
                       node->transition_counts[i]);
            }
        }
    }
    fclose(mem_stream);
    
    char *prompt = construct_sequence_generation_prompt(ctx->protocol_name,
                                                       current_state,
                                                       target_state,
                                                       transitions_str);
    free(transitions_str);
    
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.5);
    free(prompt);
    
    if (!response) {
        *sequence_length = 0;
        return NULL;
    }
    
    // Parse JSON array
    json_object *jarr = json_tokener_parse(response);
    free(response);
    
    if (!jarr || !json_object_is_type(jarr, json_type_array)) {
        if (jarr) json_object_put(jarr);
        *sequence_length = 0;
        return NULL;
    }
    
    int len = json_object_array_length(jarr);
    char **sequence = (char **)ck_alloc(len * sizeof(char *));
    
    for (int i = 0; i < len; i++) {
        json_object *msg_obj = json_object_array_get_idx(jarr, i);
        sequence[i] = strdup(json_object_get_string(msg_obj));
    }
    
    json_object_put(jarr);
    *sequence_length = len;
    
    ctx->llm_assists++;
    return sequence;
}

char **generate_sequence_to_state(scheduler_context_t *ctx,
                                 state_node_t *target_state,
                                 int *sequence_length) {
    // Simple BFS to find path to target state (non-LLM fallback)
    // For now, just return empty sequence
    *sequence_length = 0;
    return NULL;
}

bool is_plateau(scheduler_context_t *ctx) {
    return ctx->execs_since_new_coverage >= ctx->plateau_threshold;
}

void update_scheduler(scheduler_context_t *ctx,
                     const char *from_state,
                     const char *to_state,
                     const char *message,
                     uint64_t *new_coverage,
                     bool new_coverage_found) {
    ctx->total_executions++;
    
    if (new_coverage_found) {
        ctx->execs_since_new_coverage = 0;
    } else {
        ctx->execs_since_new_coverage++;
    }
    
    // Update state tree
    state_node_t *to_node = add_or_update_state(ctx->stt, to_state, new_coverage);
    if (to_node->visit_count == 1) {
        ctx->state_discoveries++;
    }
    
    record_transition(ctx->stt, from_state, to_state, message);
    
    // Trigger LLM assist on plateau
    if (ctx->llm_assist_enabled && is_plateau(ctx) &&
        ctx->execs_since_new_coverage % ctx->llm_trigger_threshold == 0) {
        
        // Select a rare state to target
        state_node_t *target = select_next_state(ctx);
        if (target) {
            int seq_len;
            char **sequence = llm_generate_sequence_to_state(ctx, target->state_name,
                                                            from_state, &seq_len);
            if (sequence) {
                printf("[SCHEDULER] LLM assist: generated %d-message sequence to reach %s\n",
                       seq_len, target->state_name);
                // These sequences would be added to fuzzing queue
                for (int i = 0; i < seq_len; i++) {
                    free(sequence[i]);
                }
                ck_free(sequence);
            }
        }
    }
}

double calculate_state_diversity(state_transition_tree_t *stt) {
    if (stt->total_states <= 1) return 0.0;
    
    // Shannon entropy of state visit distribution
    double entropy = 0.0;
    int total_visits = 0;
    
    khiter_t k;
    for (k = kh_begin(stt->state_index); k != kh_end(stt->state_index); ++k) {
        if (kh_exist(stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
            total_visits += node->visit_count;
        }
    }
    
    if (total_visits == 0) return 0.0;
    
    for (k = kh_begin(stt->state_index); k != kh_end(stt->state_index); ++k) {
        if (kh_exist(stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
            if (node->visit_count > 0) {
                double p = (double)node->visit_count / (double)total_visits;
                entropy -= p * log2(p);
            }
        }
    }
    
    return entropy;
}

void print_scheduler_statistics(scheduler_context_t *ctx) {
    printf("\n=== Scheduler Statistics ===\n");
    printf("Total executions: %d\n", ctx->total_executions);
    printf("Total states: %d\n", ctx->stt->total_states);
    printf("Total transitions: %d\n", ctx->stt->total_transitions);
    printf("State discoveries: %d\n", ctx->state_discoveries);
    printf("LLM assists: %d\n", ctx->llm_assists);
    printf("State diversity (entropy): %.2f\n", calculate_state_diversity(ctx->stt));
    printf("Execs since new coverage: %d\n", ctx->execs_since_new_coverage);
    printf("============================\n\n");
}

void print_state_tree(state_transition_tree_t *stt) {
    printf("\n=== State Transition Tree ===\n");
    khiter_t k;
    for (k = kh_begin(stt->state_index); k != kh_end(stt->state_index); ++k) {
        if (kh_exist(stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
            printf("State: %s (visits=%d, coverage=%.0f, rare=%d, priority=%.2f)\n",
                   node->state_name, node->visit_count, node->coverage_score,
                   node->is_rare, node->priority_score);
            for (int i = 0; i < node->child_count; i++) {
                printf("  --> %s [%s] (count=%d)\n",
                       node->children[i]->state_name,
                       node->transition_messages[i],
                       node->transition_counts[i]);
            }
        }
    }
    printf("==============================\n\n");
}

void export_state_tree(state_transition_tree_t *stt, const char *output_path) {
    FILE *f = fopen(output_path, "w");
    if (!f) return;
    
    fprintf(f, "digraph StateTree {\n");
    khiter_t k;
    for (k = kh_begin(stt->state_index); k != kh_end(stt->state_index); ++k) {
        if (kh_exist(stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
            fprintf(f, "  \"%s\" [label=\"%s\\nvisits=%d\"];\n",
                   node->state_name, node->state_name, node->visit_count);
            for (int i = 0; i < node->child_count; i++) {
                fprintf(f, "  \"%s\" -> \"%s\" [label=\"%s\"];\n",
                       node->state_name, node->children[i]->state_name,
                       node->transition_messages[i]);
            }
        }
    }
    fprintf(f, "}\n");
    fclose(f);
}

char *infer_state_from_trace(const char *protocol_name,
                            const char **message_sequence,
                            int sequence_length,
                            const char *final_response) {
    // Stub: would analyze trace and infer state
    return strdup("UNKNOWN");
}

void free_state_node(state_node_t *node) {
    if (!node) return;
    if (node->state_name) free(node->state_name);
    if (node->children) ck_free(node->children);
    if (node->transition_messages) {
        for (int i = 0; i < node->child_count; i++) {
            free(node->transition_messages[i]);
        }
        ck_free(node->transition_messages);
    }
    if (node->transition_counts) ck_free(node->transition_counts);
    ck_free(node);
}

void free_state_tree(state_transition_tree_t *stt) {
    if (!stt) return;
    
    khiter_t k;
    for (k = kh_begin(stt->state_index); k != kh_end(stt->state_index); ++k) {
        if (kh_exist(stt->state_index, k)) {
            state_node_t *node = (state_node_t *)(intptr_t)kh_value(stt->state_index, k);
            free_state_node(node);
        }
    }
    kh_destroy(strMap, stt->state_index);
    ck_free(stt);
}

void free_scheduler_context(scheduler_context_t *ctx) {
    if (!ctx) return;
    if (ctx->protocol_name) free(ctx->protocol_name);
    free_state_tree(ctx->stt);
    ck_free(ctx);
}
