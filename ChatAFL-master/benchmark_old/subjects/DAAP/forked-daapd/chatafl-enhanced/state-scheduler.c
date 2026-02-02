/*
 * state-scheduler.c - State-aware seed scheduling (Stateful Greybox Fuzzing ideas)
 * 
 * Part of ChatAFL-Enhanced: Verified Loop Architecture
 * 
 * Inspired by USENIX'22 "Stateful Greybox Fuzzing", this module:
 * - Tracks state nodes and transitions in a tree (STT)
 * - Prioritizes rare (low-visitation) states
 * - Detects plateau and triggers LLM for state-targeted message generation
 */

#include "state-scheduler.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define RARITY_THRESHOLD 0.1  // States with rarity < 0.1 are considered rare
#define PLATEAU_CHECK_INTERVAL 100  // Check for plateau every 100 iterations

// Global scheduler context
static state_scheduler_t *g_scheduler = NULL;
static FILE *g_sched_log = NULL;

void state_scheduler_init(
    state_scheduler_t *scheduler,
    int plateau_threshold) {
    
    if (!scheduler) return;
    
    scheduler->stt = (state_transition_tree_t *)ck_alloc(sizeof(state_transition_tree_t));
    memset(scheduler->stt, 0, sizeof(state_transition_tree_t));
    scheduler->stt->nodes = (state_node_t *)ck_alloc(4096 * sizeof(state_node_t));
    memset(scheduler->stt->nodes, 0, 4096 * sizeof(state_node_t));
    scheduler->stt->node_count = 0;
    scheduler->stt->transitions = (state_transition_t *)ck_alloc(4096 * 4 * sizeof(state_transition_t));
    memset(scheduler->stt->transitions, 0, 4096 * 4 * sizeof(state_transition_t));
    scheduler->stt->transition_count = 0;
    
    scheduler->state_stats = (state_stats_t *)ck_alloc(4096 * sizeof(state_stats_t));
    memset(scheduler->state_stats, 0, 4096 * sizeof(state_stats_t));
    scheduler->state_stats_count = 0;
    
    scheduler->rare_transitions = (rare_transition_t *)ck_alloc(8192 * sizeof(rare_transition_t));
    memset(scheduler->rare_transitions, 0, 8192 * sizeof(rare_transition_t));
    scheduler->rare_transition_count = 0;
    
    scheduler->plateau_counter = 0;
    scheduler->plateau_threshold = plateau_threshold ? plateau_threshold : 50;
    scheduler->last_coverage = 0.0f;
    
    g_scheduler = scheduler;
    
    // Open logging
    g_sched_log = fopen(".sched_log", "a");
    if (g_sched_log) {
        fprintf(g_sched_log, "[SCHEDULER] Initialized with plateau_threshold=%d\n", 
                scheduler->plateau_threshold);
        fflush(g_sched_log);
    }
    
    fprintf(stderr, "[SCHEDULER] Initialized (max %d states, %d transitions)\n", 4096, 8192);
}

/**
 * Compute rarity: 1.0 / (1 + visitation_count)
 * Higher rarity = more desirable to schedule
 */
float compute_state_rarity(
    const state_transition_tree_t *stt,
    unsigned int state_id) {
    
    if (!stt) return 0.0f;
    
    for (int i = 0; i < stt->node_count; i++) {
        if (stt->nodes[i].state_id == state_id) {
            int visits = stt->nodes[i].visitation_count;
            float rarity = 1.0f / (1.0f + visits);
            return rarity;
        }
    }
    
    // Unknown state = maximum rarity
    return 1.0f;
}

/**
 * Recompute rarity statistics for all states
 */
void update_state_rarity(
    state_scheduler_t *scheduler) {
    
    if (!scheduler || !scheduler->stt) return;
    
    scheduler->state_stats_count = 0;
    
    for (int i = 0; i < scheduler->stt->node_count; i++) {
        state_node_t *node = &scheduler->stt->nodes[i];
        
        if (scheduler->state_stats_count >= 4096) break;
        
        state_stats_t *stat = &scheduler->state_stats[scheduler->state_stats_count];
        stat->state_id = node->state_id;
        stat->rarity = compute_state_rarity(scheduler->stt, node->state_id);
        stat->coverage = node->coverage;
        
        // Count incoming/outgoing transitions
        int incoming = 0, outgoing = 0;
        for (int j = 0; j < scheduler->stt->transition_count; j++) {
            if (scheduler->stt->transitions[j].to_state == node->state_id) incoming++;
            if (scheduler->stt->transitions[j].from_state == node->state_id) outgoing++;
        }
        stat->incoming_transition_count = incoming;
        stat->outgoing_transition_count = outgoing;
        
        scheduler->state_stats_count++;
    }
}

/**
 * Identify rare transitions (transitions with low frequency)
 */
void identify_rare_transitions(
    state_scheduler_t *scheduler,
    float rarity_threshold) {
    
    if (!scheduler || !scheduler->stt) return;
    
    scheduler->rare_transition_count = 0;
    
    for (int i = 0; i < scheduler->stt->transition_count; i++) {
        state_transition_t *trans = &scheduler->stt->transitions[i];
        
        float trans_rarity = 1.0f / (1.0f + trans->frequency);
        if (trans_rarity >= rarity_threshold) {
            if (scheduler->rare_transition_count >= 8192) break;
            
            rare_transition_t *rare = &scheduler->rare_transitions[scheduler->rare_transition_count];
            rare->state_a = trans->from_state;
            rare->state_b = trans->to_state;
            rare->triggering_message = trans->message_type;
            rare->frequency = trans->transition_count;
            rare->coverage_delta = trans->coverage_gain;
            rare->is_rare = 1;
            
            scheduler->rare_transition_count++;
        }
    }
}

/**
 * Select next seed using state rarity + coverage feedback
 * 
 * Scheduling algorithm:
 *   score(seed) = rarity_weight * rarity(state) + (1-rarity_weight) * coverage_gain
 * 
 * Seed with highest score is selected next
 */
struct queue_entry *select_seed_by_state_rarity(
    state_scheduler_t *scheduler,
    struct queue_entry *queue_head,
    float rarity_weight) {
    
    if (!scheduler || !queue_head) return NULL;
    if (rarity_weight < 0.0f || rarity_weight > 1.0f) rarity_weight = 0.5f;
    
    struct queue_entry *best_seed = NULL;
    float best_score = -1.0f;
    int evaluated_count = 0;
    
    /* 论文Algorithm 1: Stateful Seed Selection */
    /* 遍历队列，计算每个seed的state-aware score */
    for (struct queue_entry *q = queue_head; q != NULL; q = q->next) {
        /* 跳过没有region的seed（无效种子）*/
        if (q->region_count == 0) continue;
        
        evaluated_count++;
        
        /* 1. 计算状态稀有度：基于该seed生成的最终状态 */
        float rarity = 1.0f;  // Default maximum rarity for unknown states
        
        /* 如果该seed有generating_state_id（AFLNet扩展字段）*/
        if (q->generating_state_id > 0) {
            rarity = compute_state_rarity(scheduler->stt, q->generating_state_id);
        }
        /* 否则使用unique_state_count作为状态多样性的proxy */
        else if (q->unique_state_count > 0) {
            /* 状态数越少越稀有（反向相关）*/
            rarity = 1.0f / (1.0f + (float)q->unique_state_count);
        }
        
        /* 2. 计算覆盖增益：基于bitmap_size（新边缘数）*/
        float coverage_score = 0.0f;
        if (q->bitmap_size > 0) {
            /* 归一化到[0, 1]范围（假设最大bitmap_size为10000）*/
            coverage_score = (float)q->bitmap_size / 10000.0f;
            if (coverage_score > 1.0f) coverage_score = 1.0f;
        }
        
        /* 3. 综合评分：加权组合 */
        /* score = α * rarity + (1-α) * coverage */
        float score = rarity_weight * rarity + (1.0f - rarity_weight) * coverage_score;
        
        /* 额外加分项：favored seeds、has_new_cov、未完全探索 */
        if (q->favored) score *= 1.2f;  // 20% bonus
        if (q->has_new_cov) score *= 1.1f;  // 10% bonus
        if (!q->was_fuzzed) score *= 1.15f;  // 15% bonus for unexplored
        
        /* 更新最佳seed */
        if (score > best_score) {
            best_score = score;
            best_seed = q;
        }
    }
    
    if (g_sched_log) {
        if (best_seed) {
            fprintf(g_sched_log, 
                    "[STATE-SCHEDULER] Selected seed with score=%.4f (evaluated %d seeds, rarity_weight=%.2f)\n",
                    best_score, evaluated_count, rarity_weight);
        } else {
            fprintf(g_sched_log, "[STATE-SCHEDULER] No valid seed found in queue\n");
        }
        fflush(g_sched_log);
    }
    
    /* 如果没找到有效seed，返回队列头作为fallback */
    return best_seed ? best_seed : queue_head;
}

/**
 * Detect plateau: has coverage stalled?
 */
int detect_coverage_plateau(
    state_scheduler_t *scheduler,
    float current_coverage) {
    
    if (!scheduler) return 0;
    
    // If coverage didn't increase much
    float coverage_delta = current_coverage - scheduler->last_coverage;
    if (coverage_delta < 0.001f) {  // Less than 0.1% improvement
        scheduler->plateau_counter++;
    } else {
        scheduler->plateau_counter = 0;
        scheduler->last_coverage = current_coverage;
    }
    
    if (g_sched_log && scheduler->plateau_counter > 0) {
        fprintf(g_sched_log, "[PLATEAU] counter=%d threshold=%d\n",
                scheduler->plateau_counter, scheduler->plateau_threshold);
        fflush(g_sched_log);
    }
    
    return scheduler->plateau_counter >= scheduler->plateau_threshold ? 1 : 0;
}

void reset_plateau_counter(state_scheduler_t *scheduler) {
    if (!scheduler) return;
    scheduler->plateau_counter = 0;
}

/**
 * Construct prompt asking LLM to reach a specific state
 * Used when plateau detected
 */
char *construct_state_targeting_prompt(
    const char *protocol_name,
    unsigned int target_state_id,
    const state_transition_tree_t *stt,
    json_object *verified_grammars) {
    
    if (!protocol_name) {
        return strdup("Error: invalid protocol name");
    }
    
    char *prompt = (char *)ck_alloc(2048);
    memset(prompt, 0, 2048);
    char *ptr = prompt;
    
    ptr += sprintf(ptr,
        "You are a protocol fuzzing expert for %s.\n\n"
        "The fuzzer has reached a PLATEAU in coverage.\n"
        "Help break the plateau by generating a message SEQUENCE that:\n"
        "  - Reaches state ID 0x%x\n"
        "  - Uses valid %s message templates\n"
        "  - Has not been tried before\n\n",
        protocol_name, target_state_id, protocol_name);
    
    // Add context about available message types
    if (verified_grammars) {
        ptr += sprintf(ptr,
            "Available message types:\n");
        // Would iterate through verified_grammars here
        ptr += sprintf(ptr,
            "  [Use JSON schema from earlier]\n\n");
    }
    
    // Add STT context
    if (stt) {
        ptr += sprintf(ptr,
            "Reachability hint: To reach state 0x%x, consider:\n",
            target_state_id);
        
        // Show paths to target state
        for (int i = 0; i < stt->transition_count && i < 5; i++) {
            if (stt->transitions[i].to_state == target_state_id) {
                ptr += sprintf(ptr,
                    "  - From state 0x%x via message: %s\n",
                    stt->transitions[i].from_state,
                    stt->transitions[i].message_type);
            }
        }
    }
    
    ptr += sprintf(ptr,
        "\nGenerate a sequence of protocol messages in JSON format:\n"
        "[\n"
        "  {\"message_type\": \"...\", \"fields\": {...}},\n"
        "  {\"message_type\": \"...\", \"fields\": {...}}\n"
        "]\n");
    
    return prompt;
}

void log_scheduling_decision(
    const struct queue_entry *selected_seed,
    float selected_rarity,
    float selected_coverage) {
    
    if (!g_sched_log) return;
    
    fprintf(g_sched_log,
            "[DECISION] seed=%p rarity=%.3f coverage=%.3f\n",
            (void *)selected_seed, selected_rarity, selected_coverage);
    fflush(g_sched_log);
}

unsigned int get_lowest_coverage_state(
    state_scheduler_t *scheduler) {
    
    if (!scheduler || !scheduler->stt || scheduler->stt->node_count == 0) {
        return 0;
    }
    
    unsigned int lowest_state = scheduler->stt->nodes[0].state_id;
    float lowest_coverage = scheduler->stt->nodes[0].coverage;
    
    for (int i = 1; i < scheduler->stt->node_count; i++) {
        if (scheduler->stt->nodes[i].coverage < lowest_coverage) {
            lowest_coverage = scheduler->stt->nodes[i].coverage;
            lowest_state = scheduler->stt->nodes[i].state_id;
        }
    }
    
    return lowest_state;
}

/**
 * Export STT to GraphViz format for visualization
 */
void export_stt_graphviz(
    const state_scheduler_t *scheduler,
    const char *output_file) {
    
    if (!scheduler || !output_file) return;
    
    FILE *f = fopen(output_file, "w");
    if (!f) {
        fprintf(stderr, "[SCHEDULER] Failed to write GraphViz file: %s\n", output_file);
        return;
    }
    
    fprintf(f, "digraph STT {\n");
    fprintf(f, "  rankdir=LR;\n");
    fprintf(f, "  node [shape=ellipse];\n\n");
    
    // Draw state nodes
    if (scheduler->stt) {
        for (int i = 0; i < scheduler->stt->node_count; i++) {
            state_node_t *node = &scheduler->stt->nodes[i];
            fprintf(f, "  state_0x%x [label=\"State 0x%x\\nvisits=%d\"];\n",
                   node->state_id, node->state_id, node->visitation_count);
        }
        
        fprintf(f, "\n");
        
        // Draw transitions
        for (int i = 0; i < scheduler->stt->transition_count; i++) {
            state_transition_t *trans = &scheduler->stt->transitions[i];
            fprintf(f, "  state_0x%x -> state_0x%x [label=\"%s\"];\n",
                   trans->from_state, trans->to_state, trans->message_type);
        }
    }
    
    fprintf(f, "}\n");
    fclose(f);
    
    fprintf(stderr, "[SCHEDULER] Exported STT to: %s\n", output_file);
}

void state_scheduler_cleanup(state_scheduler_t *scheduler) {
    if (!scheduler) return;
    
    if (scheduler->stt) {
        // Free message_type strings (allocated with strdup) before freeing transitions array
        if (scheduler->stt->transitions) {
            for (int i = 0; i < scheduler->stt->transition_count; i++) {
                if (scheduler->stt->transitions[i].message_type) {
                    free(scheduler->stt->transitions[i].message_type);  // strdup uses malloc
                }
            }
            ck_free(scheduler->stt->transitions);  // transitions array uses ck_alloc
        }
        
        if (scheduler->stt->nodes) ck_free(scheduler->stt->nodes);  // nodes uses ck_alloc
        ck_free(scheduler->stt);  // stt itself uses ck_alloc
    }
    
    if (scheduler->state_stats) ck_free(scheduler->state_stats);
    if (scheduler->rare_transitions) ck_free(scheduler->rare_transitions);
    
    if (g_sched_log) {
        fclose(g_sched_log);
        g_sched_log = NULL;
    }
}
