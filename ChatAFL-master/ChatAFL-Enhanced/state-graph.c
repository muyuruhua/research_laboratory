/*
 * state-graph.c - 状态转移图实现
 * 
 * 基于USENIX Security '22 "Stateful Greybox Fuzzing"论文
 * 实现完整的状态转移树(STT)和多因子状态价值评估算法
 */

#include "state-graph.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// Safety limits to prevent memory exhaustion
#define MAX_SEEDS_PER_STATE 1024  // Limit seeds per state to prevent DoS

/**
 * @brief 初始化状态转移图
 */
void state_graph_init(StateGraph *graph) {
    if (!graph) return;
    
    memset(graph, 0, sizeof(StateGraph));
    graph->start_time = time(NULL);
    
    // 初始化所有节点
    for (uint32_t i = 0; i < MAX_GRAPH_STATES; i++) {
        graph->nodes[i].state_id = 0;
        graph->nodes[i].visit_count = 0;
        graph->nodes[i].out_degree = 0;
        graph->nodes[i].first_discovered = 0;
        graph->nodes[i].is_initial_state = false;
        graph->nodes[i].is_error_state = false;
        graph->nodes[i].triggering_seeds = NULL;
        graph->nodes[i].triggering_seeds_count = 0;
        graph->nodes[i].triggering_seeds_capacity = 0;
    }
}

/**
 * @brief 查找状态节点，不存在则创建
 */
static StateNode* find_or_create_state_node(StateGraph *graph, uint32_t state_id) {
    if (!graph) return NULL;
    
    // 查找已存在的节点
    for (uint32_t i = 0; i < graph->node_count; i++) {
        if (graph->nodes[i].state_id == state_id) {
            return &graph->nodes[i];
        }
    }
    
    // 创建新节点
    if (graph->node_count >= MAX_GRAPH_STATES) {
        return NULL;  // 图已满
    }
    
    StateNode *new_node = &graph->nodes[graph->node_count];
    new_node->state_id = state_id;
    new_node->visit_count = 0;
    new_node->out_degree = 0;
    new_node->first_discovered = time(NULL);
    new_node->is_initial_state = (graph->node_count == 0);  // 第一个节点为初始状态
    new_node->is_error_state = (state_id >= 400 && state_id < 600);  // HTTP错误状态
    new_node->triggering_seeds = NULL;
    new_node->triggering_seeds_count = 0;
    new_node->triggering_seeds_capacity = 0;
    
    graph->node_count++;
    return new_node;
}

/**
 * @brief 添加状态转移边
 */
int state_graph_add_transition(StateGraph *graph,
                               uint32_t from_state,
                               uint32_t to_state,
                               const unsigned char *trigger_input,
                               uint32_t input_len) {
    if (!graph) return 0;
    
    StateNode *from_node = find_or_create_state_node(graph, from_state);
    StateNode *to_node = find_or_create_state_node(graph, to_state);
    
    if (!from_node || !to_node) return 0;
    
    // 检查是否已存在该转移
    for (uint32_t i = 0; i < from_node->out_degree; i++) {
        if (from_node->edges[i].to_state == to_state) {
            // 更新已存在的转移
            from_node->edges[i].transition_count++;
            from_node->edges[i].last_seen_time = time(NULL);
            to_node->visit_count++;
            graph->total_transitions++;
            return 1;
        }
    }
    
    // 添加新转移
    if (from_node->out_degree >= MAX_EDGES_PER_STATE) {
        return 0;  // 出度已满
    }
    
    StateEdge *new_edge = &from_node->edges[from_node->out_degree];
    new_edge->to_state = to_state;
    new_edge->transition_count = 1;
    new_edge->first_seen_time = time(NULL);
    new_edge->last_seen_time = time(NULL);
    
    // 记录触发输入（前64字节）
    if (trigger_input && input_len > 0) {
        uint32_t copy_len = input_len > 63 ? 63 : input_len;
        memcpy(new_edge->trigger_input, trigger_input, copy_len);
        new_edge->trigger_input[copy_len] = '\0';
    }
    
    from_node->out_degree++;
    to_node->visit_count++;
    graph->total_transitions++;
    
    return 1;
}

/**
 * @brief 记录某个seed触发了特定状态
 */
int state_graph_register_seed_for_state(StateGraph *graph,
                                        uint32_t state_id,
                                        uint32_t queue_id) {
    if (!graph) return 0;
    
    StateNode *node = find_or_create_state_node(graph, state_id);
    if (!node) return 0;
    
    // Safety check: prevent excessive memory allocation
    if (node->triggering_seeds_count >= MAX_SEEDS_PER_STATE) {
        // Silently skip to avoid DoS via memory exhaustion
        return 1;  // Return success but don't add
    }
    
    // 扩展seeds数组（如果需要）
    if (node->triggering_seeds_count >= node->triggering_seeds_capacity) {
        uint32_t new_capacity = node->triggering_seeds_capacity * 2;
        if (new_capacity == 0) new_capacity = 4;
        if (new_capacity > MAX_SEEDS_PER_STATE) new_capacity = MAX_SEEDS_PER_STATE;
        
        // Safety check: prevent excessive memory allocation
        if (new_capacity > 1024) {
            return 0;  // Limit to 1024 seeds per state
        }
        
        uint32_t *new_seeds = (uint32_t *)ck_realloc(node->triggering_seeds,
                                                     new_capacity * sizeof(uint32_t));
        if (!new_seeds) return 0;
        
        node->triggering_seeds = new_seeds;
        node->triggering_seeds_capacity = new_capacity;
    }
    
    // 检查是否已记录该seed
    for (uint32_t i = 0; i < node->triggering_seeds_count; i++) {
        if (node->triggering_seeds[i] == queue_id) {
            return 1;  // 已存在
        }
    }
    
    // 添加新seed
    node->triggering_seeds[node->triggering_seeds_count] = queue_id;
    node->triggering_seeds_count++;
    
    return 1;
}

/**
 * @brief 获取能触发目标状态的最佳seed
 */
int state_graph_get_best_seed_for_state(const StateGraph *graph,
                                        uint32_t target_state_id) {
    if (!graph) return -1;
    
    // 查找目标状态节点
    for (uint32_t i = 0; i < graph->node_count; i++) {
        if (graph->nodes[i].state_id == target_state_id) {
            const StateNode *node = &graph->nodes[i];
            
            if (node->triggering_seeds_count == 0) return -1;
            
            // 返回最新的seed（假设数组是按时间顺序的）
            return node->triggering_seeds[node->triggering_seeds_count - 1];
        }
    }
    
    return -1;
}

/**
 * @brief 计算状态的探索价值分数（基于Stateful Greybox Fuzzing论文的多因子评估）
 * 
 * 价值评估公式:
 * Value(s) = w1*Rarity(s) + w2*Expandability(s) + w3*Freshness(s) + w4*ErrorPotential(s)
 * 
 * 其中:
 * - Rarity(s) = 1 / (1 + visit_count)
 * - Expandability(s) = out_degree / max_out_degree  
 * - Freshness(s) = 1 / (1 + time_since_discovery)
 * - ErrorPotential(s) = is_error_state ? 2.0 : 1.0
 */
double state_graph_compute_state_value(const StateGraph *graph, uint32_t state_id) {
    if (!graph || graph->node_count == 0) return 0.0;
    
    StateNode *target_node = NULL;
    uint32_t max_out_degree = 0;
    uint64_t current_time = time(NULL);
    
    // 查找目标节点并计算最大出度
    for (uint32_t i = 0; i < graph->node_count; i++) {
        if (graph->nodes[i].state_id == state_id) {
            target_node = (StateNode*)&graph->nodes[i];
        }
        if (graph->nodes[i].out_degree > max_out_degree) {
            max_out_degree = graph->nodes[i].out_degree;
        }
    }
    
    if (!target_node) return 0.0;
    
    // 计算各个因子 (权重可通过环境变量调整)
    double w1 = 0.4, w2 = 0.2, w3 = 0.2, w4 = 0.2;
    
    // Factor 1: 稀有性 (访问次数越少价值越高)
    double rarity = 1.0 / (1.0 + target_node->visit_count);
    
    // Factor 2: 可扩展性 (出度越高，潜在探索空间越大)
    double expandability = max_out_degree > 0 ? 
        (double)target_node->out_degree / max_out_degree : 0.0;
    
    // Factor 3: 新鲜度 (最近发现的状态价值更高)
    uint64_t time_since_discovery = current_time > target_node->first_discovered ?
        current_time - target_node->first_discovered : 0;
    double freshness = 1.0 / (1.0 + time_since_discovery / 3600.0);  // 以小时为单位衰减
    
    // Factor 4: 错误状态潜力 (错误状态可能触发bug)
    double error_potential = target_node->is_error_state ? 2.0 : 1.0;
    
    double total_value = w1 * rarity + w2 * expandability + w3 * freshness + w4 * error_potential;
    
    return total_value;
}

/**
 * @brief 选择最有价值的target_state（Plateau时的智能选择）
 * 使用多因子价值评估替代简单的least_visited
 */
uint32_t state_graph_select_valuable_target(const StateGraph *graph, bool exclude_initial) {
    if (!graph || graph->node_count == 0) return 0;
    
    uint32_t best_state = 0;
    double best_value = -1.0;
    
    for (uint32_t i = 0; i < graph->node_count; i++) {
        const StateNode *node = &graph->nodes[i];
        
        // 排除初始状态（如果要求）
        if (exclude_initial && node->is_initial_state) continue;
        
        // 计算该状态的价值
        double value = state_graph_compute_state_value(graph, node->state_id);
        
        if (value > best_value) {
            best_value = value;
            best_state = node->state_id;
        }
    }
    
    return best_state;
}

/**
 * @brief 查找访问次数最少的状态（作为fallback）
 */
uint32_t state_graph_find_least_visited(const StateGraph *graph, bool exclude_initial) {
    if (!graph || graph->node_count == 0) return 0;
    
    uint32_t best_state = 0;
    uint32_t min_visits = UINT32_MAX;
    
    for (uint32_t i = 0; i < graph->node_count; i++) {
        const StateNode *node = &graph->nodes[i];
        
        if (exclude_initial && node->is_initial_state) continue;
        
        if (node->visit_count < min_visits) {
            min_visits = node->visit_count;
            best_state = node->state_id;
        }
    }
    
    return best_state;
}

/**
 * @brief 查找稀有转移边
 */
int state_graph_find_rare_transition(const StateGraph *graph,
                                     uint32_t *out_from,
                                     uint32_t *out_to) {
    if (!graph || !out_from || !out_to) return 0;
    
    uint32_t min_count = UINT32_MAX;
    uint32_t rare_from = 0, rare_to = 0;
    
    for (uint32_t i = 0; i < graph->node_count; i++) {
        const StateNode *node = &graph->nodes[i];
        
        for (uint32_t j = 0; j < node->out_degree; j++) {
            const StateEdge *edge = &node->edges[j];
            
            if (edge->transition_count < min_count) {
                min_count = edge->transition_count;
                rare_from = node->state_id;
                rare_to = edge->to_state;
            }
        }
    }
    
    if (min_count == UINT32_MAX) return 0;
    
    *out_from = rare_from;
    *out_to = rare_to;
    return 1;
}

/**
 * @brief 检查状态转移是否存在
 */
bool state_graph_has_transition(const StateGraph *graph,
                                uint32_t from_state,
                                uint32_t to_state) {
    if (!graph) return false;
    
    for (uint32_t i = 0; i < graph->node_count; i++) {
        const StateNode *node = &graph->nodes[i];
        
        if (node->state_id == from_state) {
            for (uint32_t j = 0; j < node->out_degree; j++) {
                if (node->edges[j].to_state == to_state) {
                    return true;
                }
            }
            break;
        }
    }
    
    return false;
}

/**
 * @brief 计算自适应稀有转移阈值
 */
uint32_t state_graph_adaptive_rare_threshold(const StateGraph *graph,
                                            uint32_t plateau_cycles) {
    if (!graph || graph->total_transitions == 0) return 1;
    
    // 计算平均转移次数
    float avg_transitions = (float)graph->total_transitions / graph->node_count;
    
    // 基础阈值为平均值的50%
    uint32_t base_threshold = (uint32_t)(avg_transitions * 0.5f);
    if (base_threshold == 0) base_threshold = 1;
    
    // Plateau期间线性提升阈值（更积极探索稀有转移）
    uint32_t plateau_boost = plateau_cycles / 10;  // 每10个cycles提升1
    
    return base_threshold + plateau_boost;
}