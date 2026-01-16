/*
 * state-graph.c - 状态转移图实现
 * 
 * GAP-4修复：完整的State Transition Graph（STT）实现
 * 参考：USENIX Security '22 "Stateful Greybox Fuzzing"
 */

#include "state-graph.h"
#include "alloc-inl.h"
#include "debug.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

/* ============================================
 * 辅助函数
 * ============================================ */

/**
 * @brief 获取当前时间（毫秒）
 */
static uint64_t get_current_time_ms() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/**
 * @brief 查找状态节点索引
 * @return 节点索引，-1=未找到
 */
static int find_node_index(const StateGraph *graph, uint32_t state_id) {
  for (uint32_t i = 0; i < graph->node_count; i++) {
    if (graph->nodes[i].state_id == state_id) {
      return (int)i;
    }
  }
  return -1;
}

/**
 * @brief 在节点中查找出边索引
 * @return 边索引，-1=未找到
 */
static int find_edge_index(const StateNode *node, uint32_t to_state) {
  for (uint32_t i = 0; i < node->out_degree; i++) {
    if (node->edges[i].to_state == to_state) {
      return (int)i;
    }
  }
  return -1;
}

/* ============================================
 * 核心实现
 * ============================================ */

/**
 * @brief 初始化状态转移图
 */
void state_graph_init(StateGraph *graph) {
  if (!graph) return;
  
  memset(graph, 0, sizeof(StateGraph));
  graph->start_time = get_current_time_ms();
  
  /* 创建初始状态节点（状态0） */
  graph->nodes[0].state_id = 0;
  graph->nodes[0].is_initial_state = true;
  graph->nodes[0].first_discovered = graph->start_time;
  /* P1-Critical: 初始化seed映射数组 */
  graph->nodes[0].triggering_seeds = NULL;
  graph->nodes[0].triggering_seeds_count = 0;
  graph->nodes[0].triggering_seeds_capacity = 0;
  graph->node_count = 1;
}

/**
 * @brief 添加状态转移边（完整实现）
 */
int state_graph_add_transition(StateGraph *graph,
                                uint32_t from_state,
                                uint32_t to_state,
                                const unsigned char *trigger_input,
                                uint32_t input_len) {
  if (!graph) return 0;
  
  uint64_t current_time = get_current_time_ms();
  
  /* 1. 查找或创建from_state节点 */
  int from_idx = find_node_index(graph, from_state);
  if (from_idx == -1) {
    /* 创建新节点 */
    if (graph->node_count >= MAX_GRAPH_STATES) {
      return 0; /* 图已满 */
    }
    
    from_idx = graph->node_count;
    graph->nodes[from_idx].state_id = from_state;
    graph->nodes[from_idx].first_discovered = current_time;
    graph->nodes[from_idx].is_initial_state = (from_state == 0);
    /* P1-Critical: 初始化seed映射 */
    graph->nodes[from_idx].triggering_seeds = NULL;
    graph->nodes[from_idx].triggering_seeds_count = 0;
    graph->nodes[from_idx].triggering_seeds_capacity = 0;
    graph->node_count++;
  }
  
  /* 2. 查找或创建to_state节点 */
  int to_idx = find_node_index(graph, to_state);
  if (to_idx == -1) {
    if (graph->node_count >= MAX_GRAPH_STATES) {
      return 0;
    }
    
    to_idx = graph->node_count;
    graph->nodes[to_idx].state_id = to_state;
    graph->nodes[to_idx].first_discovered = current_time;
    /* P1-Critical: 初始化seed映射 */
    graph->nodes[to_idx].triggering_seeds = NULL;
    graph->nodes[to_idx].triggering_seeds_count = 0;
    graph->nodes[to_idx].triggering_seeds_capacity = 0;
    
    /* 判断是否为错误状态（4xx/5xx响应码） */
    if (to_state >= 400 && to_state < 600) {
      graph->nodes[to_idx].is_error_state = true;
    }
    
    graph->node_count++;
  }
  
  /* 3. 更新to_state访问计数 */
  graph->nodes[to_idx].visit_count++;
  
  /* 4. 在from_state节点中添加/更新到to_state的边 */
  StateNode *from_node = &graph->nodes[from_idx];
  int edge_idx = find_edge_index(from_node, to_state);
  
  if (edge_idx == -1) {
    /* 新边：添加 */
    if (from_node->out_degree >= MAX_EDGES_PER_STATE) {
      return 0; /* 出边已满 */
    }
    
    edge_idx = from_node->out_degree;
    from_node->edges[edge_idx].to_state = to_state;
    from_node->edges[edge_idx].first_seen_time = current_time;
    
    /* 保存触发输入示例（前64字节） */
    if (trigger_input && input_len > 0) {
      uint32_t copy_len = (input_len > 63) ? 63 : input_len;
      memcpy(from_node->edges[edge_idx].trigger_input, trigger_input, copy_len);
      from_node->edges[edge_idx].trigger_input[copy_len] = '\0';
    }
    
    from_node->out_degree++;
  }
  
  /* 5. 更新转移计数 */
  from_node->edges[edge_idx].transition_count++;
  from_node->edges[edge_idx].last_seen_time = current_time;
  
  graph->total_transitions++;
  
  return 1;
}

/**
 * @brief 查找访问次数最少的状态
 */
uint32_t state_graph_find_least_visited(const StateGraph *graph,
                                        bool exclude_initial) {
  if (!graph || graph->node_count == 0) return 0;
  
  uint32_t min_visits = UINT32_MAX;
  uint32_t least_visited_state = 0;
  
  for (uint32_t i = 0; i < graph->node_count; i++) {
    const StateNode *node = &graph->nodes[i];
    
    /* 跳过初始状态（如果需要） */
    if (exclude_initial && node->is_initial_state) continue;
    
    if (node->visit_count < min_visits) {
      min_visits = node->visit_count;
      least_visited_state = node->state_id;
    }
  }
  
  return least_visited_state;
}

/**
 * @brief 查找稀有转移边
 * P1-1修复: 使用自适应阈值，只返回transition_count低于阈值的边
 */
int state_graph_find_rare_transition(const StateGraph *graph,
                                     uint32_t *out_from,
                                     uint32_t *out_to) {
  if (!graph || !out_from || !out_to) return 0;
  
  /* P1-1: 计算自适应阈值（基于全局平均+plateau调整） */
  uint32_t rare_threshold = state_graph_adaptive_rare_threshold(graph, 0);
  
  uint32_t min_count = UINT32_MAX;
  int found = 0;
  
  for (uint32_t i = 0; i < graph->node_count; i++) {
    const StateNode *node = &graph->nodes[i];
    
    for (uint32_t j = 0; j < node->out_degree; j++) {
      const StateEdge *edge = &node->edges[j];
      
      /* 只考虑低于阈值的边（真正的稀有转移） */
      if (edge->transition_count <= rare_threshold && edge->transition_count < min_count) {
        min_count = edge->transition_count;
        *out_from = node->state_id;
        *out_to = edge->to_state;
        found = 1;
      }
    }
  }
  
  return found;
}

/**
 * @brief 检查状态转移是否存在
 */
bool state_graph_has_transition(const StateGraph *graph,
                                uint32_t from_state,
                                uint32_t to_state) {
  if (!graph) return false;
  
  int from_idx = find_node_index(graph, from_state);
  if (from_idx == -1) return false;
  
  int edge_idx = find_edge_index(&graph->nodes[from_idx], to_state);
  return (edge_idx != -1);
}

/**
 * @brief 导出状态转移图为DOT格式
 */
int state_graph_export_dot(const StateGraph *graph,
                           const char *output_file) {
  if (!graph || !output_file) return 0;
  
  FILE *f = fopen(output_file, "w");
  if (!f) return 0;
  
  /* DOT文件头 */
  fprintf(f, "digraph StateTransitionGraph {\n");
  fprintf(f, "  rankdir=LR;\n");
  fprintf(f, "  node [shape=circle];\n\n");
  
  /* 输出节点 */
  for (uint32_t i = 0; i < graph->node_count; i++) {
    const StateNode *node = &graph->nodes[i];
    
    /* 节点颜色：初始状态=绿色，错误状态=红色，普通=蓝色 */
    const char *color = "lightblue";
    if (node->is_initial_state) color = "lightgreen";
    else if (node->is_error_state) color = "lightcoral";
    
    fprintf(f, "  S%u [label=\"State %u\\n(%u visits)\", fillcolor=\"%s\", style=filled];\n",
            node->state_id, node->state_id, node->visit_count, color);
  }
  
  fprintf(f, "\n");
  
  /* 输出边 */
  for (uint32_t i = 0; i < graph->node_count; i++) {
    const StateNode *node = &graph->nodes[i];
    
    for (uint32_t j = 0; j < node->out_degree; j++) {
      const StateEdge *edge = &node->edges[j];
      
      /* 边粗细：转移次数越多，线越粗 */
      int penwidth = 1;
      if (edge->transition_count > 100) penwidth = 3;
      else if (edge->transition_count > 10) penwidth = 2;
      
      fprintf(f, "  S%u -> S%u [label=\"%u times\", penwidth=%d];\n",
              node->state_id, edge->to_state, edge->transition_count, penwidth);
    }
  }
  
  fprintf(f, "}\n");
  fclose(f);
  
  return 1;
}

/**
 * @brief 获取图统计信息
 */
void state_graph_get_stats(const StateGraph *graph,
                           uint32_t *out_nodes,
                           uint32_t *out_edges,
                           uint32_t *out_total_transitions) {
  if (!graph) return;
  
  if (out_nodes) {
    *out_nodes = graph->node_count;
  }
  
  if (out_edges) {
    uint32_t total_edges = 0;
    for (uint32_t i = 0; i < graph->node_count; i++) {
      total_edges += graph->nodes[i].out_degree;
    }
    *out_edges = total_edges;
  }
  
  if (out_total_transitions) {
    *out_total_transitions = graph->total_transitions;
  }
}

/**
 * @brief BFS查找最短路径（完整实现）
 */
int state_graph_find_path(const StateGraph *graph,
                          uint32_t from_state,
                          uint32_t to_state,
                          uint32_t *path_buffer,
                          uint32_t max_path_len,
                          uint32_t *out_path_len) {
  if (!graph || !path_buffer || !out_path_len) return 0;
  if (max_path_len == 0) return 0;
  
  /* BFS队列和访问标记 */
  uint32_t queue[MAX_GRAPH_STATES];
  int parent[MAX_GRAPH_STATES]; /* parent[i] = 从哪个节点到达节点i */
  bool visited[MAX_GRAPH_STATES];
  
  memset(visited, 0, sizeof(visited));
  memset(parent, -1, sizeof(parent));
  
  int queue_front = 0, queue_rear = 0;
  
  /* 1. 找到起始节点 */
  int start_idx = find_node_index(graph, from_state);
  if (start_idx == -1) return 0;
  
  /* 2. BFS初始化 */
  queue[queue_rear++] = start_idx;
  visited[start_idx] = true;
  
  int target_idx = -1;
  
  /* 3. BFS主循环 */
  while (queue_front < queue_rear) {
    int current_idx = queue[queue_front++];
    const StateNode *current_node = &graph->nodes[current_idx];
    
    /* 检查是否到达目标 */
    if (current_node->state_id == to_state) {
      target_idx = current_idx;
      break;
    }
    
    /* 遍历所有出边 */
    for (uint32_t i = 0; i < current_node->out_degree; i++) {
      uint32_t next_state = current_node->edges[i].to_state;
      int next_idx = find_node_index(graph, next_state);
      
      if (next_idx != -1 && !visited[next_idx]) {
        visited[next_idx] = true;
        parent[next_idx] = current_idx;
        queue[queue_rear++] = next_idx;
      }
    }
  }
  
  /* 4. 未找到路径 */
  if (target_idx == -1) {
    *out_path_len = 0;
    return 0;
  }
  
  /* 5. 回溯路径 */
  int path_len = 0;
  int idx = target_idx;
  uint32_t reverse_path[MAX_GRAPH_STATES];
  
  while (idx != -1 && path_len < MAX_GRAPH_STATES) {
    reverse_path[path_len++] = graph->nodes[idx].state_id;
    idx = parent[idx];
  }
  
  /* 6. 反转路径（从起点到终点） */
  if (path_len > (int)max_path_len) {
    path_len = max_path_len;
  }
  
  for (int i = 0; i < path_len; i++) {
    path_buffer[i] = reverse_path[path_len - 1 - i];
  }
  
  *out_path_len = path_len;
  return 1;
}

/* ============================================
 * P1修复：自适应稀有转移阈值 + 状态价值估计
 * ============================================ */

/**
 * @brief 计算自适应稀有转移阈值
 * @param graph 图结构指针
 * @param plateau_cycles 当前plateau持续的cycles数
 * @return 自适应阈值（转移次数低于此值视为稀有）
 * 
 * 策略：
 * - 正常探索期：阈值=平均转移次数的50%
 * - Plateau期：阈值随plateau_cycles线性提升（提高探索激进度）
 */
uint32_t state_graph_adaptive_rare_threshold(const StateGraph *graph,
                                            uint32_t plateau_cycles) {
    if (!graph || graph->node_count == 0) {
        return 5;  // 默认阈值
    }
    
    /* 计算所有转移的平均次数 */
    uint64_t total_transitions = 0;
    uint32_t edge_count = 0;
    
    for (uint32_t i = 0; i < graph->node_count; i++) {
        const StateNode *node = &graph->nodes[i];
        for (uint32_t j = 0; j < node->out_degree; j++) {
            total_transitions += node->edges[j].transition_count;
            edge_count++;
        }
    }
    
    if (edge_count == 0) {
        return 5;
    }
    
    uint32_t avg_transitions = (uint32_t)(total_transitions / edge_count);
    
    /* 基础阈值：平均值的50% */
    uint32_t base_threshold = (avg_transitions / 2);
    if (base_threshold < 3) base_threshold = 3;
    
    /* Plateau调整：每50 cycles提升10% */
    if (plateau_cycles > 50) {
        uint32_t boost = (plateau_cycles / 50) * (base_threshold / 10);
        base_threshold += boost;
    }
    
    /* 上限：平均值的150%（避免过度激进） */
    uint32_t max_threshold = (avg_transitions * 3) / 2;
    if (base_threshold > max_threshold) {
        base_threshold = max_threshold;
    }
    
    return base_threshold;
}

/**
 * @brief 计算状态的探索价值（用于Plateau时智能选择target_state）
 * @param graph 图结构指针
 * @param state_id 状态ID
 * @return 价值分数（越高越有探索价值）
 * 
 * 价值计算因子：
 * 1. 低访问次数（未充分探索）
 * 2. 高出度（潜在有更多后继状态）
 * 3. 新近发现（时间衰减）
 * 4. 非错误状态（错误状态价值降低）
 */
double state_graph_compute_state_value(const StateGraph *graph,
                                      uint32_t state_id) {
    if (!graph) return 0.0;
    
    int node_idx = find_node_index(graph, state_id);
    if (node_idx == -1) return 0.0;
    
    const StateNode *node = &graph->nodes[node_idx];
    
    /* 因子1：访问稀缺性（越少越好） */
    double visit_factor = 1.0;
    if (node->visit_count > 0) {
        visit_factor = 100.0 / (double)(node->visit_count + 1);
    }
    
    /* 因子2：潜在扩展性（出度越高越好） */
    double expansion_factor = 1.0 + (double)node->out_degree * 0.5;
    
    /* 因子3：新鲜度（最近发现的状态更有价值） */
    double freshness_factor = 1.0;
    if (node->first_discovered > 0) {
        time_t current_time = time(NULL);
        time_t age = current_time - (time_t)(node->first_discovered / 1000);  // 转换为秒
        if (age < 300) {  // 5分钟内发现的状态
            freshness_factor = 2.0;
        } else if (age < 1800) {  // 30分钟内
            freshness_factor = 1.5;
        }
    }
    
    /* 因子4：状态类型（错误状态价值折半） */
    double type_factor = node->is_error_state ? 0.5 : 1.0;
    
    /* 综合价值 */
    double value = visit_factor * expansion_factor * freshness_factor * type_factor;
    
    return value;
}

/**
 * @brief 选择最有价值的target_state（用于Plateau时LLM指导）
 * @param graph 图结构指针
 * @param exclude_initial 是否排除初始状态
 * @return 最有价值的状态ID，0=图为空
 */
uint32_t state_graph_select_valuable_target(const StateGraph *graph,
                                           bool exclude_initial) {
    if (!graph || graph->node_count == 0) return 0;
    
    double max_value = 0.0;
    uint32_t best_state = 0;
    
    for (uint32_t i = 0; i < graph->node_count; i++) {
        const StateNode *node = &graph->nodes[i];
        
        /* 跳过初始状态 */
        if (exclude_initial && node->is_initial_state) continue;
        
        double value = state_graph_compute_state_value(graph, node->state_id);
        if (value > max_value) {
            max_value = value;
            best_state = node->state_id;
        }
    }
    
    return best_state;
}

/* ============================================
 * P1-Critical修复: State→Seed精确映射实现
 * ============================================ */

/**
 * @brief 记录某个seed触发了特定状态
 */
int state_graph_register_seed_for_state(StateGraph *graph,
                                       uint32_t state_id,
                                       uint32_t queue_id) {
    if (!graph) return 0;
    
    /* 查找状态节点 */
    int node_idx = find_node_index(graph, state_id);
    if (node_idx < 0) return 0; /* 状态不存在 */
    
    StateNode *node = &graph->nodes[node_idx];
    
    /* 检查是否已记录该seed */
    for (uint32_t i = 0; i < node->triggering_seeds_count; i++) {
        if (node->triggering_seeds[i] == queue_id) {
            return 1; /* 已存在，无需重复添加 */
        }
    }
    
    /* 扩容检查 */
    if (node->triggering_seeds_count >= node->triggering_seeds_capacity) {
        uint32_t new_capacity = node->triggering_seeds_capacity == 0 ? 
                               8 : node->triggering_seeds_capacity * 2;
        uint32_t *new_array = ck_realloc(node->triggering_seeds, 
                                        new_capacity * sizeof(uint32_t));
        if (!new_array) return 0;
        
        node->triggering_seeds = new_array;
        node->triggering_seeds_capacity = new_capacity;
    }
    
    /* 添加seed */
    node->triggering_seeds[node->triggering_seeds_count++] = queue_id;
    return 1;
}

/**
 * @brief 获取能触发目标状态的最佳seed
 */
int state_graph_get_best_seed_for_state(const StateGraph *graph,
                                        uint32_t target_state_id) {
    if (!graph) return -1;
    
    /* 查找状态节点 */
    int node_idx = find_node_index(graph, target_state_id);
    if (node_idx < 0 || graph->nodes[node_idx].triggering_seeds_count == 0) {
        return -1; /* 未找到或无触发seed */
    }
    
    const StateNode *node = &graph->nodes[node_idx];
    
    /* 策略：返回最新添加的seed（假设越新越有价值） */
    return (int)node->triggering_seeds[node->triggering_seeds_count - 1];
}

