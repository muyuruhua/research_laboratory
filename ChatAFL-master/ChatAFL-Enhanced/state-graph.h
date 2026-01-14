/*
 * state-graph.h - 状态转移图（State Transition Graph）
 * 
 * 灵感来源: USENIX Security '22 "Stateful Greybox Fuzzing"
 * 核心思想: 显式构建状态转移图（非单纯的状态计数）
 * 
 * 功能：
 * 1. 记录状态转移边（from_state → to_state）
 * 2. 统计转移频率（支持"稀有转移"优先探索）
 * 3. 路径查询（从状态A到状态B的路径）
 * 4. DOT格式导出（可视化）
 * 
 * GAP-4修复：提供完整的STT数据结构
 */

#ifndef __STATE_GRAPH_H
#define __STATE_GRAPH_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_GRAPH_STATES 2048        /* 最大状态节点数 */
#define MAX_EDGES_PER_STATE 32       /* 每个状态最多出边数 */

/* ============================================
 * 数据结构定义
 * ============================================ */

/**
 * @brief 状态转移边
 */
typedef struct StateEdge {
  uint32_t to_state;              /* 目标状态ID */
  uint32_t transition_count;      /* 转移次数 */
  uint64_t first_seen_time;       /* 首次发现时间（毫秒） */
  uint64_t last_seen_time;        /* 最后访问时间 */
  char trigger_input[64];         /* 触发该转移的输入示例（前64字节） */
} StateEdge;

/**
 * @brief 状态节点
 */
typedef struct StateNode {
  uint32_t state_id;              /* 状态ID */
  uint32_t visit_count;           /* 访问次数 */
  uint32_t out_degree;            /* 出度（出边数量） */
  StateEdge edges[MAX_EDGES_PER_STATE]; /* 出边数组 */
  uint64_t first_discovered;      /* 首次发现时间 */
  bool is_initial_state;          /* 是否为初始状态 */
  bool is_error_state;            /* 是否为错误状态（4xx/5xx） */
} StateNode;

/**
 * @brief 状态转移图（全局）
 */
typedef struct StateGraph {
  StateNode nodes[MAX_GRAPH_STATES];  /* 状态节点数组 */
  uint32_t node_count;                /* 当前节点数 */
  uint32_t total_transitions;         /* 总转移次数 */
  uint64_t start_time;                /* 图创建时间 */
} StateGraph;

/* ============================================
 * 核心API
 * ============================================ */

/**
 * @brief 初始化状态转移图
 * @param graph 图结构指针
 */
void state_graph_init(StateGraph *graph);

/**
 * @brief 添加状态转移边
 * 
 * @param graph 图结构指针
 * @param from_state 源状态ID
 * @param to_state 目标状态ID
 * @param trigger_input 触发输入（用于记录如何触发该转移）
 * @param input_len 输入长度
 * @return 1=成功添加, 0=失败（图已满）
 * 
 * 逻辑：
 * 1. 查找或创建from_state节点
 * 2. 查找或创建to_state节点
 * 3. 在from_state节点中添加/更新到to_state的边
 * 4. 更新转移计数和时间戳
 */
int state_graph_add_transition(StateGraph *graph,
                                uint32_t from_state,
                                uint32_t to_state,
                                const unsigned char *trigger_input,
                                uint32_t input_len);

/**
 * @brief 查找访问次数最少的状态（低覆盖率优先）
 * 
 * @param graph 图结构指针
 * @param exclude_initial 是否排除初始状态（通常为true）
 * @return 访问次数最少的状态ID，0=图为空
 * 
 * 用途：用于Plateau时触发LLM生成到达该状态的测试序列
 */
uint32_t state_graph_find_least_visited(const StateGraph *graph,
                                        bool exclude_initial);

/**
 * @brief 查找稀有转移边（转移次数最少）
 * 
 * @param graph 图结构指针
 * @param out_from 输出：源状态ID
 * @param out_to 输出：目标状态ID
 * @return 1=找到, 0=未找到
 * 
 * 用途：指导fuzzer优先探索稀有转移路径
 */
int state_graph_find_rare_transition(const StateGraph *graph,
                                     uint32_t *out_from,
                                     uint32_t *out_to);

/**
 * @brief 检查状态转移是否存在
 * 
 * @param graph 图结构指针
 * @param from_state 源状态ID
 * @param to_state 目标状态ID
 * @return true=存在, false=不存在
 */
bool state_graph_has_transition(const StateGraph *graph,
                                uint32_t from_state,
                                uint32_t to_state);

/**
 * @brief 导出状态转移图为DOT格式（Graphviz可视化）
 * 
 * @param graph 图结构指针
 * @param output_file 输出文件路径
 * @return 1=成功, 0=失败
 * 
 * 输出格式：
 * digraph StateGraph {
 *   S0 [label="State 0 (1234 visits)"];
 *   S1 [label="State 1 (567 visits)"];
 *   S0 -> S1 [label="89 times"];
 * }
 */
int state_graph_export_dot(const StateGraph *graph,
                           const char *output_file);

/**
 * @brief 获取图统计信息（用于fuzzer_stats输出）
 * 
 * @param graph 图结构指针
 * @param out_nodes 输出：节点数
 * @param out_edges 输出：边数
 * @param out_total_transitions 输出：总转移次数
 */
void state_graph_get_stats(const StateGraph *graph,
                           uint32_t *out_nodes,
                           uint32_t *out_edges,
                           uint32_t *out_total_transitions);

/**
 * @brief BFS查找从源状态到目标状态的最短路径
 * 
 * @param graph 图结构指针
 * @param from_state 源状态ID
 * @param to_state 目标状态ID
 * @param path_buffer 输出：路径数组（调用者提供）
 * @param max_path_len 路径数组最大长度
 * @param out_path_len 输出：实际路径长度
 * @return 1=找到路径, 0=未找到
 * 
 * 用途：当LLM需要生成"到达状态X的序列"时，提供路径参考
 */
int state_graph_find_path(const StateGraph *graph,
                          uint32_t from_state,
                          uint32_t to_state,
                          uint32_t *path_buffer,
                          uint32_t max_path_len,
                          uint32_t *out_path_len);

#endif /* __STATE_GRAPH_H */
