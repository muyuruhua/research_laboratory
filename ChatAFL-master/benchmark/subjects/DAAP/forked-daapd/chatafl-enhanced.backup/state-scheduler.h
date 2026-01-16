/*
 * 文件: state-scheduler.h
 * 描述: 状态导向调度器 - 基于状态转移覆盖的测试用例选择策略
 * 灵感来源: USENIX Security '22 "Stateful Greybox Fuzzing"
 * 
 * 创新点：
 * 1. 将协议状态作为feedback维度（传统AFL只关注代码覆盖）
 * 2. 优先探索低覆盖状态（State Transition Tree思想）
 * 3. Plateau检测：停滞时触发LLM生成到达特定状态的序列
 */

#ifndef __STATE_SCHEDULER_H
#define __STATE_SCHEDULER_H

#include <stdbool.h>
#include <stddef.h>
#include "protocol-spec.h"

/* P1-1修复: RFC理论状态定义（用于状态覆盖率计算） */
#define MAX_PROTOCOL_STATES 32

typedef struct {
  const char *state_name;          /* 状态名称（如 "S_INIT", "S_USER"） */
  unsigned int state_id;           /* 理论状态ID */
  bool is_discovered;              /* 是否已被发现 */
} TheoreticalState;

typedef struct {
  const char *protocol_name;       /* 协议名称（FTP/SMTP/HTTP等） */
  TheoreticalState states[MAX_PROTOCOL_STATES];
  unsigned int state_count;        /* 理论状态总数 */
  unsigned int discovered_count;   /* 已发现状态数 */
} ProtocolStateMachine;

#define MAX_CORPUS 256     // Corpus大小限制

/* ============================================
 * 状态管理 API
 * ============================================ */

/**
 * @brief 增加状态访问计数
 * @param state 状态哈希（如 "S_230_authenticated"）
 * 
 * 每次观察到该状态时调用，用于低覆盖率优先调度
 */
void increment_state_count(const char* state);

/**
 * @brief 获取状态访问次数
 * @param state 状态哈希
 * @return 访问次数，0表示未访问过
 */
int get_state_count(const char* state);

/**
 * @brief 选择访问次数最少的状态
 * @param out 输出缓冲区（存储状态哈希）
 * @param out_len 缓冲区大小
 * @return 1=成功找到, 0=状态表为空
 * 
 * 策略：遍历状态计数表，返回count最小的状态
 * 用于指导LLM生成到达该状态的测试序列
 */
int pick_least_visited_state(char* out, size_t out_len);

/**
 * @brief P1-1修复: 计算协议状态覆盖率
 * @param protocol_name 协议名称（"FTP", "SMTP", "HTTP"）
 * @param state_ids 已发现的状态ID数组
 * @param state_count 已发现状态数量
 * @param out_coverage 输出：覆盖率百分比（0.0-100.0）
 * @param out_missing 输出：缺失的理论状态名称数组（可选，传NULL忽略）
 * @param max_missing 缺失状态数组最大长度
 * @return 实际缺失状态数量
 * 
 * 功能：根据RFC理论状态机，计算实际覆盖的状态百分比
 * 示例：FTP协议理论8个状态，发现6个 → 覆盖率75.0%
 */
int compute_state_coverage(const char *protocol_name,
                          unsigned int *state_ids,
                          unsigned int state_count,
                          double *out_coverage,
                          const char **out_missing,
                          unsigned int max_missing);

/* get_all_state_counts() - Week 6补充（用于热力图生成） */

/* ============================================
 * Corpus管理 API（状态感知的种子池）
 * ============================================ */

/**
 * @brief 保存触发新状态转移的测试用例到corpus（带覆盖增益验证）
 * @param json 测试用例JSON
 * @param edge_info 状态转移边信息（如 "S_220 -> S_230"）
 * @param virgin_bits 覆盖bitmap（用于计算边覆盖增益）
 * @param map_size Bitmap大小
 * @param prev_state_count 之前的状态数量
 * @param new_state_count 新的状态数量
 * @return true=已保存（有增益）, false=拒绝（无增益）
 * 
 * **Week 2-4 P0关键修复**: 覆盖增益验证
 * 存储策略：
 * - 只有在edge_coverage或state_coverage有提升时才保存
 * - 计算bitmap diff: count_non_255_bytes(virgin_bits)
 * - 关联其触发的状态转移
 * - 用于后续的低覆盖率优先选择
 * 
 * 增益判断公式：
 *   has_gain = (new_edge_coverage > prev_edge_coverage) ||
 *              (new_state_count > prev_state_count)
 */
bool save_to_corpus(const char* json, 
                    const char* edge_info,
                    const unsigned char* virgin_bits,
                    unsigned int map_size,
                    unsigned int prev_state_count,
                    unsigned int new_state_count);

/**
 * @brief 从corpus中选择目标为低覆盖状态的用例
 * @param out 输出缓冲区（存储JSON字符串）
 * @param out_len 缓冲区大小
 * @return 1=成功选择, 0=未找到合适用例
 * 
 * 流程：
 * 1. 调用 pick_least_visited_state() 找到低覆盖状态
 * 2. 遍历corpus，找到target_state匹配的entry
 * 3. 返回该entry的JSON用例
 */
int pick_corpus_for_low_coverage(char* out, size_t out_len);

/**
 * @brief 清空corpus（用于重置或内存管理）
 */
void clear_corpus();

/**
 * @brief 获取corpus中的条目数量
 * @return 当前已占用的条目数
 */
int get_corpus_size();

/* ============================================
 * Plateau检测 API（停滞检测）
 * ============================================ */

/**
 * @brief 检测fuzzing是否陷入停滞（Plateau）
 * @param recent_new_states 最近N轮发现的新状态数
 * @param threshold 停滞阈值（建议3-5轮）
 * @return true=已停滞，应触发LLM介入
 * 
 * 示例：
 * 如果连续5轮fuzzing都没有发现新状态转移，则判定为plateau
 */
bool is_plateau(int recent_cycles, double threshold);

/**
 * @brief 请求LLM生成到达目标状态的测试序列
 * @param target_state 目标状态哈希
 * @param current_state 当前状态哈希
 * @param spec 协议规范
 * @return 生成的JSON字符串（需调用者free），NULL=失败
 * 
 * Prompt策略：
 * "当前在状态 S_220，需要到达 S_230_authenticated。
 *  请生成一个命令序列达成此状态转移。
 *  输出格式：[TEMPLATE]...[/TEMPLATE]"
 * 
 * 注意：此函数会调用 chat_with_llm()
 */
char* request_llm_for_state_sequence(const char* target_state, 
                                     const char* current_state, 
                                     ProtocolSpec* spec);

/* ============================================
 * 状态转移图可视化 API（Week 6实现）
 * ============================================ */

/* 注: 以下函数在Week 6补充实现（用于论文图表）
 * - export_state_graph_dot() - 导出Graphviz DOT格式
 * - export_state_heatmap_csv() - 导出CSV热力图数据
 * 当前使用 save_state_table_to_file() 保存基础数据
 */

/* ============================================
 * 集成到AFL的调度逻辑 (Week 6)
 * ============================================ */

/* 注: calculate_state_aware_priority() 在Week 6集成到afl-fuzz.c
 * 当前版本使用简单的低覆盖优先策略
 */

#endif /* __STATE_SCHEDULER_H */
