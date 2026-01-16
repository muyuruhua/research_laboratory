/*
 * llm-cost-tracker.h - LLM成本统计模块
 * P1功能：实时追踪LLM调用成本，支持预算控制
 */

#ifndef __LLM_COST_TRACKER_H
#define __LLM_COST_TRACKER_H

#include <stdint.h>
#include <stdbool.h>

/* ============================================
 * 数据结构
 * ============================================ */

typedef struct {
  uint64_t total_calls;           /* 总调用次数 */
  uint64_t cached_hits;           /* 缓存命中次数 */
  uint64_t grammar_gen_calls;     /* 语法生成调用 */
  uint64_t cegar_calls;           /* CEGAR修正调用 */
  uint64_t plateau_calls;         /* Plateau突破调用 */
  
  uint64_t total_prompt_tokens;   /* 总prompt tokens */
  uint64_t total_response_tokens; /* 总response tokens */
  uint64_t total_tokens;          /* 总tokens */
  
  float estimated_cost_usd;       /* 估计成本（美元） */
  float cost_per_1k_tokens;       /* 每1K tokens成本 */
  
  uint64_t start_time;            /* 开始时间戳 */
  uint64_t last_update_time;      /* 最后更新时间 */
} LLMCostReport;

/* ============================================
 * API函数
 * ============================================ */

/**
 * @brief 初始化成本追踪器
 * @param cost_per_1k 每1K tokens的成本（美元），如gpt-3.5-turbo: 0.002
 */
void llm_cost_init(float cost_per_1k);

/**
 * @brief 记录一次LLM调用
 * @param call_type 调用类型："grammar"|"cegar"|"plateau"
 * @param prompt_tokens prompt消耗的tokens
 * @param response_tokens 响应消耗的tokens
 * @param is_cached 是否命中缓存
 */
void llm_cost_record(const char* call_type, 
                     uint32_t prompt_tokens,
                     uint32_t response_tokens,
                     bool is_cached);

/**
 * @brief 获取当前成本报告
 * @return 成本报告结构体指针（静态内存，无需释放）
 */
const LLMCostReport* llm_cost_get_report();

/**
 * @brief 导出成本报告到文件
 * @param out_dir 输出目录
 */
void llm_cost_export(const char* out_dir);

/**
 * @brief 检查是否超出预算
 * @param budget_usd 预算上限（美元）
 * @return true=超出预算
 */
bool llm_cost_exceeds_budget(float budget_usd);

/**
 * @brief 重置统计数据
 */
void llm_cost_reset();

#endif /* __LLM_COST_TRACKER_H */
