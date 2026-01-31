/*
 * cegar-optimized.h - 优化的 CEGAR 集成配置
 * 
 * 主要优化：
 * 1. 降低触发频率（1000x 而非 100x）
 * 2. 环境变量控制开关
 * 3. LLM budget 限制
 * 4. 快速失败机制
 * 5. 性能监控
 */

#ifndef __CEGAR_OPTIMIZED_H
#define __CEGAR_OPTIMIZED_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* ========== 配置参数 ========== */

/* CEGAR 触发频率（每N次rejection触发一次）*/
#define CEGAR_TRIGGER_INTERVAL_DEFAULT 1000  /* 默认：1000次 */
#define CEGAR_TRIGGER_INTERVAL_AGGRESSIVE 100 /* 激进模式：100次 */
#define CEGAR_TRIGGER_INTERVAL_MINIMAL 10000  /* 最小模式：10000次 */

/* LLM Budget 限制 */
#define CEGAR_MAX_LLM_CALLS_PER_HOUR 30      /* 每小时最多调用30次 */
#define CEGAR_MAX_RETRIES 3                  /* 每次最多重试3次 */
#define CEGAR_RETRY_BACKOFF_MS 1000          /* 重试退避时间（毫秒）*/

/* 缓存配置 */
#define CEGAR_CACHE_SIZE 256                 /* 缓存条目数 */
#define CEGAR_CACHE_TTL_SECONDS 3600         /* 缓存有效期（秒）*/

/* 性能监控阈值 */
#define CEGAR_MAX_TIME_PER_CALL_MS 5000      /* 单次调用最大时间（毫秒）*/
#define CEGAR_TIME_BUDGET_PERCENT 10         /* CEGAR最多占用10%时间 */

/* 快速失败配置 */
#define CEGAR_CONSECUTIVE_FAILURES_THRESHOLD 10  /* 连续失败10次后暂停 */
#define CEGAR_COOLDOWN_PERIOD_SECONDS 300        /* 暂停5分钟 */

/* ========== 数据结构 ========== */

/**
 * @brief CEGAR 统计信息
 */
typedef struct {
    uint64_t triggers;              /* 触发次数 */
    uint64_t llm_calls;             /* LLM 调用次数 */
    uint64_t successes;             /* 成功修正次数 */
    uint64_t failures;              /* 失败次数 */
    uint64_t cache_hits;            /* 缓存命中次数 */
    uint64_t consecutive_failures;  /* 连续失败次数 */
    uint64_t total_time_ms;         /* 总耗时（毫秒）*/
    time_t last_llm_call_time;      /* 最后一次 LLM 调用时间 */
    time_t cooldown_until;          /* 冷却期结束时间 */
} CEGARStats;

/**
 * @brief CEGAR 运行时配置
 */
typedef struct {
    bool enabled;                   /* 是否启用 CEGAR */
    uint32_t trigger_interval;      /* 触发间隔 */
    uint32_t max_llm_calls_per_hour;/* 每小时最大 LLM 调用数 */
    uint32_t max_retries;           /* 最大重试次数 */
    bool fast_fail_enabled;         /* 是否启用快速失败 */
    bool performance_monitoring;    /* 是否启用性能监控 */
    CEGARStats stats;               /* 统计信息 */
} CEGARConfig;

/* ========== 全局配置（由 afl-fuzz.c 初始化）========== */
extern CEGARConfig g_cegar_config;

/* ========== 函数声明 ========== */

/**
 * @brief 初始化 CEGAR 配置（从环境变量读取）
 */
void cegar_config_init(void);

/**
 * @brief 检查是否应该触发 CEGAR（考虑所有限制条件）
 * @param rejection_count 当前 rejection 计数
 * @return true=应该触发, false=跳过
 */
bool should_trigger_cegar(uint64_t rejection_count);

/**
 * @brief 检查 LLM budget 是否充足
 * @return true=可以调用, false=已超出限额
 */
bool check_llm_budget(void);

/**
 * @brief 记录 CEGAR 调用开始（用于性能监控）
 * @return 开始时间戳（毫秒）
 */
uint64_t cegar_call_begin(void);

/**
 * @brief 记录 CEGAR 调用结束（更新统计）
 * @param start_time_ms 开始时间戳
 * @param success 是否成功
 */
void cegar_call_end(uint64_t start_time_ms, bool success);

/**
 * @brief 检查是否处于冷却期
 * @return true=冷却中，应跳过
 */
bool is_in_cooldown(void);

/**
 * @brief 重置冷却期（手动恢复）
 */
void reset_cooldown(void);

/**
 * @brief 打印 CEGAR 统计信息
 */
void print_cegar_stats(void);

/**
 * @brief 获取 CEGAR 时间占比
 * @param total_fuzzing_time_ms 总 fuzzing 时间（毫秒）
 * @return CEGAR 时间占比（0.0-1.0）
 */
float get_cegar_time_ratio(uint64_t total_fuzzing_time_ms);

#endif /* __CEGAR_OPTIMIZED_H */
