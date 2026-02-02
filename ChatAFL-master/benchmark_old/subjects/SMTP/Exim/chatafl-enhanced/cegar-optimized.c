/*
 * cegar-optimized.c - 优化的 CEGAR 运行时控制实现
 */

#include "cegar-optimized.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* 外部全局配置（在 afl-fuzz.c 中定义）*/
extern CEGARConfig g_cegar_config;

/* 辅助函数：获取当前时间（毫秒）*/
static uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/**
 * @brief 初始化 CEGAR 配置（从环境变量读取）
 */
void cegar_config_init(void) {
    /* 默认禁用 CEGAR（需要显式启用）*/
    g_cegar_config.enabled = (getenv("CHATAFL_CEGAR_ENABLE") != NULL);
    
    if (!g_cegar_config.enabled) {
        OKF("CEGAR disabled (set CHATAFL_CEGAR_ENABLE=1 to enable)");
        return;
    }
    
    /* 读取触发间隔 */
    char *interval_str = getenv("CHATAFL_CEGAR_INTERVAL");
    if (interval_str) {
        g_cegar_config.trigger_interval = (uint32_t)atoi(interval_str);
    } else {
        g_cegar_config.trigger_interval = CEGAR_TRIGGER_INTERVAL_DEFAULT;
    }
    
    /* 读取 LLM budget */
    char *budget_str = getenv("CHATAFL_LLM_BUDGET_HOURLY");
    if (budget_str) {
        g_cegar_config.max_llm_calls_per_hour = (uint32_t)atoi(budget_str);
    } else {
        g_cegar_config.max_llm_calls_per_hour = CEGAR_MAX_LLM_CALLS_PER_HOUR;
    }
    
    /* 读取最大重试次数 */
    char *retries_str = getenv("CHATAFL_CEGAR_MAX_RETRIES");
    if (retries_str) {
        g_cegar_config.max_retries = (uint32_t)atoi(retries_str);
    } else {
        g_cegar_config.max_retries = CEGAR_MAX_RETRIES;
    }
    
    /* 快速失败开关 */
    g_cegar_config.fast_fail_enabled = (getenv("CHATAFL_CEGAR_FAST_FAIL") != NULL);
    
    /* 性能监控开关 */
    g_cegar_config.performance_monitoring = (getenv("CHATAFL_CEGAR_MONITOR") != NULL);
    
    /* 初始化统计 */
    memset(&g_cegar_config.stats, 0, sizeof(CEGARStats));
    
    OKF("CEGAR enabled: interval=%u, budget=%u/hour, retries=%u, fast_fail=%s",
        g_cegar_config.trigger_interval,
        g_cegar_config.max_llm_calls_per_hour,
        g_cegar_config.max_retries,
        g_cegar_config.fast_fail_enabled ? "yes" : "no");
}

/**
 * @brief 检查是否应该触发 CEGAR
 */
bool should_trigger_cegar(uint64_t rejection_count) {
    if (!g_cegar_config.enabled) return false;
    
    /* 检查是否处于冷却期 */
    if (is_in_cooldown()) {
        return false;
    }
    
    /* 检查触发间隔 */
    if (rejection_count % g_cegar_config.trigger_interval != 0) {
        return false;
    }
    
    /* 检查 LLM budget */
    if (!check_llm_budget()) {
        return false;
    }
    
    return true;
}

/**
 * @brief 检查 LLM budget
 */
bool check_llm_budget(void) {
    time_t now = time(NULL);
    time_t hour_ago = now - 3600;
    
    /* 如果最后一次调用超过1小时前，重置计数 */
    if (g_cegar_config.stats.last_llm_call_time < hour_ago) {
        /* 重置小时计数（保留总计数）*/
        return true;
    }
    
    /* 简化版：假设每次 CEGAR 调用 = max_retries 次 LLM 调用 */
    uint64_t estimated_calls = g_cegar_config.stats.triggers * g_cegar_config.max_retries;
    uint64_t max_calls = g_cegar_config.max_llm_calls_per_hour;
    
    // Check for potential overflow
    if (g_cegar_config.stats.triggers > UINT64_MAX / g_cegar_config.max_retries) {
        WARNF("CEGAR trigger count overflow risk, resetting statistics");
        g_cegar_config.stats.triggers = 0;
        return false;
    }
    
    if (estimated_calls >= max_calls) {
        static bool warned = false;
        if (!warned) {
            WARNF("LLM budget exhausted (%llu/%u calls this hour), CEGAR suspended",
                  estimated_calls, max_calls);
            warned = true;
        }
        return false;
    }
    
    return true;
}

/**
 * @brief 记录 CEGAR 调用开始
 */
uint64_t cegar_call_begin(void) {
    g_cegar_config.stats.triggers++;
    g_cegar_config.stats.last_llm_call_time = time(NULL);
    return get_time_ms();
}

/**
 * @brief 记录 CEGAR 调用结束
 */
void cegar_call_end(uint64_t start_time_ms, bool success) {
    uint64_t end_time_ms = get_time_ms();
    uint64_t elapsed_ms = end_time_ms - start_time_ms;
    
    g_cegar_config.stats.total_time_ms += elapsed_ms;
    g_cegar_config.stats.llm_calls++;
    
    if (success) {
        g_cegar_config.stats.successes++;
        g_cegar_config.stats.consecutive_failures = 0;
    } else {
        g_cegar_config.stats.failures++;
        g_cegar_config.stats.consecutive_failures++;
        
        /* 快速失败：连续失败过多，进入冷却期 */
        if (g_cegar_config.fast_fail_enabled &&
            g_cegar_config.stats.consecutive_failures >= CEGAR_CONSECUTIVE_FAILURES_THRESHOLD) {
            
            g_cegar_config.stats.cooldown_until = time(NULL) + CEGAR_COOLDOWN_PERIOD_SECONDS;
            
            WARNF("CEGAR: %llu consecutive failures, entering cooldown for %d seconds",
                  g_cegar_config.stats.consecutive_failures,
                  CEGAR_COOLDOWN_PERIOD_SECONDS);
        }
    }
    
    /* 性能监控：单次调用超时警告 */
    if (g_cegar_config.performance_monitoring && elapsed_ms > CEGAR_MAX_TIME_PER_CALL_MS) {
        WARNF("CEGAR call took %llu ms (threshold: %u ms)", 
              elapsed_ms, CEGAR_MAX_TIME_PER_CALL_MS);
    }
}

/**
 * @brief 检查是否处于冷却期
 */
bool is_in_cooldown(void) {
    if (g_cegar_config.stats.cooldown_until == 0) {
        return false;
    }
    
    time_t now = time(NULL);
    if (now < g_cegar_config.stats.cooldown_until) {
        return true;
    }
    
    /* 冷却期结束 */
    g_cegar_config.stats.cooldown_until = 0;
    g_cegar_config.stats.consecutive_failures = 0;
    OKF("CEGAR cooldown ended, resuming operation");
    return false;
}

/**
 * @brief 重置冷却期
 */
void reset_cooldown(void) {
    g_cegar_config.stats.cooldown_until = 0;
    g_cegar_config.stats.consecutive_failures = 0;
    OKF("CEGAR cooldown manually reset");
}

/**
 * @brief 打印 CEGAR 统计信息
 */
void print_cegar_stats(void) {
    if (!g_cegar_config.enabled) {
        return;
    }
    
    CEGARStats *s = &g_cegar_config.stats;
    
    ACTF("===== CEGAR Statistics =====");
    ACTF("  Triggers:           %llu", s->triggers);
    ACTF("  LLM Calls:          %llu", s->llm_calls);
    ACTF("  Successes:          %llu (%.1f%%)", 
         s->successes, 
         s->llm_calls > 0 ? (s->successes * 100.0 / s->llm_calls) : 0.0);
    ACTF("  Failures:           %llu (%.1f%%)", 
         s->failures, 
         s->llm_calls > 0 ? (s->failures * 100.0 / s->llm_calls) : 0.0);
    ACTF("  Cache Hits:         %llu", s->cache_hits);
    ACTF("  Total Time:         %llu ms (%.1f sec)", 
         s->total_time_ms, s->total_time_ms / 1000.0);
    ACTF("  Avg Time/Call:      %llu ms", 
         s->llm_calls > 0 ? s->total_time_ms / s->llm_calls : 0);
    
    if (s->consecutive_failures > 0) {
        WARNF("  Consecutive Fails:  %llu", s->consecutive_failures);
    }
    
    if (is_in_cooldown()) {
        time_t remaining = g_cegar_config.stats.cooldown_until - time(NULL);
        WARNF("  Cooldown:           %ld seconds remaining", remaining);
    }
}

/**
 * @brief 获取 CEGAR 时间占比
 */
float get_cegar_time_ratio(uint64_t total_fuzzing_time_ms) {
    if (total_fuzzing_time_ms == 0) return 0.0f;
    return (float)g_cegar_config.stats.total_time_ms / (float)total_fuzzing_time_ms;
}
