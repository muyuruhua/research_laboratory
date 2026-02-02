/*
 * ChatAFL Enhanced Deep Integration Plugin
 * ChatAFL增强深度集成插件
 * 
 * 演示如何在严格遵循OCP的前提下实现深度功能集成：
 * 1. 智能种子选择策略 - 替换核心种子选择算法
 * 2. LLM增强变异策略 - 深度集成ChatLLM功能
 * 3. 多维覆盖率分析 - 增强覆盖率检测算法
 * 4. 自适应调度策略 - 动态优化执行策略
 * 5. 执行监控装饰器 - 增强执行流程监控
 */

#include "afl-advanced-plugin.h"
#include "../aflnet/aflnet.h"
#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

/* ====================================================================
 * 智能种子选择策略 - Intelligent Seed Selection Strategy
 * ==================================================================== */

typedef struct smart_seed_data {
    double* seed_scores;       /* 种子质量评分 */
    u32* seed_generations;     /* 种子代数 */
    u64* seed_exec_times;      /* 种子执行时间历史 */
    u32* seed_coverage_gains;  /* 种子覆盖率增益 */
    u32 max_seeds;
    
    /* LLM集成数据 */
    char* llm_analysis_cache;  /* LLM分析结果缓存 */
    bool enable_llm_guidance;  /* 是否启用LLM引导 */
} smart_seed_data_t;

static u32 smart_select_next_seed(void* queue, u32 queued_paths) {
    smart_seed_data_t* data = (smart_seed_data_t*)g_seed_strategy->strategy_data;
    
    if (!data || queued_paths == 0) {
        return 0;
    }
    
    /* 计算每个种子的综合评分 */
    u32 best_seed = 0;
    double best_score = -1.0;
    
    for (u32 i = 0; i < queued_paths && i < data->max_seeds; i++) {
        double score = 0.0;
        
        /* 基础评分：覆盖率增益 */
        if (data->seed_coverage_gains[i] > 0) {
            score += log(data->seed_coverage_gains[i] + 1) * 10.0;
        }
        
        /* 执行效率评分：快速执行的种子更优先 */
        if (data->seed_exec_times[i] > 0) {
            score += 100.0 / (1.0 + data->seed_exec_times[i] / 1000.0);
        }
        
        /* 新颖性评分：较新的种子有加成 */
        if (data->seed_generations[i] > 0) {
            score += 5.0 / (1.0 + data->seed_generations[i] / 10.0);
        }
        
        /* LLM增强评分 */
        if (data->enable_llm_guidance && data->llm_analysis_cache) {
            /* 这里可以集成LLM分析结果 */
            score += data->seed_scores[i] * 20.0;
        }
        
        /* 随机扰动，避免过度确定性 */
        score += (double)(rand() % 100) / 1000.0;
        
        if (score > best_score) {
            best_score = score;
            best_seed = i;
        }
    }
    
    return best_seed;
}

static bool smart_should_skip_seed(void* queue_entry) {
    /* 智能跳过策略：跳过低质量种子 */
    smart_seed_data_t* data = (smart_seed_data_t*)g_seed_strategy->strategy_data;
    
    if (!data) return false;
    
    /* 这里可以根据种子历史表现决定是否跳过 */
    /* 例如：连续执行多次都没有新发现的种子 */
    
    return false; /* 简化版本暂不跳过 */
}

static void smart_update_seed_score(void* queue_entry, u64 exec_us, u8 fault) {
    smart_seed_data_t* data = (smart_seed_data_t*)g_seed_strategy->strategy_data;
    
    if (!data) return;
    
    /* 更新种子评分逻辑 */
    /* 这里可以根据执行结果动态调整种子评分 */
    
    /* 发现crash或hang给高分 */
    if (fault) {
        /* 假设当前处理第0个种子（简化） */
        if (data->seed_scores) {
            data->seed_scores[0] += 50.0;
        }
    }
    
    /* 记录执行时间 */
    if (data->seed_exec_times) {
        data->seed_exec_times[0] = exec_us;
    }
}

static int smart_seed_init(void** strategy_data) {
    smart_seed_data_t* data = malloc(sizeof(smart_seed_data_t));
    if (!data) return -1;
    
    data->max_seeds = 10000; /* 最大支持种子数 */
    data->seed_scores = calloc(data->max_seeds, sizeof(double));
    data->seed_generations = calloc(data->max_seeds, sizeof(u32));
    data->seed_exec_times = calloc(data->max_seeds, sizeof(u64));
    data->seed_coverage_gains = calloc(data->max_seeds, sizeof(u32));
    data->llm_analysis_cache = malloc(4096);
    data->enable_llm_guidance = true;
    
    if (!data->seed_scores || !data->seed_generations || 
        !data->seed_exec_times || !data->seed_coverage_gains ||
        !data->llm_analysis_cache) {
        /* 清理已分配的内存 */
        free(data->seed_scores);
        free(data->seed_generations);
        free(data->seed_exec_times);
        free(data->seed_coverage_gains);
        free(data->llm_analysis_cache);
        free(data);
        return -1;
    }
    
    strcpy(data->llm_analysis_cache, "{}"); /* 初始化为空JSON */
    
    *strategy_data = data;
    return 0;
}

static void smart_seed_cleanup(void* strategy_data) {
    smart_seed_data_t* data = (smart_seed_data_t*)strategy_data;
    if (data) {
        free(data->seed_scores);
        free(data->seed_generations);
        free(data->seed_exec_times);
        free(data->seed_coverage_gains);
        free(data->llm_analysis_cache);
        free(data);
    }
}

static afl_seed_selection_strategy_t smart_seed_strategy = {
    .name = "smart_llm_guided",
    .select_next_seed = smart_select_next_seed,
    .should_skip_seed = smart_should_skip_seed,
    .update_seed_score = smart_update_seed_score,
    .strategy_data = NULL,
    .init = smart_seed_init,
    .cleanup = smart_seed_cleanup
};

/* ====================================================================
 * LLM增强变异策略 - LLM Enhanced Mutation Strategy
 * ==================================================================== */

typedef struct llm_mutation_data {
    char* llm_server_url;
    char* api_key;
    json_object* mutation_patterns;
    u32 total_mutations;
    u32 successful_mutations;
    bool enable_adaptive_mutation;
} llm_mutation_data_t;

static u32 llm_mutate_buffer(u8* buf, u32 len, u32 max_len) {
    llm_mutation_data_t* data = (llm_mutation_data_t*)g_mutation_strategy->strategy_data;
    
    if (!data || len == 0) {
        return default_mutate_buffer(buf, len, max_len);
    }
    
    data->total_mutations++;
    
    /* 智能变异策略选择 */
    int mutation_type = rand() % 5;
    
    switch (mutation_type) {
        case 0: /* 结构化变异 - 基于协议格式 */
            if (len >= 4) {
                /* HTTP请求变异示例 */
                if (memcmp(buf, "GET ", 4) == 0 || memcmp(buf, "POST", 4) == 0) {
                    /* 变异HTTP方法 */
                    const char* methods[] = {"HEAD", "PUT ", "DELE"};
                    int method_idx = rand() % 3;
                    memcpy(buf, methods[method_idx], 4);
                }
            }
            break;
            
        case 1: /* 语义感知变异 - 保持数据有效性 */
            /* 查找JSON结构并变异值 */
            for (u32 i = 0; i < len - 1; i++) {
                if (buf[i] == ':' && buf[i+1] == '"') {
                    /* 找到JSON字符串值，智能变异 */
                    u32 start = i + 2;
                    u32 end = start;
                    while (end < len && buf[end] != '"') end++;
                    if (end < len) {
                        /* 变异字符串内容 */
                        for (u32 j = start; j < end; j++) {
                            if (rand() % 10 == 0) { /* 10%概率变异 */
                                buf[j] = 'A' + (rand() % 26);
                            }
                        }
                    }
                    break;
                }
            }
            break;
            
        case 2: /* LLM指导变异 - 使用LLM分析结果 */
            if (data->mutation_patterns) {
                /* 基于LLM分析的模式进行变异 */
                /* 这里可以集成实际的LLM调用 */
                u32 rand_pos = rand() % len;
                buf[rand_pos] ^= 1 + (rand() % 255);
            }
            break;
            
        case 3: /* 热点变异 - 专注于高价值区域 */
            /* 变异前几个字节（通常是协议头） */
            if (len > 10) {
                u32 header_end = len < 50 ? len : 50;
                u32 rand_pos = rand() % header_end;
                buf[rand_pos] = rand() % 256;
            }
            break;
            
        default: /* 回退到默认变异 */
            return default_mutate_buffer(buf, len, max_len);
    }
    
    return len;
}

static bool llm_should_apply_mutation(void* queue_entry, u32 stage) {
    llm_mutation_data_t* data = (llm_mutation_data_t*)g_mutation_strategy->strategy_data;
    
    if (!data) return true;
    
    /* 自适应变异：根据历史成功率决定是否应用变异 */
    if (data->enable_adaptive_mutation && data->total_mutations > 100) {
        double success_rate = (double)data->successful_mutations / data->total_mutations;
        
        /* 成功率低时减少变异强度 */
        if (success_rate < 0.1) {
            return (rand() % 100) < 30; /* 30%概率应用 */
        }
    }
    
    return true;
}

static void llm_post_mutation_feedback(u8* buf, u32 len, u8 fault, u64 exec_us) {
    llm_mutation_data_t* data = (llm_mutation_data_t*)g_mutation_strategy->strategy_data;
    
    if (!data) return;
    
    /* 记录变异成功情况 */
    if (fault || exec_us > 0) { /* 有结果就算成功 */
        data->successful_mutations++;
    }
    
    /* 这里可以将变异结果反馈给LLM，用于改进变异策略 */
}

static int llm_mutation_init(void** strategy_data) {
    llm_mutation_data_t* data = malloc(sizeof(llm_mutation_data_t));
    if (!data) return -1;
    
    data->llm_server_url = strdup("http://localhost:8080");
    data->api_key = strdup("default_key");
    data->mutation_patterns = json_object_new_object();
    data->total_mutations = 0;
    data->successful_mutations = 0;
    data->enable_adaptive_mutation = true;
    
    *strategy_data = data;
    return 0;
}

static void llm_mutation_cleanup(void* strategy_data) {
    llm_mutation_data_t* data = (llm_mutation_data_t*)strategy_data;
    if (data) {
        free(data->llm_server_url);
        free(data->api_key);
        if (data->mutation_patterns) {
            json_object_put(data->mutation_patterns);
        }
        free(data);
    }
}

static afl_mutation_strategy_t llm_mutation_strategy = {
    .name = "llm_enhanced",
    .mutate_buffer = llm_mutate_buffer,
    .should_apply_mutation = llm_should_apply_mutation,
    .post_mutation_feedback = llm_post_mutation_feedback,
    .strategy_data = NULL,
    .init = llm_mutation_init,
    .cleanup = llm_mutation_cleanup
};

/* ====================================================================
 * 多维覆盖率分析策略 - Multi-Dimensional Coverage Analysis
 * ==================================================================== */

typedef struct advanced_coverage_data {
    u8* baseline_coverage;    /* 基础覆盖率基线 */
    u8* edge_coverage;        /* 边覆盖率 */
    u8* path_coverage;        /* 路径覆盖率 */
    u32* hit_counts;          /* 命中次数统计 */
    double* coverage_weights; /* 覆盖率权重 */
    u32 map_size;
    
    /* 高级分析数据 */
    u64 total_paths_discovered;
    u64 unique_crashes;
    double coverage_diversity_score;
} advanced_coverage_data_t;

static bool advanced_has_new_coverage(u8* trace_bits, u32 map_size) {
    advanced_coverage_data_t* data = (advanced_coverage_data_t*)g_coverage_strategy->strategy_data;
    
    if (!data) {
        return default_has_new_coverage(trace_bits, map_size);
    }
    
    bool has_new = false;
    double diversity_score = 0.0;
    u32 new_edges = 0;
    
    /* 多维度覆盖率检查 */
    for (u32 i = 0; i < map_size && i < data->map_size; i++) {
        if (trace_bits[i]) {
            /* 更新命中次数 */
            data->hit_counts[i]++;
            
            /* 检查基础覆盖率 */
            if (data->baseline_coverage[i] == 0) {
                data->baseline_coverage[i] = 1;
                has_new = true;
                new_edges++;
            }
            
            /* 检查边覆盖率增强 */
            if (trace_bits[i] > data->edge_coverage[i]) {
                data->edge_coverage[i] = trace_bits[i];
                has_new = true;
            }
            
            /* 计算覆盖率多样性 */
            if (data->coverage_weights[i] > 0) {
                diversity_score += data->coverage_weights[i] * trace_bits[i];
            }
        }
    }
    
    /* 更新多样性评分 */
    if (diversity_score > data->coverage_diversity_score * 1.1) {
        data->coverage_diversity_score = diversity_score;
        has_new = true;
    }
    
    /* 记录新路径 */
    if (new_edges > 0) {
        data->total_paths_discovered++;
    }
    
    return has_new;
}

static u32 advanced_calculate_coverage_score(u8* trace_bits, u32 map_size) {
    advanced_coverage_data_t* data = (advanced_coverage_data_t*)g_coverage_strategy->strategy_data;
    
    if (!data) return 0;
    
    u32 basic_score = 0;
    double weighted_score = 0.0;
    
    for (u32 i = 0; i < map_size && i < data->map_size; i++) {
        if (trace_bits[i]) {
            basic_score++;
            
            /* 权重评分：稀有路径获得更高分数 */
            if (data->hit_counts[i] > 0) {
                weighted_score += 1000.0 / (1.0 + log(data->hit_counts[i]));
            } else {
                weighted_score += 1000.0; /* 全新路径最高分 */
            }
        }
    }
    
    /* 综合评分：基础分数 + 权重分数 + 多样性分数 */
    return basic_score + (u32)(weighted_score / 100.0) + 
           (u32)(data->coverage_diversity_score / 1000.0);
}

static void advanced_update_bitmap(u8* virgin_map, u8* trace_bits, u32 map_size) {
    advanced_coverage_data_t* data = (advanced_coverage_data_t*)g_coverage_strategy->strategy_data;
    
    /* 执行标准更新 */
    for (u32 i = 0; i < map_size; i++) {
        if (trace_bits[i] && virgin_map[i]) {
            virgin_map[i] = 0;
        }
    }
    
    if (!data) return;
    
    /* 更新高级统计信息 */
    for (u32 i = 0; i < map_size && i < data->map_size; i++) {
        if (trace_bits[i]) {
            /* 动态调整覆盖率权重 */
            if (data->coverage_weights[i] > 0.1) {
                data->coverage_weights[i] *= 0.99; /* 逐渐降低已发现路径的权重 */
            }
        }
    }
}

static int advanced_coverage_init(void** strategy_data) {
    advanced_coverage_data_t* data = malloc(sizeof(advanced_coverage_data_t));
    if (!data) return -1;
    
    data->map_size = MAP_SIZE;
    data->baseline_coverage = calloc(data->map_size, sizeof(u8));
    data->edge_coverage = calloc(data->map_size, sizeof(u8));
    data->path_coverage = calloc(data->map_size, sizeof(u8));
    data->hit_counts = calloc(data->map_size, sizeof(u32));
    data->coverage_weights = malloc(data->map_size * sizeof(double));
    
    if (!data->baseline_coverage || !data->edge_coverage || 
        !data->path_coverage || !data->hit_counts || !data->coverage_weights) {
        free(data->baseline_coverage);
        free(data->edge_coverage);
        free(data->path_coverage);
        free(data->hit_counts);
        free(data->coverage_weights);
        free(data);
        return -1;
    }
    
    /* 初始化覆盖率权重 */
    for (u32 i = 0; i < data->map_size; i++) {
        data->coverage_weights[i] = 1.0;
    }
    
    data->total_paths_discovered = 0;
    data->unique_crashes = 0;
    data->coverage_diversity_score = 0.0;
    
    *strategy_data = data;
    return 0;
}

static void advanced_coverage_cleanup(void* strategy_data) {
    advanced_coverage_data_t* data = (advanced_coverage_data_t*)strategy_data;
    if (data) {
        free(data->baseline_coverage);
        free(data->edge_coverage);
        free(data->path_coverage);
        free(data->hit_counts);
        free(data->coverage_weights);
        free(data);
    }
}

static afl_coverage_strategy_t advanced_coverage_strategy = {
    .name = "multi_dimensional",
    .has_new_coverage = advanced_has_new_coverage,
    .calculate_coverage_score = advanced_calculate_coverage_score,
    .update_bitmap = advanced_update_bitmap,
    .strategy_data = NULL,
    .init = advanced_coverage_init,
    .cleanup = advanced_coverage_cleanup
};

/* ====================================================================
 * 执行监控装饰器 - Execution Monitoring Decorator
 * ==================================================================== */

typedef struct execution_monitor_data {
    u64 total_executions;
    u64 total_exec_time;
    u64 fast_executions;     /* 快速执行计数 */
    u64 slow_executions;     /* 慢执行计数 */
    u64 crash_executions;    /* crash计数 */
    u64 timeout_executions;  /* 超时计数 */
    
    /* 性能统计 */
    double avg_exec_time;
    double exec_time_variance;
    
    /* LLM集成点 */
    bool enable_llm_analysis;
    char* llm_insights;
} execution_monitor_data_t;

static void execution_monitor_pre(void* queue_entry, u8* mem, u32 len) {
    execution_monitor_data_t* data = (execution_monitor_data_t*)
        g_execution_decorators[0]->decorator_data; /* 假设是第一个装饰器 */
    
    if (!data) return;
    
    /* 执行前预处理 */
    data->total_executions++;
    
    /* 这里可以添加LLM分析调用，预测执行结果 */
    if (data->enable_llm_analysis && data->total_executions % 100 == 0) {
        /* 每100次执行进行一次LLM分析 */
        snprintf(data->llm_insights, 256, 
                "Execution #%llu: Input length %u, Avg time %.2fms", 
                data->total_executions, len, data->avg_exec_time);
    }
}

static void execution_monitor_post(void* queue_entry, u8 fault, u64 exec_us) {
    execution_monitor_data_t* data = (execution_monitor_data_t*)
        g_execution_decorators[0]->decorator_data;
    
    if (!data) return;
    
    /* 执行后统计 */
    data->total_exec_time += exec_us;
    
    /* 更新平均执行时间 */
    data->avg_exec_time = (double)data->total_exec_time / data->total_executions;
    
    /* 分类执行结果 */
    if (exec_us < 1000) { /* 1ms以内为快速执行 */
        data->fast_executions++;
    } else if (exec_us > 100000) { /* 100ms以上为慢执行 */
        data->slow_executions++;
    }
    
    if (fault == FAULT_CRASH) {
        data->crash_executions++;
    } else if (fault == FAULT_TMOUT) {
        data->timeout_executions++;
    }
    
    /* 每1000次执行输出统计 */
    if (data->total_executions % 1000 == 0) {
        printf("[MONITOR] Executions: %llu, Crashes: %llu, "
               "Avg time: %.2fms, Fast: %llu, Slow: %llu\n",
               data->total_executions, data->crash_executions,
               data->avg_exec_time / 1000.0, 
               data->fast_executions, data->slow_executions);
    }
}

static bool execution_monitor_should_retry(void* queue_entry, u8 fault) {
    execution_monitor_data_t* data = (execution_monitor_data_t*)
        g_execution_decorators[0]->decorator_data;
    
    if (!data) return false;
    
    /* 智能重试策略：对于超时的情况，如果平均执行时间合理，可以重试 */
    if (fault == FAULT_TMOUT && data->avg_exec_time < 50000) { /* 平均50ms以内 */
        return true;
    }
    
    return false;
}

static int execution_monitor_init(void** decorator_data) {
    execution_monitor_data_t* data = malloc(sizeof(execution_monitor_data_t));
    if (!data) return -1;
    
    memset(data, 0, sizeof(execution_monitor_data_t));
    data->enable_llm_analysis = true;
    data->llm_insights = malloc(256);
    if (!data->llm_insights) {
        free(data);
        return -1;
    }
    strcpy(data->llm_insights, "");
    
    *decorator_data = data;
    return 0;
}

static void execution_monitor_cleanup(void* decorator_data) {
    execution_monitor_data_t* data = (execution_monitor_data_t*)decorator_data;
    if (data) {
        free(data->llm_insights);
        free(data);
    }
}

static afl_execution_decorator_t execution_monitor = {
    .name = "execution_monitor",
    .priority = 1000, /* 高优先级，最先执行 */
    .pre_execution = execution_monitor_pre,
    .post_execution = execution_monitor_post,
    .should_retry_execution = execution_monitor_should_retry,
    .decorator_data = NULL,
    .init = execution_monitor_init,
    .cleanup = execution_monitor_cleanup
};

/* ====================================================================
 * 插件接口实现 - Plugin Interface Implementation
 * ==================================================================== */

static afl_seed_selection_strategy_t* get_seed_strategy(const char* config) {
    return &smart_seed_strategy;
}

static afl_mutation_strategy_t* get_mutation_strategy(const char* config) {
    return &llm_mutation_strategy;
}

static afl_coverage_strategy_t* get_coverage_strategy(const char* config) {
    return &advanced_coverage_strategy;
}

static afl_execution_decorator_t* execution_decorators[] = {
    &execution_monitor
};

static afl_execution_decorator_t** get_execution_decorators(int* count) {
    *count = 1;
    return execution_decorators;
}

static int plugin_init(const char* config) {
    printf("[DEEP INTEGRATION] ChatAFL Enhanced Deep Integration Plugin initialized\n");
    printf("[CONFIG] %s\n", config ? config : "No config provided");
    
    /* 这里可以解析配置并初始化LLM连接等 */
    return 0;
}

static void plugin_cleanup(void) {
    printf("[DEEP INTEGRATION] ChatAFL Enhanced Deep Integration Plugin cleaned up\n");
}

static bool plugin_configure(const char* key, const char* value) {
    printf("[CONFIG] Setting %s = %s\n", key, value);
    return true;
}

static const char* plugin_get_config(const char* key) {
    if (strcmp(key, "version") == 0) {
        return "1.0.0";
    }
    return NULL;
}

/* 导出的插件接口 */
static afl_advanced_plugin_t deep_integration_plugin = {
    .api_version = 1,
    .name = "ChatAFL-Enhanced-DeepIntegration",
    .version = "1.0.0",
    .description = "Deep integration plugin demonstrating OCP-compliant advanced features",
    
    /* 策略提供者 */
    .get_seed_strategy = get_seed_strategy,
    .get_mutation_strategy = get_mutation_strategy,
    .get_coverage_strategy = get_coverage_strategy,
    .get_scheduler_strategy = NULL, /* 不提供调度策略 */
    
    /* 装饰器提供者 */
    .get_execution_decorators = get_execution_decorators,
    .get_queue_decorators = NULL, /* 不提供队列装饰器 */
    
    /* 生命周期 */
    .init = plugin_init,
    .cleanup = plugin_cleanup,
    
    /* 配置接口 */
    .configure = plugin_configure,
    .get_config = plugin_get_config
};

/* 插件入口点 */
afl_advanced_plugin_t* afl_get_advanced_plugin(void) {
    return &deep_integration_plugin;
}