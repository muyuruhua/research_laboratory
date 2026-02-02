/*
 * Advanced Plugin Architecture - Deep Integration with OCP Compliance
 * 深度集成的OCP兼容架构
 * 
 * 核心思想：通过策略注入和装饰器模式实现深度功能扩展
 * 而无需修改核心算法代码
 */

#ifndef AFL_ADVANCED_PLUGIN_H
#define AFL_ADVANCED_PLUGIN_H

#include <stdbool.h>
#include <stdint.h>

/* 类型定义 - 兼容AFL类型 */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* 常量定义 */
#ifndef MAP_SIZE
#define MAP_SIZE (1 << 16)
#endif

#ifndef FAULT_NONE
#define FAULT_NONE   0
#define FAULT_TMOUT  1
#define FAULT_CRASH  2
#define FAULT_ERROR  3
#endif

/* ====================================================================
 * 核心策略接口 - Strategy Pattern for Core Algorithms
 * ==================================================================== */

/* 1. 种子选择策略接口 */
typedef struct afl_seed_selection_strategy {
    const char* name;
    
    /* 策略函数指针 */
    u32 (*select_next_seed)(void* queue, u32 queued_paths);
    bool (*should_skip_seed)(void* queue_entry);
    void (*update_seed_score)(void* queue_entry, u64 exec_us, u8 fault);
    
    /* 策略特定数据 */
    void* strategy_data;
    
    /* 生命周期管理 */
    int (*init)(void** strategy_data);
    void (*cleanup)(void* strategy_data);
} afl_seed_selection_strategy_t;

/* 2. 变异策略接口 */
typedef struct afl_mutation_strategy {
    const char* name;
    
    /* 变异函数指针 */
    u32 (*mutate_buffer)(u8* buf, u32 len, u32 max_len);
    bool (*should_apply_mutation)(void* queue_entry, u32 stage);
    void (*post_mutation_feedback)(u8* buf, u32 len, u8 fault, u64 exec_us);
    
    void* strategy_data;
    int (*init)(void** strategy_data);
    void (*cleanup)(void* strategy_data);
} afl_mutation_strategy_t;

/* 3. 覆盖率分析策略接口 */
typedef struct afl_coverage_strategy {
    const char* name;
    
    /* 覆盖率分析函数 */
    bool (*has_new_coverage)(u8* trace_bits, u32 map_size);
    u32 (*calculate_coverage_score)(u8* trace_bits, u32 map_size);
    void (*update_bitmap)(u8* virgin_map, u8* trace_bits, u32 map_size);
    
    void* strategy_data;
    int (*init)(void** strategy_data);
    void (*cleanup)(void* strategy_data);
} afl_coverage_strategy_t;

/* 4. 调度策略接口 */
typedef struct afl_scheduler_strategy {
    const char* name;
    
    /* 调度决策函数 */
    u32 (*get_execution_timeout)(void* queue_entry);
    bool (*should_skip_deterministic)(void* queue_entry);
    u32 (*get_performance_score)(void* queue_entry);
    
    void* strategy_data;
    int (*init)(void** strategy_data);
    void (*cleanup)(void* strategy_data);
} afl_scheduler_strategy_t;

/* ====================================================================
 * 装饰器接口 - Decorator Pattern for Core Functions
 * ==================================================================== */

/* 执行装饰器 - 在不修改run_target的前提下增强功能 */
typedef struct afl_execution_decorator {
    const char* name;
    u32 priority; /* 0-1000, 高优先级先执行 */
    
    /* 装饰器钩子 */
    void (*pre_execution)(void* queue_entry, u8* mem, u32 len);
    void (*post_execution)(void* queue_entry, u8 fault, u64 exec_us);
    bool (*should_retry_execution)(void* queue_entry, u8 fault);
    
    void* decorator_data;
    int (*init)(void** decorator_data);
    void (*cleanup)(void* decorator_data);
} afl_execution_decorator_t;

/* 队列管理装饰器 */
typedef struct afl_queue_decorator {
    const char* name;
    u32 priority;
    
    /* 队列操作钩子 */
    bool (*before_queue_add)(u8* mem, u32 len, u8 passed_det);
    void (*after_queue_add)(void* queue_entry);
    bool (*before_queue_cull)(void* queue_entry);
    
    void* decorator_data;
    int (*init)(void** decorator_data);
    void (*cleanup)(void* decorator_data);
} afl_queue_decorator_t;

/* ====================================================================
 * 高级插件接口 - Advanced Plugin Interface
 * ==================================================================== */

typedef struct afl_advanced_plugin {
    /* 标准插件信息 */
    u32 api_version;
    const char* name;
    const char* version;
    const char* description;
    
    /* 策略提供者 - 可选实现 */
    afl_seed_selection_strategy_t* (*get_seed_strategy)(const char* config);
    afl_mutation_strategy_t* (*get_mutation_strategy)(const char* config);
    afl_coverage_strategy_t* (*get_coverage_strategy)(const char* config);
    afl_scheduler_strategy_t* (*get_scheduler_strategy)(const char* config);
    
    /* 装饰器提供者 - 可选实现 */
    afl_execution_decorator_t** (*get_execution_decorators)(int* count);
    afl_queue_decorator_t** (*get_queue_decorators)(int* count);
    
    /* 插件生命周期 */
    int (*init)(const char* config);
    void (*cleanup)(void);
    
    /* 配置接口 */
    bool (*configure)(const char* key, const char* value);
    const char* (*get_config)(const char* key);
} afl_advanced_plugin_t;

/* ====================================================================
 * 策略注册和管理 - Strategy Registration & Management
 * ==================================================================== */

/* 全局策略管理器 */
extern afl_seed_selection_strategy_t* g_seed_strategy;
extern afl_mutation_strategy_t* g_mutation_strategy;
extern afl_coverage_strategy_t* g_coverage_strategy;
extern afl_scheduler_strategy_t* g_scheduler_strategy;

/* 装饰器链管理 */
#define MAX_DECORATORS 16
extern afl_execution_decorator_t* g_execution_decorators[MAX_DECORATORS];
extern afl_queue_decorator_t* g_queue_decorators[MAX_DECORATORS];
extern int g_execution_decorator_count;
extern int g_queue_decorator_count;

/* 策略注册API */
int afl_register_seed_strategy(afl_seed_selection_strategy_t* strategy);
int afl_register_mutation_strategy(afl_mutation_strategy_t* strategy);
int afl_register_coverage_strategy(afl_coverage_strategy_t* strategy);
int afl_register_scheduler_strategy(afl_scheduler_strategy_t* strategy);

/* 装饰器注册API */
int afl_register_execution_decorator(afl_execution_decorator_t* decorator);
int afl_register_queue_decorator(afl_queue_decorator_t* decorator);

/* 策略切换API - 运行时切换 */
int afl_switch_seed_strategy(const char* strategy_name);
int afl_switch_mutation_strategy(const char* strategy_name);

/* ====================================================================
 * 深度集成宏 - Deep Integration Macros (OCP Compliant)
 * ==================================================================== */

/* 种子选择的策略注入点 */
#define AFL_SELECT_NEXT_SEED(queue, queued_paths) \
    (g_seed_strategy ? g_seed_strategy->select_next_seed(queue, queued_paths) : \
     default_select_next_seed(queue, queued_paths))

/* 变异的策略注入点 */
#define AFL_MUTATE_BUFFER(buf, len, max_len) \
    (g_mutation_strategy ? g_mutation_strategy->mutate_buffer(buf, len, max_len) : \
     default_mutate_buffer(buf, len, max_len))

/* 覆盖率分析的策略注入点 */
#define AFL_HAS_NEW_COVERAGE(trace_bits, map_size) \
    (g_coverage_strategy ? g_coverage_strategy->has_new_coverage(trace_bits, map_size) : \
     default_has_new_coverage(trace_bits, map_size))

/* 执行装饰器调用链 */
#define AFL_CALL_EXECUTION_DECORATORS_PRE(queue_entry, mem, len) \
    do { \
        for (int i = 0; i < g_execution_decorator_count; i++) { \
            if (g_execution_decorators[i] && g_execution_decorators[i]->pre_execution) { \
                g_execution_decorators[i]->pre_execution(queue_entry, mem, len); \
            } \
        } \
    } while(0)

#define AFL_CALL_EXECUTION_DECORATORS_POST(queue_entry, fault, exec_us) \
    do { \
        for (int i = 0; i < g_execution_decorator_count; i++) { \
            if (g_execution_decorators[i] && g_execution_decorators[i]->post_execution) { \
                g_execution_decorators[i]->post_execution(queue_entry, fault, exec_us); \
            } \
        } \
    } while(0)

/* ====================================================================
 * 配置驱动的策略选择 - Configuration-Driven Strategy Selection
 * ==================================================================== */

typedef struct afl_strategy_config {
    char seed_strategy_name[64];
    char seed_strategy_config[256];
    
    char mutation_strategy_name[64]; 
    char mutation_strategy_config[256];
    
    char coverage_strategy_name[64];
    char coverage_strategy_config[256];
    
    char scheduler_strategy_name[64];
    char scheduler_strategy_config[256];
    
    bool enable_execution_decorators;
    bool enable_queue_decorators;
} afl_strategy_config_t;

/* 配置加载API */
int afl_load_strategy_config(const char* config_file, afl_strategy_config_t* config);
int afl_apply_strategy_config(const afl_strategy_config_t* config);

/* ====================================================================
 * 默认实现 - Default Implementations
 * ==================================================================== */

/* 默认种子选择 - 保持原始AFL逻辑 */
u32 default_select_next_seed(void* queue, u32 queued_paths);
u32 default_mutate_buffer(u8* buf, u32 len, u32 max_len);
bool default_has_new_coverage(u8* trace_bits, u32 map_size);

#endif /* AFL_ADVANCED_PLUGIN_H */