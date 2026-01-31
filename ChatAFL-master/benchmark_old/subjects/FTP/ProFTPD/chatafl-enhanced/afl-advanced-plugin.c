/*
 * Advanced Plugin Strategy Manager - Deep Integration Implementation
 * 深度集成策略管理器实现
 * 
 * 关键特性：
 * 1. 零侵入核心代码 - 通过宏定义和函数指针实现策略注入
 * 2. 运行时策略切换 - 动态算法替换
 * 3. 装饰器链模式 - 功能增强而不修改原始逻辑
 */

#include "afl-advanced-plugin.h"
#include "../aflnet/aflnet.h"
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ====================================================================
 * 全局策略实例 - Global Strategy Instances
 * ==================================================================== */

/* 活跃策略指针 */
afl_seed_selection_strategy_t* g_seed_strategy = NULL;
afl_mutation_strategy_t* g_mutation_strategy = NULL;
afl_coverage_strategy_t* g_coverage_strategy = NULL;
afl_scheduler_strategy_t* g_scheduler_strategy = NULL;

/* 装饰器链 */
afl_execution_decorator_t* g_execution_decorators[MAX_DECORATORS];
afl_queue_decorator_t* g_queue_decorators[MAX_DECORATORS];
int g_execution_decorator_count = 0;
int g_queue_decorator_count = 0;

/* 注册的策略表 */
#define MAX_STRATEGIES 32
static afl_seed_selection_strategy_t* seed_strategies[MAX_STRATEGIES];
static afl_mutation_strategy_t* mutation_strategies[MAX_STRATEGIES];
static afl_coverage_strategy_t* coverage_strategies[MAX_STRATEGIES];
static afl_scheduler_strategy_t* scheduler_strategies[MAX_STRATEGIES];

static int seed_strategy_count = 0;
static int mutation_strategy_count = 0;
static int coverage_strategy_count = 0;
static int scheduler_strategy_count = 0;

/* ====================================================================
 * 策略注册实现 - Strategy Registration Implementation
 * ==================================================================== */

int afl_register_seed_strategy(afl_seed_selection_strategy_t* strategy) {
    if (!strategy || seed_strategy_count >= MAX_STRATEGIES) {
        return -1;
    }
    
    /* 初始化策略 */
    if (strategy->init && strategy->init(&strategy->strategy_data) != 0) {
        return -1;
    }
    
    seed_strategies[seed_strategy_count++] = strategy;
    
    /* 如果没有活跃策略，设置为默认 */
    if (!g_seed_strategy) {
        g_seed_strategy = strategy;
    }
    
    printf("[STRATEGY] Registered seed selection strategy: %s\n", strategy->name);
    return 0;
}

int afl_register_mutation_strategy(afl_mutation_strategy_t* strategy) {
    if (!strategy || mutation_strategy_count >= MAX_STRATEGIES) {
        return -1;
    }
    
    if (strategy->init && strategy->init(&strategy->strategy_data) != 0) {
        return -1;
    }
    
    mutation_strategies[mutation_strategy_count++] = strategy;
    
    if (!g_mutation_strategy) {
        g_mutation_strategy = strategy;
    }
    
    printf("[STRATEGY] Registered mutation strategy: %s\n", strategy->name);
    return 0;
}

int afl_register_coverage_strategy(afl_coverage_strategy_t* strategy) {
    if (!strategy || coverage_strategy_count >= MAX_STRATEGIES) {
        return -1;
    }
    
    if (strategy->init && strategy->init(&strategy->strategy_data) != 0) {
        return -1;
    }
    
    coverage_strategies[coverage_strategy_count++] = strategy;
    
    if (!g_coverage_strategy) {
        g_coverage_strategy = strategy;
    }
    
    printf("[STRATEGY] Registered coverage strategy: %s\n", strategy->name);
    return 0;
}

int afl_register_scheduler_strategy(afl_scheduler_strategy_t* strategy) {
    if (!strategy || scheduler_strategy_count >= MAX_STRATEGIES) {
        return -1;
    }
    
    if (strategy->init && strategy->init(&strategy->strategy_data) != 0) {
        return -1;
    }
    
    scheduler_strategies[scheduler_strategy_count++] = strategy;
    
    if (!g_scheduler_strategy) {
        g_scheduler_strategy = strategy;
    }
    
    printf("[STRATEGY] Registered scheduler strategy: %s\n", strategy->name);
    return 0;
}

/* ====================================================================
 * 装饰器注册实现 - Decorator Registration Implementation
 * ==================================================================== */

static int compare_decorator_priority(const void* a, const void* b) {
    afl_execution_decorator_t* dec_a = *(afl_execution_decorator_t**)a;
    afl_execution_decorator_t* dec_b = *(afl_execution_decorator_t**)b;
    return dec_b->priority - dec_a->priority; /* 高优先级在前 */
}

int afl_register_execution_decorator(afl_execution_decorator_t* decorator) {
    if (!decorator || g_execution_decorator_count >= MAX_DECORATORS) {
        return -1;
    }
    
    if (decorator->init && decorator->init(&decorator->decorator_data) != 0) {
        return -1;
    }
    
    g_execution_decorators[g_execution_decorator_count++] = decorator;
    
    /* 按优先级排序 */
    qsort(g_execution_decorators, g_execution_decorator_count, 
          sizeof(afl_execution_decorator_t*), compare_decorator_priority);
    
    printf("[DECORATOR] Registered execution decorator: %s (priority: %u)\n", 
           decorator->name, decorator->priority);
    return 0;
}

int afl_register_queue_decorator(afl_queue_decorator_t* decorator) {
    if (!decorator || g_queue_decorator_count >= MAX_DECORATORS) {
        return -1;
    }
    
    if (decorator->init && decorator->init(&decorator->decorator_data) != 0) {
        return -1;
    }
    
    g_queue_decorators[g_queue_decorator_count++] = decorator;
    
    printf("[DECORATOR] Registered queue decorator: %s (priority: %u)\n", 
           decorator->name, decorator->priority);
    return 0;
}

/* ====================================================================
 * 运行时策略切换 - Runtime Strategy Switching
 * ==================================================================== */

int afl_switch_seed_strategy(const char* strategy_name) {
    for (int i = 0; i < seed_strategy_count; i++) {
        if (strcmp(seed_strategies[i]->name, strategy_name) == 0) {
            g_seed_strategy = seed_strategies[i];
            printf("[STRATEGY] Switched to seed strategy: %s\n", strategy_name);
            return 0;
        }
    }
    return -1;
}

int afl_switch_mutation_strategy(const char* strategy_name) {
    for (int i = 0; i < mutation_strategy_count; i++) {
        if (strcmp(mutation_strategies[i]->name, strategy_name) == 0) {
            g_mutation_strategy = mutation_strategies[i];
            printf("[STRATEGY] Switched to mutation strategy: %s\n", strategy_name);
            return 0;
        }
    }
    return -1;
}

/* ====================================================================
 * 默认实现 - Default Implementations (保持原始AFL逻辑)
 * ==================================================================== */

u32 default_select_next_seed(void* queue, u32 queued_paths) {
    /* 原始AFL的种子选择逻辑 - 保持不变 */
    static u32 current_entry = 0;
    return (current_entry++) % queued_paths;
}

u32 default_mutate_buffer(u8* buf, u32 len, u32 max_len) {
    /* 原始AFL的变异逻辑 - 简化版本 */
    if (len == 0) return 0;
    
    u32 rand_pos = rand() % len;
    buf[rand_pos] ^= 1 + (rand() % 255);
    
    return len;
}

bool default_has_new_coverage(u8* trace_bits, u32 map_size) {
    /* 原始AFL的覆盖率检查逻辑 - 简化版本 */
    static u8 virgin_bits[MAP_SIZE];
    static bool virgin_init = false;
    
    if (!virgin_init) {
        memset(virgin_bits, 255, MAP_SIZE);
        virgin_init = true;
    }
    
    bool has_new = false;
    for (u32 i = 0; i < map_size; i++) {
        if (trace_bits[i] && virgin_bits[i]) {
            virgin_bits[i] = 0;
            has_new = true;
        }
    }
    
    return has_new;
}

/* ====================================================================
 * 高级插件加载器 - Advanced Plugin Loader
 * ==================================================================== */

typedef struct loaded_advanced_plugin {
    void* handle;
    afl_advanced_plugin_t* plugin;
    char* path;
} loaded_advanced_plugin_t;

#define MAX_LOADED_PLUGINS 16
static loaded_advanced_plugin_t loaded_plugins[MAX_LOADED_PLUGINS];
static int loaded_plugin_count = 0;

int afl_load_advanced_plugin(const char* plugin_path, const char* config) {
    if (loaded_plugin_count >= MAX_LOADED_PLUGINS) {
        printf("[ERROR] Maximum number of plugins (%d) already loaded\n", MAX_LOADED_PLUGINS);
        return -1;
    }
    
    /* 加载动态库 */
    void* handle = dlopen(plugin_path, RTLD_LAZY);
    if (!handle) {
        printf("[ERROR] Cannot load plugin %s: %s\n", plugin_path, dlerror());
        return -1;
    }
    
    /* 获取插件接口 */
    afl_advanced_plugin_t* (*get_plugin)(void) = dlsym(handle, "afl_get_advanced_plugin");
    if (!get_plugin) {
        printf("[ERROR] Plugin %s missing afl_get_advanced_plugin function\n", plugin_path);
        dlclose(handle);
        return -1;
    }
    
    afl_advanced_plugin_t* plugin = get_plugin();
    if (!plugin) {
        printf("[ERROR] Plugin %s returned NULL interface\n", plugin_path);
        dlclose(handle);
        return -1;
    }
    
    /* 初始化插件 */
    if (plugin->init && plugin->init(config) != 0) {
        printf("[ERROR] Plugin %s initialization failed\n", plugin_path);
        dlclose(handle);
        return -1;
    }
    
    /* 注册策略 */
    if (plugin->get_seed_strategy) {
        afl_seed_selection_strategy_t* strategy = plugin->get_seed_strategy(config);
        if (strategy) {
            afl_register_seed_strategy(strategy);
        }
    }
    
    if (plugin->get_mutation_strategy) {
        afl_mutation_strategy_t* strategy = plugin->get_mutation_strategy(config);
        if (strategy) {
            afl_register_mutation_strategy(strategy);
        }
    }
    
    if (plugin->get_coverage_strategy) {
        afl_coverage_strategy_t* strategy = plugin->get_coverage_strategy(config);
        if (strategy) {
            afl_register_coverage_strategy(strategy);
        }
    }
    
    if (plugin->get_scheduler_strategy) {
        afl_scheduler_strategy_t* strategy = plugin->get_scheduler_strategy(config);
        if (strategy) {
            afl_register_scheduler_strategy(strategy);
        }
    }
    
    /* 注册装饰器 */
    if (plugin->get_execution_decorators) {
        int decorator_count = 0;
        afl_execution_decorator_t** decorators = plugin->get_execution_decorators(&decorator_count);
        for (int i = 0; i < decorator_count; i++) {
            afl_register_execution_decorator(decorators[i]);
        }
    }
    
    if (plugin->get_queue_decorators) {
        int decorator_count = 0;
        afl_queue_decorator_t** decorators = plugin->get_queue_decorators(&decorator_count);
        for (int i = 0; i < decorator_count; i++) {
            afl_register_queue_decorator(decorators[i]);
        }
    }
    
    /* 保存插件信息 */
    loaded_plugins[loaded_plugin_count].handle = handle;
    loaded_plugins[loaded_plugin_count].plugin = plugin;
    loaded_plugins[loaded_plugin_count].path = strdup(plugin_path);
    loaded_plugin_count++;
    
    printf("[PLUGIN] Successfully loaded advanced plugin: %s (%s)\n", 
           plugin->name, plugin->version);
    return 0;
}

/* ====================================================================
 * 配置驱动的策略管理 - Configuration-Driven Strategy Management
 * ==================================================================== */

int afl_load_strategy_config(const char* config_file, afl_strategy_config_t* config) {
    FILE* fp = fopen(config_file, "r");
    if (!fp) {
        printf("[WARNING] Cannot open strategy config file: %s\n", config_file);
        return -1;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char key[128], value[256];
        if (sscanf(line, "%127[^=]=%255s", key, value) == 2) {
            if (strcmp(key, "seed_strategy") == 0) {
                strncpy(config->seed_strategy_name, value, 63);
            } else if (strcmp(key, "mutation_strategy") == 0) {
                strncpy(config->mutation_strategy_name, value, 63);
            } else if (strcmp(key, "coverage_strategy") == 0) {
                strncpy(config->coverage_strategy_name, value, 63);
            } else if (strcmp(key, "scheduler_strategy") == 0) {
                strncpy(config->scheduler_strategy_name, value, 63);
            }
        }
    }
    
    fclose(fp);
    printf("[CONFIG] Loaded strategy configuration from %s\n", config_file);
    return 0;
}

int afl_apply_strategy_config(const afl_strategy_config_t* config) {
    int success_count = 0;
    
    if (strlen(config->seed_strategy_name) > 0) {
        if (afl_switch_seed_strategy(config->seed_strategy_name) == 0) {
            success_count++;
        }
    }
    
    if (strlen(config->mutation_strategy_name) > 0) {
        if (afl_switch_mutation_strategy(config->mutation_strategy_name) == 0) {
            success_count++;
        }
    }
    
    printf("[CONFIG] Applied %d strategy configurations\n", success_count);
    return success_count;
}

/* ====================================================================
 * 插件系统清理 - Plugin System Cleanup
 * ==================================================================== */

void afl_cleanup_advanced_plugins(void) {
    /* 清理装饰器 */
    for (int i = 0; i < g_execution_decorator_count; i++) {
        if (g_execution_decorators[i] && g_execution_decorators[i]->cleanup) {
            g_execution_decorators[i]->cleanup(g_execution_decorators[i]->decorator_data);
        }
    }
    
    for (int i = 0; i < g_queue_decorator_count; i++) {
        if (g_queue_decorators[i] && g_queue_decorators[i]->cleanup) {
            g_queue_decorators[i]->cleanup(g_queue_decorators[i]->decorator_data);
        }
    }
    
    /* 清理策略 */
    for (int i = 0; i < seed_strategy_count; i++) {
        if (seed_strategies[i] && seed_strategies[i]->cleanup) {
            seed_strategies[i]->cleanup(seed_strategies[i]->strategy_data);
        }
    }
    
    /* 清理插件 */
    for (int i = 0; i < loaded_plugin_count; i++) {
        if (loaded_plugins[i].plugin && loaded_plugins[i].plugin->cleanup) {
            loaded_plugins[i].plugin->cleanup();
        }
        if (loaded_plugins[i].handle) {
            dlclose(loaded_plugins[i].handle);
        }
        if (loaded_plugins[i].path) {
            free(loaded_plugins[i].path);
        }
    }
    
    printf("[CLEANUP] Advanced plugin system cleaned up\n");
}