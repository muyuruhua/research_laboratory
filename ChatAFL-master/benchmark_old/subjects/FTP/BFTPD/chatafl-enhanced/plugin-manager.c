/*
 * plugin-manager.c - ChatAFL Plugin Manager Implementation
 * 
 * Manages plugin lifecycle, registration, and hook invocation.
 * This is the core of the plugin system.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include "plugin-interface.h"
#include "alloc-inl.h"
#include "debug.h"

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static u64 plugin_get_cur_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

static u64 plugin_get_cur_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/* Maximum number of plugins */
#define MAX_PLUGINS 32

/* Plugin registry */
static plugin_t *g_plugins[MAX_PLUGINS];
static int g_plugin_count = 0;
static bool g_plugins_initialized = false;

/* Fuzzer context (opaque pointer to fuzzer state) */
static void *g_fuzzer_ctx = NULL;

/* Statistics tracking */
static u64 g_hook_invocations[HOOK_MAX] = {0};

/* ============================================================================
 * INTERNAL HELPER FUNCTIONS
 * ============================================================================ */

/**
 * Find plugin index by name
 */
static int find_plugin_index(const char *name) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i] && strcmp(g_plugins[i]->ops.name, name) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Compare plugins by priority (for sorting)
 */
static int compare_plugin_priority(const void *a, const void *b) {
    const plugin_t *pa = *(const plugin_t **)a;
    const plugin_t *pb = *(const plugin_t **)b;
    
    if (!pa) return 1;
    if (!pb) return -1;
    
    // Higher priority comes first
    return pb->ops.priority - pa->ops.priority;
}

/**
 * Sort plugins by priority
 */
static void sort_plugins_by_priority(void) {
    qsort(g_plugins, g_plugin_count, sizeof(plugin_t *), compare_plugin_priority);
}

/* ============================================================================
 * PLUGIN REGISTRY API IMPLEMENTATION
 * ============================================================================ */

plugin_t* plugin_register(const plugin_ops_t *ops) {
    if (!ops || !ops->name) {
        WARNF("Cannot register plugin: invalid ops structure");
        return NULL;
    }
    
    if (g_plugin_count >= MAX_PLUGINS) {
        WARNF("Cannot register plugin '%s': registry full", ops->name);
        return NULL;
    }
    
    // Check for duplicate names
    if (find_plugin_index(ops->name) >= 0) {
        WARNF("Plugin '%s' already registered", ops->name);
        return NULL;
    }
    
    // Allocate plugin structure
    plugin_t *plugin = ck_alloc(sizeof(plugin_t));
    memset(plugin, 0, sizeof(plugin_t));
    
    // Copy operations
    memcpy(&plugin->ops, ops, sizeof(plugin_ops_t));
    
    // Add to registry
    g_plugins[g_plugin_count++] = plugin;
    
    // Sort by priority
    sort_plugins_by_priority();
    
    ACTF("Registered plugin '%s' v%s (priority: %d)", 
         ops->name, ops->version, ops->priority);
    
    return plugin;
}

void plugin_unregister(plugin_t *plugin) {
    if (!plugin) return;
    
    // Find and remove from registry
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i] == plugin) {
            // Cleanup if initialized (plugin is responsible for freeing private_data)
            if (plugin->initialized && plugin->ops.cleanup) {
                plugin->ops.cleanup(plugin);
            }
            
            // Note: private_data should be freed by plugin's cleanup function
            // to avoid double-free bugs and maintain single responsibility
            
            ACTF("Unregistered plugin '%s'", plugin->ops.name);
            
            // Shift remaining plugins
            for (int j = i; j < g_plugin_count - 1; j++) {
                g_plugins[j] = g_plugins[j + 1];
            }
            g_plugins[--g_plugin_count] = NULL;
            
            // Free plugin structure
            ck_free(plugin);
            return;
        }
    }
}

bool plugin_enable(const char *name) {
    int idx = find_plugin_index(name);
    if (idx < 0) {
        WARNF("Cannot enable plugin '%s': not found", name);
        return false;
    }
    
    g_plugins[idx]->ops.enabled = true;
    ACTF("Enabled plugin '%s'", name);
    return true;
}

bool plugin_disable(const char *name) {
    int idx = find_plugin_index(name);
    if (idx < 0) {
        WARNF("Cannot disable plugin '%s': not found", name);
        return false;
    }
    
    g_plugins[idx]->ops.enabled = false;
    ACTF("Disabled plugin '%s'", name);
    return true;
}

plugin_t* plugin_get(const char *name) {
    int idx = find_plugin_index(name);
    return (idx >= 0) ? g_plugins[idx] : NULL;
}

int plugin_list(char *buffer, size_t max_len) {
    if (!buffer || max_len == 0) return g_plugin_count;
    
    size_t offset = 0;
    for (int i = 0; i < g_plugin_count && offset < max_len - 1; i++) {
        plugin_t *p = g_plugins[i];
        int written = snprintf(buffer + offset, max_len - offset,
                              "%s%s (v%s, %s)",
                              (i > 0) ? ", " : "",
                              p->ops.name,
                              p->ops.version,
                              p->ops.enabled ? "enabled" : "disabled");
        if (written > 0) {
            offset += written;
        }
    }
    buffer[offset] = '\0';
    return g_plugin_count;
}

/* ============================================================================
 * PLUGIN INITIALIZATION
 * ============================================================================ */

bool plugin_system_init(void *fuzzer_ctx) {
    if (g_plugins_initialized) {
        WARNF("Plugin system already initialized");
        return true;
    }
    
    g_fuzzer_ctx = fuzzer_ctx;
    
    // Initialize all registered plugins
    for (int i = 0; i < g_plugin_count; i++) {
        plugin_t *p = g_plugins[i];
        
        if (!p->ops.enabled) {
            continue;
        }
        
        if (p->ops.init) {
            int ret = p->ops.init(p, fuzzer_ctx);
            if (ret != 0) {
                WARNF("Plugin '%s' initialization failed: %d", p->ops.name, ret);
                p->ops.enabled = false;
                continue;
            }
        }
        
        p->initialized = true;
        ACTF("Initialized plugin '%s'", p->ops.name);
    }
    
    g_plugins_initialized = true;
    SAYF(cGRA "    plugins  : " cRST "%d registered\n", g_plugin_count);
    
    return true;
}

void plugin_system_cleanup(void) {
    if (!g_plugins_initialized) return;
    
    // Cleanup all plugins in reverse order
    for (int i = g_plugin_count - 1; i >= 0; i--) {
        plugin_t *p = g_plugins[i];
        
        // Plugin cleanup is responsible for freeing private_data
        // to maintain single responsibility and avoid double-free
        if (p->initialized && p->ops.cleanup) {
            p->ops.cleanup(p);
        }
        
        // Note: Do NOT free private_data here - it's already freed in cleanup
        // This prevents double-free bugs
        
        ck_free(p);
        g_plugins[i] = NULL;
    }
    
    g_plugin_count = 0;
    g_plugins_initialized = false;
    g_fuzzer_ctx = NULL;
    
    ACTF("Plugin system cleaned up");
}

/* ============================================================================
 * HOOK INVOCATION API IMPLEMENTATION
 * ============================================================================ */

plugin_decision_t plugin_invoke_hook(plugin_hook_type_t hook_type, 
                                     hook_data_t *hook_data) {
    if (!g_plugins_initialized) {
        return PLUGIN_CONTINUE;
    }
    
    if (hook_type >= HOOK_MAX) {
        WARNF("Invalid hook type: %d", hook_type);
        return PLUGIN_CONTINUE;
    }
    
    g_hook_invocations[hook_type]++;
    
    plugin_decision_t final_decision = PLUGIN_CONTINUE;
    
    // Invoke each plugin in priority order
    for (int i = 0; i < g_plugin_count; i++) {
        plugin_t *p = g_plugins[i];
        
        if (!p->ops.enabled || !p->initialized) {
            continue;
        }
        
        if (!p->ops.on_hook) {
            continue;
        }
        
        // Track timing
        u64 start_time = plugin_get_cur_time_us();
        
        plugin_result_t *result = p->ops.on_hook(p, hook_type, hook_data);
        
        u64 elapsed = plugin_get_cur_time_us() - start_time;
        p->total_time_us += elapsed;
        p->total_calls++;
        
        if (!result) {
            continue;  // Plugin doesn't handle this hook
        }
        
        // Process plugin decision
        switch (result->decision) {
            case PLUGIN_ABORT:
                plugin_result_free(result);
                return PLUGIN_ABORT;  // Immediate abort
                
            case PLUGIN_SKIP:
            case PLUGIN_MUTATE_AGAIN:
            case PLUGIN_ADD_TO_QUEUE:
            case PLUGIN_MODIFIED:
                final_decision = result->decision;
                break;
                
            case PLUGIN_CONTINUE:
            default:
                break;
        }
        
        plugin_result_free(result);
        
        // If any plugin says skip/abort, stop processing
        if (final_decision == PLUGIN_SKIP || final_decision == PLUGIN_ABORT) {
            break;
        }
    }
    
    return final_decision;
}

plugin_result_t* plugin_invoke_single(plugin_t *plugin,
                                      plugin_hook_type_t hook_type,
                                      hook_data_t *hook_data) {
    if (!plugin || !plugin->ops.enabled || !plugin->initialized) {
        return NULL;
    }
    
    if (!plugin->ops.on_hook) {
        return NULL;
    }
    
    u64 start_time = plugin_get_cur_time_us();
    plugin_result_t *result = plugin->ops.on_hook(plugin, hook_type, hook_data);
    u64 elapsed = plugin_get_cur_time_us() - start_time;
    
    plugin->total_time_us += elapsed;
    plugin->total_calls++;
    
    return result;
}

void plugin_result_free(plugin_result_t *result) {
    if (!result) return;
    
    if (result->modified_data) {
        ck_free(result->modified_data);
    }
    
    if (result->reason) {
        ck_free(result->reason);
    }
    
    ck_free(result);
}

/* ============================================================================
 * UTILITY FUNCTIONS FOR PLUGINS
 * ============================================================================ */

// Note: These statistics will be set via plugin hooks rather than direct access
// to avoid static linkage issues
static u64 g_plugin_total_execs = 0;
static u32 g_plugin_queue_size = 0;
static u32 g_plugin_pending_favored = 0;
static u64 g_plugin_start_time = 0;

u64 plugin_get_stat(const char *key) {
    if (!key) return 0;
    
    if (strcmp(key, "total_execs") == 0) return g_plugin_total_execs;
    if (strcmp(key, "queue_size") == 0) return g_plugin_queue_size;
    if (strcmp(key, "pending_favored") == 0) return g_plugin_pending_favored;
    if (strcmp(key, "runtime_ms") == 0) {
        if (g_plugin_start_time == 0) g_plugin_start_time = plugin_get_cur_time();
        return plugin_get_cur_time() - g_plugin_start_time;
    }
    
    return 0;
}

void plugin_log(plugin_t *plugin, int level, const char *format, ...) {
    if (!plugin || !format) return;
    
    char buf[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    
    const char *level_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    const char *level_color[] = {cGRA, cLCY, cYEL, cLRD};
    
    int idx = (level >= 0 && level <= 3) ? level : 1;
    
    SAYF("%s[%s:%s] " cRST "%s\n",
         level_color[idx],
         plugin->ops.name, level_str[idx], buf);
}

void* plugin_alloc(size_t size) {
    return ck_alloc(size);
}

void plugin_free(void *ptr) {
    if (ptr) ck_free(ptr);
}

/* ============================================================================
 * STATISTICS AND DEBUGGING
 * ============================================================================ */

void plugin_print_stats(void) {
    if (!g_plugins_initialized || g_plugin_count == 0) {
        return;
    }
    
    SAYF("\n" cYEL "[+] Plugin Statistics:\n" cRST);
    
    for (int i = 0; i < g_plugin_count; i++) {
        plugin_t *p = g_plugins[i];
        
        SAYF("    %s%-20s" cRST " : calls=%llu, time=%llu ms, avg=%.2f us/call\n",
             p->ops.enabled ? cLGN : cGRA,
             p->ops.name,
             p->total_calls,
             p->total_time_us / 1000,
             p->total_calls > 0 ? (double)p->total_time_us / p->total_calls : 0.0);
    }
    
    SAYF("\n" cYEL "[+] Hook Invocation Counts:\n" cRST);
    const char *hook_names[] = {
        "INIT", "PRE_FUZZ", "PRE_EXEC", "POST_EXEC", "NEW_QUEUE_ENTRY",
        "CALIBRATION", "TRIM", "HAVOC", "SPLICE", "STATE_TRANSITION",
        "COVERAGE_UPDATE", "CRASH_FOUND", "HANG_FOUND", "PERIODIC", "CLEANUP"
    };
    
    for (int i = 0; i < HOOK_MAX; i++) {
        if (g_hook_invocations[i] > 0) {
            SAYF("    %-20s : %llu\n", hook_names[i], g_hook_invocations[i]);
        }
    }
}
