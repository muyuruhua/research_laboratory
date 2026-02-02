/*
 * plugin-interface.h - ChatAFL Plugin Interface
 * 
 * This file defines the plugin architecture for ChatAFL-Enhanced.
 * Plugins can hook into the fuzzing lifecycle without modifying core code.
 * 
 * Design Principles:
 * - Open/Closed Principle: Core is closed for modification, open for extension
 * - Plugin-based: All extensions are plugins with well-defined interfaces
 * - Decoupled: Plugins communicate through events, not global variables
 */

#ifndef __PLUGIN_INTERFACE_H
#define __PLUGIN_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>
#include "types.h"

/* ============================================================================
 * PLUGIN LIFECYCLE HOOKS
 * ============================================================================ */

typedef enum {
    HOOK_INIT,                    // Called during fuzzer initialization
    HOOK_PRE_FUZZ,                // Called before fuzzing starts
    HOOK_PRE_EXEC,                // Called before each test case execution
    HOOK_POST_EXEC,               // Called after each test case execution
    HOOK_NEW_QUEUE_ENTRY,         // Called when new test case is queued
    HOOK_CALIBRATION,             // Called during test case calibration
    HOOK_TRIM,                    // Called during test case trimming
    HOOK_HAVOC,                   // Called during havoc stage
    HOOK_SPLICE,                  // Called during splicing stage
    HOOK_STATE_TRANSITION,        // Called on protocol state change
    HOOK_COVERAGE_UPDATE,         // Called when coverage increases
    HOOK_CRASH_FOUND,             // Called when crash is discovered
    HOOK_HANG_FOUND,              // Called when hang is discovered
    HOOK_PERIODIC,                // Called periodically (e.g., every second)
    HOOK_CLEANUP,                 // Called during fuzzer shutdown
    HOOK_MAX
} plugin_hook_type_t;

/* ============================================================================
 * HOOK DATA STRUCTURES
 * ============================================================================ */

typedef struct {
    char *in_dir;                 // Input directory
    char *out_dir;                // Output directory
    char *target_path;            // Target binary path
    u32 exec_tmout;               // Execution timeout
    u64 mem_limit;                // Memory limit
    void *fuzzer_state;           // Opaque fuzzer state (for plugin use)
} hook_init_data_t;

typedef struct {
    u8 *test_case;                // Test case data
    u32 len;                      // Test case length
    u32 exec_cksum;               // Execution checksum
    u64 exec_us;                  // Execution time (microseconds)
    u8 fault;                     // Fault type (0=none, 1=crash, 2=hang)
    u8 *trace_bits;               // Coverage bitmap
    bool calibration_done;        // Has calibration completed?
    void *queue_entry;            // Opaque queue entry pointer
} hook_exec_data_t;

typedef struct {
    u32 from_state;               // Previous state ID
    u32 to_state;                 // New state ID
    u8 *message;                  // Message that triggered transition
    u32 msg_len;                  // Message length
    float coverage_gain;          // Coverage increase
} hook_state_data_t;

typedef struct {
    float old_coverage;           // Previous coverage percentage
    float new_coverage;           // New coverage percentage
    u32 total_bitmap;             // Total bitmap bytes
    u32 virgin_bits_count;        // Count of new virgin bits
} hook_coverage_data_t;

typedef struct {
    u8 *crash_input;              // Input that caused crash
    u32 crash_len;                // Crash input length
    char *crash_path;             // Path to saved crash file
    int signal;                   // Signal that caused crash
} hook_crash_data_t;

typedef struct {
    u64 total_execs;              // Total executions so far
    u64 cur_time;                 // Current time (ms since start)
    u32 queue_size;               // Current queue size
    u32 pending_favored;          // Pending favored entries
} hook_periodic_data_t;

typedef union {
    hook_init_data_t init;
    hook_exec_data_t exec;
    hook_state_data_t state;
    hook_coverage_data_t coverage;
    hook_crash_data_t crash;
    hook_periodic_data_t periodic;
} hook_data_t;

/* ============================================================================
 * PLUGIN DECISION/ACTION RETURN VALUES
 * ============================================================================ */

typedef enum {
    PLUGIN_CONTINUE,              // Continue normal fuzzing
    PLUGIN_SKIP,                  // Skip this test case
    PLUGIN_MUTATE_AGAIN,          // Mutate this test case again
    PLUGIN_ADD_TO_QUEUE,          // Add modified test case to queue
    PLUGIN_ABORT,                 // Abort fuzzing
    PLUGIN_MODIFIED               // Plugin modified the data (check output)
} plugin_decision_t;

typedef struct {
    plugin_decision_t decision;   // Plugin's decision
    u8 *modified_data;            // Modified test case (if PLUGIN_MODIFIED)
    u32 modified_len;             // Length of modified data
    char *reason;                 // Human-readable reason for decision
    void *plugin_private;         // Plugin-specific data
} plugin_result_t;

/* ============================================================================
 * PLUGIN DESCRIPTOR
 * ============================================================================ */

typedef struct plugin plugin_t;

typedef struct {
    /* Plugin metadata */
    const char *name;             // Plugin name (e.g., "CEGAR")
    const char *version;          // Plugin version (e.g., "1.0.0")
    const char *author;           // Plugin author
    const char *description;      // Brief description
    
    /* Plugin lifecycle callbacks */
    int (*init)(plugin_t *plugin, void *fuzzer_ctx);
    void (*cleanup)(plugin_t *plugin);
    
    /* Hook handlers - return NULL if hook is not implemented */
    plugin_result_t* (*on_hook)(plugin_t *plugin, 
                                plugin_hook_type_t hook_type,
                                hook_data_t *hook_data);
    
    /* Plugin configuration */
    bool enabled;                 // Is plugin enabled?
    int priority;                 // Execution priority (higher = earlier)
    void *config;                 // Plugin-specific configuration
} plugin_ops_t;

struct plugin {
    plugin_ops_t ops;             // Plugin operations
    void *private_data;           // Plugin private data
    bool initialized;             // Initialization status
    u64 total_calls;              // Total hook invocations
    u64 total_time_us;            // Total time spent in plugin (us)
};

/* ============================================================================
 * PLUGIN REGISTRY API
 * ============================================================================ */

/**
 * Register a plugin with the fuzzer
 * @param ops Plugin operation structure
 * @return Plugin handle, or NULL on failure
 */
plugin_t* plugin_register(const plugin_ops_t *ops);

/**
 * Unregister a plugin
 * @param plugin Plugin handle
 */
void plugin_unregister(plugin_t *plugin);

/**
 * Enable a plugin by name
 * @param name Plugin name
 * @return true on success
 */
bool plugin_enable(const char *name);

/**
 * Disable a plugin by name
 * @param name Plugin name
 * @return true on success
 */
bool plugin_disable(const char *name);

/**
 * Get plugin by name
 * @param name Plugin name
 * @return Plugin handle, or NULL if not found
 */
plugin_t* plugin_get(const char *name);

/**
 * List all registered plugins
 * @param buffer Output buffer for plugin names
 * @param max_len Maximum buffer length
 * @return Number of plugins
 */
int plugin_list(char *buffer, size_t max_len);

/* ============================================================================
 * HOOK INVOCATION API (Used by Core Fuzzer)
 * ============================================================================ */

/**
 * Invoke all registered plugins for a specific hook
 * @param hook_type Type of hook to invoke
 * @param hook_data Hook-specific data
 * @return Aggregated decision from all plugins
 */
plugin_decision_t plugin_invoke_hook(plugin_hook_type_t hook_type, 
                                     hook_data_t *hook_data);

/**
 * Invoke a specific plugin for a hook
 * @param plugin Plugin to invoke
 * @param hook_type Type of hook
 * @param hook_data Hook-specific data
 * @return Plugin result
 */
plugin_result_t* plugin_invoke_single(plugin_t *plugin,
                                      plugin_hook_type_t hook_type,
                                      hook_data_t *hook_data);

/**
 * Free plugin result (called by core after processing)
 * @param result Plugin result to free
 */
void plugin_result_free(plugin_result_t *result);

/* ============================================================================
 * UTILITY FUNCTIONS FOR PLUGINS
 * ============================================================================ */

/**
 * Get fuzzer statistics (safe for plugins to call)
 * @param key Statistics key (e.g., "total_execs", "queue_size")
 * @return Statistics value, or 0 if key not found
 */
u64 plugin_get_stat(const char *key);

/**
 * Log message from plugin
 * @param plugin Plugin handle
 * @param level Log level (0=debug, 1=info, 2=warn, 3=error)
 * @param format Printf-style format string
 */
void plugin_log(plugin_t *plugin, int level, const char *format, ...);

/**
 * Allocate memory through fuzzer's allocator
 * @param size Size to allocate
 * @return Pointer to allocated memory
 */
void* plugin_alloc(size_t size);

/**
 * Free memory allocated by plugin_alloc
 * @param ptr Pointer to free
 */
void plugin_free(void *ptr);

#endif /* __PLUGIN_INTERFACE_H */
