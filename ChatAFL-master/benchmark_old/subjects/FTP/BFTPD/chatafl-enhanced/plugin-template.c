/*
 * plugin-template.c - Plugin Development Template
 * 
 * This template demonstrates how to create a new ChatAFL plugin.
 * Copy this file, rename it, and modify to implement your custom functionality.
 * 
 * Example: Create a crash deduplication plugin
 * 
 * Steps:
 * 1. Copy this file: cp plugin-template.c plugin-crashdedup.c
 * 2. Modify plugin metadata (name, version, description)
 * 3. Implement init/cleanup callbacks
 * 4. Implement hook handlers for hooks you care about
 * 5. Add to Makefile.plugin
 * 6. Register in afl-fuzz-plugin.h
 * 7. Build and test!
 */

#include <string.h>
#include <stdlib.h>
#include "plugin-interface.h"
#include "alloc-inl.h"
#include "hash.h"

/* ============================================================================
 * PLUGIN CONFIGURATION
 * 
 * Define configuration parameters that users can set via environment variables
 * ============================================================================ */

typedef struct {
    /* Plugin-specific configuration */
    u32 example_threshold;       // Example: trigger threshold
    bool enable_logging;          // Example: logging flag
    char *output_file;            // Example: output file path
    
    /* Plugin-specific state */
    u64 total_invocations;        // Example: invocation counter
    u64 successful_actions;       // Example: success counter
    void *custom_data;            // Example: custom data structure
} template_plugin_data_t;

/* ============================================================================
 * HELPER FUNCTIONS
 * 
 * Internal helper functions for your plugin logic
 * ============================================================================ */

/**
 * Example: Process test case data
 */
static bool process_test_case(u8 *data, u32 len) {
    if (!data || len == 0) {
        return false;
    }
    
    // Add your processing logic here
    // Example: check for specific patterns, validate format, etc.
    
    return true;
}

/**
 * Example: Save data to file
 */
static void save_to_file(const char *filename, u8 *data, u32 len) {
    FILE *f = fopen(filename, "ab");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

/* ============================================================================
 * PLUGIN LIFECYCLE CALLBACKS
 * ============================================================================ */

/**
 * Initialize plugin
 * 
 * Called once during fuzzer startup. Allocate resources, load configuration,
 * initialize state, etc.
 * 
 * @param plugin Plugin handle
 * @param fuzzer_ctx Opaque fuzzer context (can be NULL)
 * @return 0 on success, non-zero on failure
 */
static int template_plugin_init(plugin_t *plugin, void *fuzzer_ctx) {
    // Allocate plugin private data
    template_plugin_data_t *data = ck_alloc(sizeof(template_plugin_data_t));
    memset(data, 0, sizeof(template_plugin_data_t));
    
    /* Load configuration from environment variables */
    
    // Example: numeric configuration
    char *threshold_str = getenv("TEMPLATE_THRESHOLD");
    if (threshold_str) {
        data->example_threshold = atoi(threshold_str);
    } else {
        data->example_threshold = 100;  // Default value
    }
    
    // Example: boolean configuration
    data->enable_logging = (getenv("TEMPLATE_LOG") != NULL);
    
    // Example: string configuration
    char *output = getenv("TEMPLATE_OUTPUT");
    if (output) {
        data->output_file = strdup(output);
    } else {
        data->output_file = strdup("./template_output.log");
    }
    
    /* Initialize custom data structures */
    // data->custom_data = create_custom_structure();
    
    /* Store private data in plugin handle */
    plugin->private_data = data;
    
    /* Log initialization */
    plugin_log(plugin, 1, "Initialized with threshold=%u, logging=%s, output=%s",
               data->example_threshold,
               data->enable_logging ? "ON" : "OFF",
               data->output_file);
    
    return 0;  // Success
}

/**
 * Cleanup plugin
 * 
 * Called once during fuzzer shutdown. Free all resources allocated during
 * init or execution.
 * 
 * @param plugin Plugin handle
 */
static void template_plugin_cleanup(plugin_t *plugin) {
    if (!plugin->private_data) {
        return;
    }
    
    template_plugin_data_t *data = (template_plugin_data_t *)plugin->private_data;
    
    /* Log final statistics */
    plugin_log(plugin, 1, "Final stats: invocations=%llu, successes=%llu, rate=%.2f%%",
               data->total_invocations,
               data->successful_actions,
               data->total_invocations > 0 ? 
                   (data->successful_actions * 100.0 / data->total_invocations) : 0.0);
    
    /* Free allocated resources */
    if (data->output_file) {
        free(data->output_file);
    }
    
    if (data->custom_data) {
        // free_custom_structure(data->custom_data);
    }
    
    /* Free private data */
    ck_free(data);
    plugin->private_data = NULL;
}

/* ============================================================================
 * HOOK HANDLERS
 * 
 * Implement handlers for hooks you care about. Return NULL for hooks you
 * don't handle.
 * ============================================================================ */

/**
 * Main hook handler
 * 
 * Called by the fuzzer at various points during execution. Inspect hook_type
 * to determine which hook is being invoked, and process hook_data accordingly.
 * 
 * @param plugin Plugin handle
 * @param hook_type Type of hook being invoked
 * @param hook_data Hook-specific data (can be NULL for some hooks)
 * @return Plugin result (decision + optional modified data), or NULL if not handled
 */
static plugin_result_t* template_on_hook(plugin_t *plugin, 
                                         plugin_hook_type_t hook_type,
                                         hook_data_t *hook_data) {
    template_plugin_data_t *data = (template_plugin_data_t *)plugin->private_data;
    
    /* Update invocation counter */
    data->total_invocations++;
    
    /* Handle different hook types */
    switch (hook_type) {
        
        /* ====================================================================
         * HOOK_POST_EXEC: Called after each test case execution
         * ==================================================================== */
        case HOOK_POST_EXEC: {
            hook_exec_data_t *exec = &hook_data->exec;
            
            // Example: Process test case that caused a fault
            if (exec->fault != 0) {
                plugin_log(plugin, 0, "Fault detected, len=%u, fault=%u", 
                          exec->len, exec->fault);
                
                // Example: Save crashing input
                if (data->output_file) {
                    save_to_file(data->output_file, exec->test_case, exec->len);
                }
                
                data->successful_actions++;
            }
            
            // Example: Check threshold
            if (data->total_invocations % data->example_threshold == 0) {
                plugin_log(plugin, 0, "Threshold reached: %llu invocations",
                          data->total_invocations);
            }
            
            // Return decision
            plugin_result_t *result = ck_alloc(sizeof(plugin_result_t));
            memset(result, 0, sizeof(plugin_result_t));
            
            result->decision = PLUGIN_CONTINUE;  // Continue normal execution
            
            // Optional: provide reason
            result->reason = ck_alloc(128);
            snprintf(result->reason, 128, "Processed test case (len=%u)", exec->len);
            
            return result;
        }
        
        /* ====================================================================
         * HOOK_CRASH_FOUND: Called when a crash is discovered
         * ==================================================================== */
        case HOOK_CRASH_FOUND: {
            hook_crash_data_t *crash = &hook_data->crash;
            
            plugin_log(plugin, 2, "CRASH found! signal=%d, path=%s", 
                      crash->signal, crash->crash_path);
            
            // Example: Deduplicate crashes, analyze patterns, etc.
            
            return NULL;  // No decision needed
        }
        
        /* ====================================================================
         * HOOK_COVERAGE_UPDATE: Called when coverage increases
         * ==================================================================== */
        case HOOK_COVERAGE_UPDATE: {
            hook_coverage_data_t *cov = &hook_data->coverage;
            
            float gain = cov->new_coverage - cov->old_coverage;
            
            if (gain > 0.01f) {  // Significant gain
                plugin_log(plugin, 0, "Coverage gain: +%.2f%% (now %.2f%%)",
                          gain * 100.0f, cov->new_coverage * 100.0f);
            }
            
            return NULL;
        }
        
        /* ====================================================================
         * HOOK_PERIODIC: Called periodically (e.g., every 1000 execs)
         * ==================================================================== */
        case HOOK_PERIODIC: {
            hook_periodic_data_t *periodic = &hook_data->periodic;
            
            // Example: Log periodic statistics
            if (data->enable_logging) {
                plugin_log(plugin, 0, "Stats: execs=%llu, queue=%u, pending=%u",
                          periodic->total_execs,
                          periodic->queue_size,
                          periodic->pending_favored);
            }
            
            return NULL;
        }
        
        /* ====================================================================
         * Other hooks you can implement:
         * - HOOK_INIT: Fuzzer initialization
         * - HOOK_PRE_FUZZ: Before fuzzing starts
         * - HOOK_PRE_EXEC: Before each execution
         * - HOOK_NEW_QUEUE_ENTRY: New test case added to queue
         * - HOOK_STATE_TRANSITION: Protocol state changed
         * - HOOK_HANG_FOUND: Hang detected
         * - HOOK_CLEANUP: Fuzzer shutdown
         * ==================================================================== */
        
        default:
            // Not handled by this plugin
            return NULL;
    }
}

/* ============================================================================
 * PLUGIN REGISTRATION
 * 
 * Create and register the plugin with the fuzzer. This function is called
 * from setup_plugins() in afl-fuzz-plugin.h.
 * ============================================================================ */

/**
 * Register the template plugin
 * 
 * Call this function from setup_plugins() in afl-fuzz-plugin.h to register
 * your plugin with the fuzzer.
 * 
 * @return Plugin handle, or NULL on failure
 */
plugin_t* register_template_plugin(void) {
    plugin_ops_t ops = {
        /* Plugin metadata */
        .name = "Template",              // CHANGE THIS: unique plugin name
        .version = "1.0.0",              // CHANGE THIS: your version
        .author = "Your Name",           // CHANGE THIS: your name
        .description = "Template plugin for demonstration",  // CHANGE THIS
        
        /* Plugin lifecycle callbacks */
        .init = template_plugin_init,
        .cleanup = template_plugin_cleanup,
        .on_hook = template_on_hook,
        
        /* Plugin configuration */
        .enabled = true,                 // Enable by default
        .priority = 50,                  // Priority (0-100, higher runs first)
        .config = NULL                   // Reserved for future use
    };
    
    return plugin_register(&ops);
}

/* ============================================================================
 * ENVIRONMENT VARIABLES
 * 
 * Document environment variables your plugin supports:
 * 
 * TEMPLATE_THRESHOLD=<number>
 *   Trigger threshold for periodic actions (default: 100)
 * 
 * TEMPLATE_LOG=1
 *   Enable verbose logging (default: disabled)
 * 
 * TEMPLATE_OUTPUT=<path>
 *   Output file path (default: ./template_output.log)
 * 
 * PLUGIN_DISABLE_TEMPLATE=1
 *   Disable this plugin at runtime
 * 
 * ============================================================================ */

/* ============================================================================
 * TESTING
 * 
 * To test your plugin:
 * 
 * 1. Add to Makefile.plugin:
 * 
 *    PLUGIN_ADAPTER_OBJS += plugin-template.o
 *    
 *    plugin-template.o: plugin-template.c plugin-interface.h
 *        $(CC) $(CFLAGS) -c plugin-template.c -o plugin-template.o
 * 
 * 2. Register in afl-fuzz-plugin.h:
 * 
 *    extern plugin_t* register_template_plugin(void);
 *    
 *    static inline bool setup_plugins(void *ctx) {
 *        // ... existing plugins ...
 *        plugin_t *template = register_template_plugin();
 *        // ...
 *    }
 * 
 * 3. Build and run:
 * 
 *    make clean && make CHATAFL_ENHANCED=1 -f Makefile.plugin
 *    export TEMPLATE_LOG=1
 *    export TEMPLATE_THRESHOLD=500
 *    ./afl-fuzz -i in -o out -- ./target
 * 
 * ============================================================================ */
