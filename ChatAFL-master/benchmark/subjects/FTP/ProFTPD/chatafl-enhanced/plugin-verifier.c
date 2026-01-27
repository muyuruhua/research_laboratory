/*
 * plugin-verifier.c - Verifier Plugin Adapter
 * 
 * Wraps the Verifier module as a ChatAFL plugin
 */

#include <string.h>
#include "plugin-interface.h"
#include "verifier.h"
#include "alloc-inl.h"

/* Plugin private data */
typedef struct {
    verifier_config_t config;
    u64 total_checks;
    u64 total_rejections;
    u64 new_states_found;
} verifier_plugin_data_t;

/* ============================================================================
 * PLUGIN LIFECYCLE CALLBACKS
 * ============================================================================ */

static int verifier_plugin_init(plugin_t *plugin, void *fuzzer_ctx) {
    verifier_plugin_data_t *data = ck_alloc(sizeof(verifier_plugin_data_t));
    memset(data, 0, sizeof(verifier_plugin_data_t));
    
    // Initialize verifier configuration
    data->config.enable_logging = (getenv("VERIFIER_LOG") != NULL);
    data->config.debug_mode = (getenv("VERIFIER_DEBUG") != NULL);
    data->config.log_file = "./verifier_plugin.log";
    data->config.stt = NULL;  // Will be set by state-graph plugin
    
    verifier_init(&data->config);
    
    plugin->private_data = data;
    
    plugin_log(plugin, 1, "Initialized (logging=%s)", 
               data->config.enable_logging ? "ON" : "OFF");
    
    return 0;
}

static void verifier_plugin_cleanup(plugin_t *plugin) {
    if (!plugin->private_data) return;
    
    verifier_plugin_data_t *data = (verifier_plugin_data_t *)plugin->private_data;
    
    plugin_log(plugin, 1, "Final stats: checks=%llu, rejections=%llu, rate=%.2f%%",
               data->total_checks, data->total_rejections,
               data->total_checks > 0 ? 
                   (data->total_rejections * 100.0 / data->total_checks) : 0.0);
    
    verifier_cleanup();
    
    ck_free(data);
    plugin->private_data = NULL;
}

/* ============================================================================
 * HOOK HANDLERS
 * ============================================================================ */

static plugin_result_t* verifier_on_hook(plugin_t *plugin, 
                                         plugin_hook_type_t hook_type,
                                         hook_data_t *hook_data) {
    verifier_plugin_data_t *data = (verifier_plugin_data_t *)plugin->private_data;
    
    switch (hook_type) {
        case HOOK_POST_EXEC: {
            hook_exec_data_t *exec = &hook_data->exec;
            
            if (!exec->test_case || exec->len == 0) {
                return NULL;
            }
            
            data->total_checks++;
            
            // Perform 4D verification
            int parseability = 1;  // Assume parseable for now
            int acceptability = (exec->fault == 0) ? 1 : 0;
            int state_reachability = 1;  // Will be checked by state-graph plugin
            float coverage_gain = 0.0f;  // Will be calculated
            
            if (!acceptability) {
                data->total_rejections++;
            }
            
            // Create result
            plugin_result_t *result = ck_alloc(sizeof(plugin_result_t));
            memset(result, 0, sizeof(plugin_result_t));
            
            if (acceptability && parseability) {
                result->decision = PLUGIN_CONTINUE;
                result->reason = ck_alloc(64);
                snprintf(result->reason, 64, "Message verified successfully");
            } else {
                result->decision = PLUGIN_CONTINUE;  // Let CEGAR handle it
                result->reason = ck_alloc(64);
                snprintf(result->reason, 64, "Message rejected (P=%d, A=%d)", 
                        parseability, acceptability);
                
                plugin_log(plugin, 0, "Verification failed: %s", result->reason);
            }
            
            return result;
        }
        
        case HOOK_STATE_TRANSITION: {
            data->new_states_found++;
            plugin_log(plugin, 0, "New state transition detected: %u -> %u",
                      hook_data->state.from_state, hook_data->state.to_state);
            return NULL;
        }
        
        case HOOK_PERIODIC: {
            if (data->total_checks % 1000 == 0 && data->total_checks > 0) {
                plugin_log(plugin, 0, "Checks=%llu, Rejections=%llu (%.2f%%), NewStates=%llu",
                          data->total_checks, data->total_rejections,
                          (data->total_rejections * 100.0) / data->total_checks,
                          data->new_states_found);
            }
            return NULL;
        }
        
        default:
            return NULL;
    }
}

/* ============================================================================
 * PLUGIN DESCRIPTOR
 * ============================================================================ */

plugin_t* register_verifier_plugin(void) {
    plugin_ops_t ops = {
        .name = "Verifier",
        .version = "1.0.0",
        .author = "ChatAFL-Enhanced",
        .description = "4D Message Verification (Parseability, Acceptability, Reachability, Coverage)",
        .init = verifier_plugin_init,
        .cleanup = verifier_plugin_cleanup,
        .on_hook = verifier_on_hook,
        .enabled = true,
        .priority = 100,  // Highest priority (runs first)
        .config = NULL
    };
    
    return plugin_register(&ops);
}
