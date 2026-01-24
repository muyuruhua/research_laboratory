/*
 * plugin-cegar.c - CEGAR Plugin Adapter
 * 
 * Wraps the CEGAR module as a ChatAFL plugin
 */

#include <string.h>
#include "plugin-interface.h"
#include "cegar-optimized.h"
#include "cegar-refinement.h"
#include "alloc-inl.h"

/* Plugin private data */
typedef struct {
    CEGARConfig config;
    u64 rejection_count;
    u64 patch_attempts;
    u64 patch_successes;
} cegar_plugin_data_t;

/* ============================================================================
 * PLUGIN LIFECYCLE CALLBACKS
 * ============================================================================ */

static int cegar_plugin_init(plugin_t *plugin, void *fuzzer_ctx) {
    cegar_plugin_data_t *data = ck_alloc(sizeof(cegar_plugin_data_t));
    memset(data, 0, sizeof(cegar_plugin_data_t));
    
    // Initialize CEGAR configuration
    data->config.enabled = true;
    data->config.trigger_interval = 10;  // Trigger after 10 rejections
    data->config.max_llm_calls_per_hour = 60;
    data->config.max_retries = 3;
    data->config.fast_fail_enabled = true;
    data->config.time_budget_percent = 10;
    
    // Read configuration from environment
    char *interval = getenv("CEGAR_TRIGGER_INTERVAL");
    if (interval) {
        data->config.trigger_interval = atoi(interval);
    }
    
    char *llm_budget = getenv("CEGAR_LLM_BUDGET");
    if (llm_budget) {
        data->config.max_llm_calls_per_hour = atoi(llm_budget);
    }
    
    plugin->private_data = data;
    
    plugin_log(plugin, 1, "Initialized with trigger_interval=%u, llm_budget=%u",
               data->config.trigger_interval, data->config.max_llm_calls_per_hour);
    
    return 0;
}

static void cegar_plugin_cleanup(plugin_t *plugin) {
    if (!plugin->private_data) return;
    
    cegar_plugin_data_t *data = (cegar_plugin_data_t *)plugin->private_data;
    
    plugin_log(plugin, 1, "Final stats: attempts=%llu, successes=%llu, rate=%.2f%%",
               data->patch_attempts, data->patch_successes,
               data->patch_attempts > 0 ? 
                   (data->patch_successes * 100.0 / data->patch_attempts) : 0.0);
    
    cegar_cleanup();
    
    ck_free(data);
    plugin->private_data = NULL;
}

/* ============================================================================
 * HOOK HANDLERS
 * ============================================================================ */

static plugin_result_t* cegar_on_hook(plugin_t *plugin, 
                                      plugin_hook_type_t hook_type,
                                      hook_data_t *hook_data) {
    cegar_plugin_data_t *data = (cegar_plugin_data_t *)plugin->private_data;
    
    switch (hook_type) {
        case HOOK_POST_EXEC: {
            hook_exec_data_t *exec = &hook_data->exec;
            
            // Check if this was a rejection (fault occurred)
            if (exec->fault == 0) {
                return NULL;  // No fault, nothing to do
            }
            
            data->rejection_count++;
            
            // Check if we should trigger CEGAR
            if (data->rejection_count % data->config.trigger_interval != 0) {
                return NULL;  // Not time yet
            }
            
            plugin_log(plugin, 0, "Triggering CEGAR after %llu rejections", 
                      data->rejection_count);
            
            data->patch_attempts++;
            
            // Apply CEGAR refinement
            cegar_patch_t *patch = cegar_refine_message(
                exec->test_case, exec->len, 
                &data->config, NULL);
            
            if (!patch || !patch->patched_message) {
                plugin_log(plugin, 2, "CEGAR refinement failed");
                if (patch) cegar_free_patch(patch);
                return NULL;
            }
            
            data->patch_successes++;
            
            // Create result with patched message
            plugin_result_t *result = ck_alloc(sizeof(plugin_result_t));
            memset(result, 0, sizeof(plugin_result_t));
            
            result->decision = PLUGIN_ADD_TO_QUEUE;
            result->modified_data = ck_alloc(patch->patched_len);
            memcpy(result->modified_data, patch->patched_message, patch->patched_len);
            result->modified_len = patch->patched_len;
            result->reason = ck_alloc(256);
            snprintf(result->reason, 256, "CEGAR patched message (confidence=%.2f)", 
                    patch->confidence);
            
            cegar_free_patch(patch);
            
            plugin_log(plugin, 1, "Successfully patched message, adding to queue");
            
            return result;
        }
        
        case HOOK_PERIODIC: {
            // Log periodic statistics
            if (data->patch_attempts > 0) {
                plugin_log(plugin, 0, "Rejections=%llu, Patches=%llu/%llu (%.1f%%)",
                          data->rejection_count, data->patch_successes, 
                          data->patch_attempts,
                          (data->patch_successes * 100.0) / data->patch_attempts);
            }
            return NULL;
        }
        
        default:
            return NULL;  // Not handled
    }
}

/* ============================================================================
 * PLUGIN DESCRIPTOR
 * ============================================================================ */

plugin_t* register_cegar_plugin(void) {
    plugin_ops_t ops = {
        .name = "CEGAR",
        .version = "1.0.0",
        .author = "ChatAFL-Enhanced",
        .description = "Counter-Example Guided Abstraction Refinement",
        .init = cegar_plugin_init,
        .cleanup = cegar_plugin_cleanup,
        .on_hook = cegar_on_hook,
        .enabled = true,
        .priority = 80,  // High priority
        .config = NULL
    };
    
    return plugin_register(&ops);
}
