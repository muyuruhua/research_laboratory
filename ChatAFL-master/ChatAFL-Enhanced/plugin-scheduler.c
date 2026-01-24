/*
 * plugin-scheduler.c - State Scheduler Plugin Adapter
 * 
 * Wraps the State Scheduler module as a ChatAFL plugin
 */

#include <string.h>
#include "plugin-interface.h"
#include "state-scheduler.h"
#include "state-graph.h"
#include "alloc-inl.h"

/* Plugin private data */
typedef struct {
    state_scheduler_t scheduler;
    StateGraph state_graph;
    u32 current_state;
    u32 previous_state;
    float last_coverage;
    int plateau_detected;
} scheduler_plugin_data_t;

/* ============================================================================
 * PLUGIN LIFECYCLE CALLBACKS
 * ============================================================================ */

static int scheduler_plugin_init(plugin_t *plugin, void *fuzzer_ctx) {
    scheduler_plugin_data_t *data = ck_alloc(sizeof(scheduler_plugin_data_t));
    memset(data, 0, sizeof(scheduler_plugin_data_t));
    
    // Initialize state graph
    state_graph_init(&data->state_graph);
    
    // Initialize scheduler
    u32 plateau_threshold = 50;  // Default
    char *threshold_str = getenv("SCHEDULER_PLATEAU_THRESHOLD");
    if (threshold_str) {
        plateau_threshold = atoi(threshold_str);
    }
    
    state_scheduler_init(&data->scheduler, plateau_threshold);
    
    plugin->private_data = data;
    
    plugin_log(plugin, 1, "Initialized with plateau_threshold=%u", plateau_threshold);
    
    return 0;
}

static void scheduler_plugin_cleanup(plugin_t *plugin) {
    if (!plugin->private_data) return;
    
    scheduler_plugin_data_t *data = (scheduler_plugin_data_t *)plugin->private_data;
    
    plugin_log(plugin, 1, "Final state graph: %u states, %u transitions",
               data->state_graph.node_count, data->state_graph.total_transitions);
    
    // Export state graph
    #ifdef __linux__
    char *dot_file = "./state_graph_plugin.dot";
    export_stt_graphviz(&data->scheduler, dot_file);
    plugin_log(plugin, 1, "State graph exported to %s", dot_file);
    #endif
    
    state_scheduler_cleanup(&data->scheduler);
    
    ck_free(data);
    plugin->private_data = NULL;
}

/* ============================================================================
 * HOOK HANDLERS
 * ============================================================================ */

static plugin_result_t* scheduler_on_hook(plugin_t *plugin, 
                                          plugin_hook_type_t hook_type,
                                          hook_data_t *hook_data) {
    scheduler_plugin_data_t *data = (scheduler_plugin_data_t *)plugin->private_data;
    
    switch (hook_type) {
        case HOOK_POST_EXEC: {
            hook_exec_data_t *exec = &hook_data->exec;
            
            // Calculate state from execution checksum
            u32 new_state = exec->exec_cksum % 10000;  // Simple state ID
            
            if (new_state != data->current_state) {
                // State transition detected
                int is_new = state_graph_add_transition(&data->state_graph,
                                                        data->current_state,
                                                        new_state,
                                                        exec->test_case,
                                                        exec->len);
                
                if (is_new) {
                    plugin_log(plugin, 0, "New state transition: %u -> %u",
                              data->current_state, new_state);
                    
                    // Notify via state transition hook
                    hook_data_t state_hook_data;
                    memset(&state_hook_data, 0, sizeof(hook_data_t));
                    state_hook_data.state.from_state = data->current_state;
                    state_hook_data.state.to_state = new_state;
                    state_hook_data.state.message = exec->test_case;
                    state_hook_data.state.msg_len = exec->len;
                    state_hook_data.state.coverage_gain = 0.0f;
                    
                    plugin_invoke_hook(HOOK_STATE_TRANSITION, &state_hook_data);
                }
                
                data->previous_state = data->current_state;
                data->current_state = new_state;
            }
            
            // Register seed for current state
            if (exec->queue_entry) {
                state_graph_register_seed_for_state(&data->state_graph,
                                                    data->current_state,
                                                    exec->queue_entry);
            }
            
            return NULL;
        }
        
        case HOOK_COVERAGE_UPDATE: {
            hook_coverage_data_t *cov = &hook_data->coverage;
            
            float coverage_gain = cov->new_coverage - cov->old_coverage;
            
            // Check for plateau
            if (coverage_gain < 0.01f && cov->new_coverage > 0.0f) {
                data->scheduler.plateau_counter++;
                
                if (data->scheduler.plateau_counter >= data->scheduler.plateau_threshold) {
                    if (!data->plateau_detected) {
                        data->plateau_detected = 1;
                        plugin_log(plugin, 2, "Coverage plateau detected! Switching to rare states.");
                        
                        // Update state rarities
                        update_state_rarity(&data->scheduler);
                        
                        // Create result to suggest prioritizing rare states
                        plugin_result_t *result = ck_alloc(sizeof(plugin_result_t));
                        memset(result, 0, sizeof(plugin_result_t));
                        result->decision = PLUGIN_CONTINUE;  // Just inform
                        result->reason = ck_alloc(128);
                        snprintf(result->reason, 128, 
                                "Plateau detected, prioritizing rare states");
                        return result;
                    }
                }
            } else {
                // Reset plateau counter on coverage gain
                data->scheduler.plateau_counter = 0;
                data->plateau_detected = 0;
            }
            
            data->last_coverage = cov->new_coverage;
            return NULL;
        }
        
        case HOOK_NEW_QUEUE_ENTRY: {
            // Update scheduler statistics
            update_state_rarity(&data->scheduler);
            return NULL;
        }
        
        case HOOK_PERIODIC: {
            // Periodic updates
            update_state_rarity(&data->scheduler);
            
            if (data->state_graph.node_count > 0) {
                plugin_log(plugin, 0, "States=%u, Transitions=%u, Plateau=%s",
                          data->state_graph.node_count,
                          data->state_graph.total_transitions,
                          data->plateau_detected ? "YES" : "NO");
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

plugin_t* register_scheduler_plugin(void) {
    plugin_ops_t ops = {
        .name = "StateScheduler",
        .version = "1.0.0",
        .author = "ChatAFL-Enhanced",
        .description = "State-aware test case scheduling with plateau detection",
        .init = scheduler_plugin_init,
        .cleanup = scheduler_plugin_cleanup,
        .on_hook = scheduler_on_hook,
        .enabled = true,
        .priority = 90,  // High priority, but after Verifier
        .config = NULL
    };
    
    return plugin_register(&ops);
}
