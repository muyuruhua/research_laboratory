/*
 * chatafl-enhanced-plugin.c - ChatAFL Enhanced functionality as a .so plugin
 * 
 * This file packages all ChatAFL-Enhanced features into a self-contained
 * dynamic library that can be loaded by AFL without modifying afl-fuzz.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afl-plugin-api.h"

/* Include the actual Enhanced modules */
#include "plugin-manager.h"
#include "plugin-interface.h"

/* Plugin context structure */
typedef struct {
  bool initialized;
  uint64_t total_hook_calls;
  uint64_t last_periodic_time;
} chatafl_plugin_ctx_t;

/*******************************************
 * Plugin Metadata                         *
 *******************************************/

static const afl_plugin_info_t g_plugin_info = {
  .name = "ChatAFL-Enhanced",
  .version = "1.0.0",
  .description = "Advanced verification, CEGAR, and state scheduling",
  .api_version = AFL_PLUGIN_API_VERSION,
  .hook_mask = AFL_HOOK_MASK(
    AFL_HOOK_INIT,
    AFL_HOOK_POST_EXEC,
    AFL_HOOK_COVERAGE_UPDATE,
    AFL_HOOK_CRASH_FOUND,
    AFL_HOOK_PERIODIC,
    AFL_HOOK_CLEANUP
  ),
  .priority = 0  /* Highest priority */
};

/*******************************************
 * Helper Functions                        *
 *******************************************/

/* Convert AFL hook type to plugin_hook_type_t */
static plugin_hook_type_t convert_hook_type(afl_hook_type_t afl_hook) {
  switch (afl_hook) {
    case AFL_HOOK_INIT: return PLUGIN_HOOK_INIT;
    case AFL_HOOK_POST_EXEC: return PLUGIN_HOOK_POST_EXEC;
    case AFL_HOOK_COVERAGE_UPDATE: return PLUGIN_HOOK_COVERAGE_UPDATE;
    case AFL_HOOK_CRASH_FOUND: return PLUGIN_HOOK_CRASH_FOUND;
    case AFL_HOOK_PERIODIC: return PLUGIN_HOOK_PERIODIC;
    case AFL_HOOK_CLEANUP: return PLUGIN_HOOK_CLEANUP;
    default: return PLUGIN_HOOK_INIT;  /* Fallback */
  }
}

/* Convert AFL decision to plugin_decision_t */
static afl_plugin_decision_t convert_decision(plugin_decision_t plugin_decision) {
  switch (plugin_decision) {
    case PLUGIN_DECISION_CONTINUE: return AFL_DECISION_CONTINUE;
    case PLUGIN_DECISION_SKIP: return AFL_DECISION_SKIP;
    default: return AFL_DECISION_CONTINUE;
  }
}

/* Create hook_data_t from afl_hook_data_t */
static hook_data_t* create_hook_data(afl_hook_type_t hook_type, afl_hook_data_t* afl_data) {
  
  hook_data_t* hook_data = (hook_data_t*)calloc(1, sizeof(hook_data_t));
  if (!hook_data) return NULL;

  switch (hook_type) {
    
    case AFL_HOOK_INIT:
      hook_data->init.input_dir = afl_data->init.input_dir;
      hook_data->init.output_dir = afl_data->init.output_dir;
      hook_data->init.target_path = afl_data->init.target_path;
      break;

    case AFL_HOOK_POST_EXEC:
      hook_data->post_exec.testcase = afl_data->post_exec.testcase;
      hook_data->post_exec.testcase_len = afl_data->post_exec.testcase_len;
      hook_data->post_exec.exec_us = afl_data->post_exec.exec_us;
      hook_data->post_exec.trace_bits = afl_data->post_exec.trace_bits;
      hook_data->post_exec.new_coverage = afl_data->post_exec.new_coverage;
      break;

    case AFL_HOOK_COVERAGE_UPDATE:
      hook_data->coverage.testcase = afl_data->coverage.testcase;
      hook_data->coverage.testcase_len = afl_data->coverage.testcase_len;
      hook_data->coverage.virgin_bits = afl_data->coverage.virgin_bits;
      break;

    case AFL_HOOK_CRASH_FOUND:
      hook_data->crash.testcase = afl_data->crash.testcase;
      hook_data->crash.testcase_len = afl_data->crash.testcase_len;
      hook_data->crash.signal = afl_data->crash.signal;
      hook_data->crash.crash_path = afl_data->crash.crash_path;
      break;

    case AFL_HOOK_PERIODIC:
      /* Map AFL stats to plugin stats if needed */
      break;

    default:
      break;
  }

  return hook_data;
}

/*******************************************
 * Plugin Export Functions                 *
 *******************************************/

/*
 * Initialize the ChatAFL-Enhanced plugin
 */
AFL_PLUGIN_EXPORT int afl_plugin_init(void** plugin_context) {
  
  chatafl_plugin_ctx_t* ctx = (chatafl_plugin_ctx_t*)calloc(1, sizeof(chatafl_plugin_ctx_t));
  if (!ctx) {
    return -1;
  }

  /* Initialize the plugin manager */
  if (plugin_manager_init() != 0) {
    free(ctx);
    return -1;
  }

  /* Setup all plugins (verifier, CEGAR, scheduler) */
  if (setup_plugins() != 0) {
    plugin_manager_cleanup();
    free(ctx);
    return -1;
  }

  ctx->initialized = true;
  *plugin_context = ctx;

  return 0;
}

/*
 * Get plugin metadata
 */
AFL_PLUGIN_EXPORT const afl_plugin_info_t* afl_plugin_get_info(void) {
  return &g_plugin_info;
}

/*
 * Invoke hook on ChatAFL-Enhanced subsystems
 */
AFL_PLUGIN_EXPORT afl_plugin_decision_t afl_plugin_invoke_hook(
  afl_hook_type_t hook_type,
  afl_hook_data_t* hook_data,
  void* plugin_context) {
  
  chatafl_plugin_ctx_t* ctx = (chatafl_plugin_ctx_t*)plugin_context;
  
  if (!ctx || !ctx->initialized) {
    return AFL_DECISION_CONTINUE;
  }

  ctx->total_hook_calls++;

  /* Convert AFL hook data to plugin hook data */
  hook_data_t* internal_hook_data = create_hook_data(hook_type, hook_data);
  if (!internal_hook_data) {
    return AFL_DECISION_CONTINUE;
  }

  /* Invoke the plugin manager */
  plugin_hook_type_t internal_hook_type = convert_hook_type(hook_type);
  plugin_decision_t decision = plugin_invoke_hook(internal_hook_type, internal_hook_data);

  /* Cleanup */
  free(internal_hook_data);

  /* Convert back to AFL decision type */
  return convert_decision(decision);
}
