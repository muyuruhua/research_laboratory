/*
 * chatafl-enhanced-plugin-minimal.c - Minimal ChatAFL Enhanced plugin
 * 
 * A simplified version to test dynamic loading without complex dependencies
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "afl-plugin-api.h"

/* Plugin context structure */
typedef struct {
  bool initialized;
  uint64_t total_hook_calls;
  uint64_t init_time;
} chatafl_minimal_ctx_t;

/*******************************************
 * Plugin Metadata                         *
 *******************************************/

static const afl_plugin_info_t g_plugin_info = {
  .name = "ChatAFL-Enhanced-Minimal",
  .version = "1.0.0",
  .description = "Minimal test plugin for ChatAFL Enhanced features",
  .api_version = AFL_PLUGIN_API_VERSION,
  .hook_mask = (1U << AFL_HOOK_INIT) | (1U << AFL_HOOK_PERIODIC) | (1U << AFL_HOOK_CLEANUP),
  .priority = 0
};

/*******************************************
 * Plugin Export Functions                 *
 *******************************************/

/*
 * Initialize the plugin
 */
AFL_PLUGIN_EXPORT int afl_plugin_init(void** plugin_context) {
  
  chatafl_minimal_ctx_t* ctx = (chatafl_minimal_ctx_t*)calloc(1, sizeof(chatafl_minimal_ctx_t));
  if (!ctx) {
    fprintf(stderr, "[ChatAFL-Enhanced] Failed to allocate context\n");
    return -1;
  }

  ctx->initialized = true;
  ctx->total_hook_calls = 0;
  ctx->init_time = 0;
  
  *plugin_context = ctx;
  
  fprintf(stderr, "[ChatAFL-Enhanced] Plugin initialized successfully\n");
  return 0;
}

/*
 * Get plugin metadata
 */
AFL_PLUGIN_EXPORT const afl_plugin_info_t* afl_plugin_get_info(void) {
  return &g_plugin_info;
}

/*
 * Invoke hook
 */
AFL_PLUGIN_EXPORT afl_plugin_decision_t afl_plugin_invoke_hook(
  afl_hook_type_t hook_type,
  afl_hook_data_t* hook_data,
  void* plugin_context) {
  
  chatafl_minimal_ctx_t* ctx = (chatafl_minimal_ctx_t*)plugin_context;
  
  if (!ctx || !ctx->initialized) {
    return AFL_DECISION_CONTINUE;
  }

  ctx->total_hook_calls++;

  switch (hook_type) {
    case AFL_HOOK_INIT:
      fprintf(stderr, "[ChatAFL-Enhanced] INIT hook called\n");
      if (hook_data && hook_data->init.input_dir) {
        fprintf(stderr, "  Input dir: %s\n", hook_data->init.input_dir);
      }
      if (hook_data && hook_data->init.output_dir) {
        fprintf(stderr, "  Output dir: %s\n", hook_data->init.output_dir);
      }
      if (hook_data && hook_data->init.target_path) {
        fprintf(stderr, "  Target: %s\n", hook_data->init.target_path);
      }
      break;

    case AFL_HOOK_PERIODIC:
      if (ctx->total_hook_calls % 1000 == 0) {
        fprintf(stderr, "[ChatAFL-Enhanced] PERIODIC hook #%llu\n", (unsigned long long)ctx->total_hook_calls);
        fprintf(stderr, "  Total execs: %llu\n", (unsigned long long)hook_data->periodic.total_execs);
        fprintf(stderr, "  Queue size: %llu\n", (unsigned long long)hook_data->periodic.queue_size);
        fprintf(stderr, "  Exec/sec: %.2f\n", hook_data->periodic.exec_per_sec);
      }
      break;

    case AFL_HOOK_CLEANUP:
      fprintf(stderr, "[ChatAFL-Enhanced] CLEANUP hook called\n");
      fprintf(stderr, "  Total hook calls: %llu\n", (unsigned long long)ctx->total_hook_calls);
      break;

    default:
      break;
  }

  return AFL_DECISION_CONTINUE;
}
