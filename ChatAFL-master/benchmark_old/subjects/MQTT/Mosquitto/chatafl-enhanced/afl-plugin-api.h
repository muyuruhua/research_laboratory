/*
 * afl-plugin-api.h - Standard API for AFL dynamic plugins
 * 
 * This header defines the interface contract between AFL and dynamically
 * loaded plugins (.so files). Plugins implement this interface to extend
 * AFL's functionality without modifying the core fuzzer code.
 * 
 * Design Philosophy:
 * - Zero modification to afl-fuzz.c (100% OCP compliance)
 * - Dynamic loading via dlopen/dlsym
 * - Self-contained plugins with no static dependencies
 * - Hook-based architecture for extensibility
 */

#ifndef _AFL_PLUGIN_API_H
#define _AFL_PLUGIN_API_H

#include <stdint.h>
#include <stdbool.h>

/* Plugin API version for compatibility checking */
#define AFL_PLUGIN_API_VERSION 1

/*******************************************
 * Plugin Hook Types                       *
 *******************************************/

typedef enum {
  AFL_HOOK_INIT = 0,           /* Called once after fuzzer initialization */
  AFL_HOOK_PRE_FUZZ,           /* Called before each fuzz iteration */
  AFL_HOOK_POST_EXEC,          /* Called after each target execution */
  AFL_HOOK_STATE_TRANSITION,   /* Called when fuzzer state changes */
  AFL_HOOK_COVERAGE_UPDATE,    /* Called when new coverage is found */
  AFL_HOOK_CRASH_FOUND,        /* Called when a crash is detected */
  AFL_HOOK_HANG_FOUND,         /* Called when a hang is detected */
  AFL_HOOK_PERIODIC,           /* Called periodically (e.g., every second) */
  AFL_HOOK_CLEANUP,            /* Called before fuzzer shutdown */
  AFL_HOOK_MAX                 /* Sentinel value */
} afl_hook_type_t;

/*******************************************
 * Execution Result Types                  *
 *******************************************/

typedef enum {
  AFL_EXEC_NORMAL = 0,         /* Normal execution, no crash/hang */
  AFL_EXEC_CRASH,              /* Target crashed */
  AFL_EXEC_HANG,               /* Target timed out */
  AFL_EXEC_SKIP                /* Execution was skipped */
} afl_exec_result_t;

/*******************************************
 * Plugin Decision Types                   *
 *******************************************/

typedef enum {
  AFL_DECISION_CONTINUE = 0,   /* Continue normal fuzzing flow */
  AFL_DECISION_SKIP,           /* Skip this test case */
  AFL_DECISION_STOP            /* Stop fuzzing */
} afl_plugin_decision_t;

/*******************************************
 * Data Structures for Hook Callbacks     *
 *******************************************/

/* Hook data passed to INIT hook */
typedef struct {
  const char* input_dir;       /* -i directory path */
  const char* output_dir;      /* -o directory path */
  const char* target_path;     /* Target binary path */
  uint32_t exec_timeout;       /* Execution timeout in ms */
  uint64_t mem_limit;          /* Memory limit in MB */
  void* fuzzer_stats;          /* Opaque pointer to fuzzer stats */
} afl_hook_init_t;

/* Hook data passed to POST_EXEC hook */
typedef struct {
  uint8_t* testcase;           /* Test case data */
  uint32_t testcase_len;       /* Test case length */
  afl_exec_result_t result;    /* Execution result */
  uint64_t exec_us;            /* Execution time in microseconds */
  uint64_t exec_count;         /* Total executions so far */
  uint8_t* trace_bits;         /* Coverage bitmap (64KB) */
  bool new_coverage;           /* Whether new coverage was found */
} afl_hook_post_exec_t;

/* Hook data passed to COVERAGE_UPDATE hook */
typedef struct {
  uint8_t* testcase;           /* Test case that triggered new coverage */
  uint32_t testcase_len;       /* Test case length */
  uint32_t virgin_bits;        /* Number of virgin bits hit */
  uint8_t* virgin_map;         /* Virgin bitmap */
} afl_hook_coverage_t;

/* Hook data passed to CRASH_FOUND hook */
typedef struct {
  uint8_t* testcase;           /* Crashing test case */
  uint32_t testcase_len;       /* Test case length */
  uint32_t signal;             /* Signal that caused crash */
  const char* crash_path;      /* Path where crash was saved */
} afl_hook_crash_t;

/* Hook data passed to PERIODIC hook */
typedef struct {
  uint64_t total_execs;        /* Total executions */
  uint64_t queue_size;         /* Current queue size */
  uint64_t pending_favs;       /* Pending favorites */
  uint64_t crashes;            /* Total crashes found */
  uint64_t hangs;              /* Total hangs found */
  double exec_per_sec;         /* Execution speed */
  uint64_t runtime_sec;        /* Total runtime in seconds */
} afl_hook_periodic_t;

/* Generic hook data union */
typedef union {
  afl_hook_init_t init;
  afl_hook_post_exec_t post_exec;
  afl_hook_coverage_t coverage;
  afl_hook_crash_t crash;
  afl_hook_periodic_t periodic;
} afl_hook_data_t;

/*******************************************
 * Plugin Descriptor                       *
 *******************************************/

typedef struct {
  const char* name;            /* Plugin name (e.g., "ChatAFL-Enhanced") */
  const char* version;         /* Plugin version (e.g., "1.0.0") */
  const char* description;     /* Brief description */
  uint32_t api_version;        /* AFL_PLUGIN_API_VERSION */
  
  /* Hook subscription bitmap (bit N = subscribe to hook N) */
  uint32_t hook_mask;
  
  /* Priority for multi-plugin ordering (0 = highest) */
  uint32_t priority;
} afl_plugin_info_t;

/*******************************************
 * Plugin Callback Function Types          *
 *******************************************/

/* Hook callback function signature */
typedef afl_plugin_decision_t (*afl_hook_callback_t)(
  afl_hook_type_t hook_type,
  afl_hook_data_t* hook_data,
  void* plugin_context
);

/*******************************************
 * Plugin Export Interface                 *
 *******************************************/

/*
 * Every plugin .so MUST export these three symbols:
 * 
 * 1. afl_plugin_init() - Called once when plugin is loaded
 *    Returns: 0 on success, -1 on error
 * 
 * 2. afl_plugin_get_info() - Returns plugin metadata
 *    Returns: Pointer to afl_plugin_info_t struct
 * 
 * 3. afl_plugin_invoke_hook() - Called for each subscribed hook
 *    Returns: Plugin decision (CONTINUE/SKIP/STOP)
 */

typedef int (*afl_plugin_init_fn_t)(void** plugin_context);
typedef const afl_plugin_info_t* (*afl_plugin_get_info_fn_t)(void);
typedef afl_plugin_decision_t (*afl_plugin_invoke_hook_fn_t)(
  afl_hook_type_t hook_type,
  afl_hook_data_t* hook_data,
  void* plugin_context
);

/* Macro to define plugin exports in .so implementation */
#define AFL_PLUGIN_EXPORT __attribute__((visibility("default")))

/*******************************************
 * Helper Macros                           *
 *******************************************/

/* Create hook subscription mask */
#define AFL_HOOK_MASK(hooks...) ({ \
  uint32_t mask = 0; \
  uint32_t hook_array[] = {hooks}; \
  for (size_t i = 0; i < sizeof(hook_array)/sizeof(uint32_t); i++) \
    mask |= (1U << hook_array[i]); \
  mask; \
})

/* Check if hook is subscribed */
#define AFL_HOOK_SUBSCRIBED(mask, hook) ((mask) & (1U << (hook)))

#endif /* _AFL_PLUGIN_API_H */
