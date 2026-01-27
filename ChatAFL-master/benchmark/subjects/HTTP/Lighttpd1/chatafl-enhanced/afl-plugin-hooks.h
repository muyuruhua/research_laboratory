/*
 * afl-plugin-hooks.h - Minimal hook integration for AFL plugin system
 * 
 * This header provides lightweight hook macros that can be inserted into
 * afl-fuzz.c without modifying its core logic. When plugins are not loaded,
 * these macros compile to no-ops with zero overhead.
 */

#ifndef _AFL_PLUGIN_HOOKS_H
#define _AFL_PLUGIN_HOOKS_H

#include "afl-plugin-loader.h"

/* Hook invocation macros - compile to no-ops when no plugins loaded */

#define AFL_HOOK_CALL_INIT(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_invoke_hook(AFL_HOOK_INIT, (hook_data_ptr)); \
    } \
  } while (0)

#define AFL_HOOK_CALL_PRE_FUZZ(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_plugin_decision_t __decision = afl_invoke_hook(AFL_HOOK_PRE_FUZZ, (hook_data_ptr)); \
      if (__decision == AFL_DECISION_SKIP) continue; \
      if (__decision == AFL_DECISION_STOP) goto stop_fuzzing; \
    } \
  } while (0)

#define AFL_HOOK_CALL_POST_EXEC(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_invoke_hook(AFL_HOOK_POST_EXEC, (hook_data_ptr)); \
    } \
  } while (0)

#define AFL_HOOK_CALL_STATE_TRANSITION(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_invoke_hook(AFL_HOOK_STATE_TRANSITION, (hook_data_ptr)); \
    } \
  } while (0)

#define AFL_HOOK_CALL_COVERAGE_UPDATE(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_invoke_hook(AFL_HOOK_COVERAGE_UPDATE, (hook_data_ptr)); \
    } \
  } while (0)

#define AFL_HOOK_CALL_CRASH_FOUND(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_invoke_hook(AFL_HOOK_CRASH_FOUND, (hook_data_ptr)); \
    } \
  } while (0)

#define AFL_HOOK_CALL_HANG_FOUND(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_plugin_decision_t __decision = afl_invoke_hook(AFL_HOOK_HANG_FOUND, (hook_data_ptr)); \
    } \
  } while (0)

#define AFL_HOOK_CALL_PERIODIC(hook_data_ptr) \
  do { \
    if (afl_plugins_enabled()) { \
      afl_invoke_hook(AFL_HOOK_PERIODIC, (hook_data_ptr)); \
    } \
  } while (0)

#define AFL_HOOK_CALL_CLEANUP() \
  do { \
    if (afl_plugins_enabled()) { \
      afl_hook_data_t __cleanup_data = {0}; \
      afl_invoke_hook(AFL_HOOK_CLEANUP, &__cleanup_data); \
    } \
  } while (0)

#endif /* _AFL_PLUGIN_HOOKS_H */
