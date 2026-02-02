/*
 * afl-fuzz-plugin.h - Plugin Integration for afl-fuzz.c
 * 
 * This header provides clean integration points for the plugin system.
 * Include this in afl-fuzz.c instead of directly including module headers.
 */

#ifndef __AFL_FUZZ_PLUGIN_H
#define __AFL_FUZZ_PLUGIN_H

#include "plugin-interface.h"

/* ============================================================================
 * PLUGIN SYSTEM API (from plugin-manager.c)
 * ============================================================================ */
extern bool plugin_system_init(void *fuzzer_ctx);
extern void plugin_system_cleanup(void);
extern void plugin_print_stats(void);
extern plugin_decision_t plugin_invoke_hook(plugin_hook_type_t hook_type, hook_data_t *hook_data);

/* ============================================================================
 * PLUGIN REGISTRATION FUNCTIONS
 * 
 * Each plugin provides a registration function that returns a plugin handle.
 * These are called during fuzzer initialization.
 * ============================================================================ */

#ifdef CHATAFL_ENHANCED

/* Verifier plugin */
extern plugin_t* register_verifier_plugin(void);

/* CEGAR plugin */
extern plugin_t* register_cegar_plugin(void);

/* State Scheduler plugin */
extern plugin_t* register_scheduler_plugin(void);

#endif

/* ============================================================================
 * PLUGIN SYSTEM INITIALIZATION
 * ============================================================================ */

/**
 * Initialize the plugin system and register all built-in plugins.
 * Call this during fuzzer initialization.
 * 
 * @param fuzzer_ctx Opaque pointer to fuzzer state
 * @return true on success
 */
static inline bool setup_plugins(void *fuzzer_ctx) {
#ifdef CHATAFL_ENHANCED
    // Register all plugins
    plugin_t *verifier = register_verifier_plugin();
    plugin_t *cegar = register_cegar_plugin();
    plugin_t *scheduler = register_scheduler_plugin();
    
    // Check registration success
    if (!verifier || !cegar || !scheduler) {
        WARNF("Failed to register one or more plugins");
        return false;
    }
    
    // Initialize plugin system
    if (!plugin_system_init(fuzzer_ctx)) {
        WARNF("Failed to initialize plugin system");
        return false;
    }
    
    ACTF("Plugin system initialized successfully");
    return true;
#else
    // No plugins in base ChatAFL
    (void)fuzzer_ctx;  // Suppress unused warning
    return true;
#endif
}

/**
 * Cleanup the plugin system.
 * Call this during fuzzer shutdown.
 */
static inline void cleanup_plugins(void) {
#ifdef CHATAFL_ENHANCED
    plugin_print_stats();
    plugin_system_cleanup();
#endif
}

/* ============================================================================
 * HOOK INVOCATION HELPERS
 * 
 * These macros make it easy to invoke hooks from various points in afl-fuzz.c
 * ============================================================================ */

#ifdef CHATAFL_ENHANCED

#define PLUGIN_HOOK_INIT(in_dir_val, out_dir_val, target_val, tmout, memlim) \
    do { \
        hook_data_t hook_data = {0}; \
        hook_data.init.in_dir = in_dir_val; \
        hook_data.init.out_dir = out_dir_val; \
        hook_data.init.target_path = target_val; \
        hook_data.init.exec_tmout = tmout; \
        hook_data.init.mem_limit = memlim; \
        plugin_invoke_hook(HOOK_INIT, &hook_data); \
    } while(0)

#define PLUGIN_HOOK_PRE_FUZZ() \
    plugin_invoke_hook(HOOK_PRE_FUZZ, NULL)

#define PLUGIN_HOOK_POST_EXEC(tc, tc_len, cksum, exec_time_us, fault_val, trace, queue_ent) \
    do { \
        hook_data_t hook_data = {0}; \
        hook_data.exec.test_case = tc; \
        hook_data.exec.len = tc_len; \
        hook_data.exec.exec_cksum = cksum; \
        hook_data.exec.exec_us = exec_time_us; \
        hook_data.exec.fault = fault_val; \
        hook_data.exec.trace_bits = trace; \
        hook_data.exec.queue_entry = queue_ent; \
        plugin_invoke_hook(HOOK_POST_EXEC, &hook_data); \
    } while(0)

#define PLUGIN_HOOK_STATE_TRANSITION(from, to, msg, msg_len, cov_gain) \
    do { \
        hook_data_t hook_data = {0}; \
        hook_data.state.from_state = from; \
        hook_data.state.to_state = to; \
        hook_data.state.message = msg; \
        hook_data.state.msg_len = msg_len; \
        hook_data.state.coverage_gain = cov_gain; \
        plugin_invoke_hook(HOOK_STATE_TRANSITION, &hook_data); \
    } while(0)

#define PLUGIN_HOOK_COVERAGE_UPDATE(old_cov, new_cov, total_bm, virgin_cnt) \
    do { \
        hook_data_t hook_data = {0}; \
        hook_data.coverage.old_coverage = old_cov; \
        hook_data.coverage.new_coverage = new_cov; \
        hook_data.coverage.total_bitmap = total_bm; \
        hook_data.coverage.virgin_bits_count = virgin_cnt; \
        plugin_invoke_hook(HOOK_COVERAGE_UPDATE, &hook_data); \
    } while(0)

#define PLUGIN_HOOK_CRASH_FOUND(crash_in, crash_len_val, crash_path_val, sig) \
    do { \
        hook_data_t hook_data = {0}; \
        hook_data.crash.crash_input = crash_in; \
        hook_data.crash.crash_len = crash_len_val; \
        hook_data.crash.crash_path = crash_path_val; \
        hook_data.crash.signal = sig; \
        plugin_invoke_hook(HOOK_CRASH_FOUND, &hook_data); \
    } while(0)

#define PLUGIN_HOOK_PERIODIC(tot_execs, cur_t, q_size, pend_fav) \
    do { \
        hook_data_t hook_data = {0}; \
        hook_data.periodic.total_execs = tot_execs; \
        hook_data.periodic.cur_time = cur_t; \
        hook_data.periodic.queue_size = q_size; \
        hook_data.periodic.pending_favored = pend_fav; \
        plugin_invoke_hook(HOOK_PERIODIC, &hook_data); \
    } while(0)

#define PLUGIN_HOOK_CLEANUP() \
    plugin_invoke_hook(HOOK_CLEANUP, NULL)

#else

// No-op macros when plugins are disabled
#define PLUGIN_HOOK_INIT(...)
#define PLUGIN_HOOK_PRE_FUZZ()
#define PLUGIN_HOOK_POST_EXEC(...)
#define PLUGIN_HOOK_STATE_TRANSITION(...)
#define PLUGIN_HOOK_COVERAGE_UPDATE(...)
#define PLUGIN_HOOK_CRASH_FOUND(...)
#define PLUGIN_HOOK_CLEANUP()
#define PLUGIN_HOOK_PERIODIC(...)

#endif

#endif /* __AFL_FUZZ_PLUGIN_H */
