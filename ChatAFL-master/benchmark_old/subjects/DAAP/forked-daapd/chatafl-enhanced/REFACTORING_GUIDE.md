/*
 * afl-fuzz-refactored.patch
 * 
 * Key modifications to afl-fuzz.c to integrate plugin system.
 * Apply these changes to make afl-fuzz.c follow the Open/Closed Principle.
 */

/* ============================================================================
 * STEP 1: Replace direct module includes with plugin interface
 * ============================================================================
 * 
 * BEFORE (Lines 45-60):
 * 
 * #include "chat-llm.h"
 * #ifdef CHATAFL_ENHANCED
 * #include "verifier.h"
 * #include "cegar-optimized.h"
 * #include "cegar-refinement.h"
 * #include "state-scheduler.h"
 * #include "state-graph.h"
 * #include "cfg-parser.h"
 * #include "module-interface.h"
 * #define CEGAR_SIMULATION_MODE 1
 * #endif
 * 
 * AFTER:
 * 
 * #include "chat-llm.h"
 * #ifdef CHATAFL_ENHANCED
 * #include "afl-fuzz-plugin.h"
 * #else
 * static inline bool setup_plugins(void *ctx) { return true; }
 * static inline void cleanup_plugins(void) { }
 * #endif
 */

/* ============================================================================
 * STEP 2: Remove global module variables (Lines 130-142)
 * ============================================================================
 * 
 * REMOVE these lines:
 * 
 * #ifdef CHATAFL_ENHANCED
 * static u64 g_verifier_checks = 0;
 * static u64 g_verifier_rejects = 0;
 * StateGraph g_state_graph = {0};
 * static state_scheduler_t g_scheduler = {0};
 * static verifier_config_t g_verifier_config = {0};
 * CEGARConfig g_cegar_config = {0};
 * static u32 g_current_state_id = 0;
 * static u32 g_previous_state_id = 0;
 * static float g_last_coverage = 0.0f;
 * static int g_plateau_detected = 0;
 * #endif
 * 
 * REASON: Plugins manage their own state internally.
 */

/* ============================================================================
 * STEP 3: Replace module initialization code (Around line 11025-11127)
 * ============================================================================
 * 
 * BEFORE:
 * 
 * #ifdef CHATAFL_ENHANCED
 *   g_verifier_module = verifier_module_create(...);
 *   g_scheduler_module = scheduler_module_create(...);
 *   state_graph_init(&g_state_graph);
 *   state_scheduler_init(&g_scheduler, ...);
 *   verifier_init(&g_verifier_config);
 * #endif
 * 
 * AFTER:
 * 
 * // Initialize plugin system
 * setup_plugins(NULL);  // Add this single line
 * 
 * PLUGIN_HOOK_INIT(in_dir, out_dir, target_path, exec_tmout, mem_limit);
 */

/* ============================================================================
 * STEP 4: Replace direct module calls in fuzzing loop (Lines 4686-4950)
 * ============================================================================
 * 
 * BEFORE:
 * 
 * #ifdef CHATAFL_ENHANCED
 *   g_verifier_checks++;
 *   if (g_module_interface_enabled && g_verifier_module) {
 *     verifier_module_process(...);
 *   }
 *   if (!acceptability && g_cegar_config.enabled && should_trigger_cegar(...)) {
 *     cegar_patch_t *patch = cegar_refine_message(...);
 *     ...
 *   }
 *   state_graph_add_transition(&g_state_graph, ...);
 *   update_state_rarity(&g_scheduler);
 * #endif
 * 
 * AFTER:
 * 
 * // Single hook invocation - plugins handle the rest
 * PLUGIN_HOOK_POST_EXEC(out_buf, len, cksum, exec_us, fault, trace_bits, q);
 */

/* ============================================================================
 * STEP 5: Replace cleanup code (Lines 11400-11480)
 * ============================================================================
 * 
 * BEFORE:
 * 
 * #ifdef CHATAFL_ENHANCED
 *   if (g_cegar_config.enabled) {
 *     print_cegar_stats();
 *     cegar_cleanup();
 *   }
 *   state_scheduler_cleanup(&g_scheduler);
 *   ACTF("[VERIFIER] Total checks: %llu", g_verifier_checks);
 *   ...
 * #endif
 * 
 * AFTER:
 * 
 * // Single cleanup call - plugins clean themselves up
 * cleanup_plugins();
 */

/* ============================================================================
 * STEP 6: Add periodic hook in main fuzzing loop
 * ============================================================================
 * 
 * ADD this code in the periodic update section (around line 9000):
 * 
 * // Periodically invoke plugins (e.g., every 1000 execs)
 * if (total_execs % 1000 == 0) {
 *   PLUGIN_HOOK_PERIODIC(total_execs, get_cur_time(), 
 *                        queued_paths, pending_favored);
 * }
 */

/* ============================================================================
 * SUMMARY OF CHANGES
 * ============================================================================
 * 
 * Lines changed: ~600 lines reduced to ~20 lines
 * Coupling: Eliminated (core doesn't know about modules)
 * Extensibility: High (add new plugins without touching core)
 * OCP compliance: FULL (core closed for modification, open for extension)
 * 
 * Benefits:
 * 1. No #ifdef blocks scattered through code
 * 2. No global variables for module state
 * 3. No direct function calls to modules
 * 4. Easy to add/remove plugins without modifying core
 * 5. Plugins can be enabled/disabled at runtime
 * 6. Clear separation of concerns
 * 
 * Migration path:
 * 1. Keep both versions during transition
 * 2. Add -DUSE_PLUGIN_SYSTEM flag to enable new architecture
 * 3. Test thoroughly
 * 4. Remove old code once validated
 */
