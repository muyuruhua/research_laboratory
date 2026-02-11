#ifndef __FUZZER_EXTENSION_H
#define __FUZZER_EXTENSION_H

#include "types.h"
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Fuzzer Extension Framework - Open/Closed Principle Compliant
 * ============================================================================
 * 
 * This framework allows extending AFL without modifying afl-fuzz.c.
 * Extensions register callbacks that are invoked at strategic hook points.
 * 
 * Design Principles:
 * - Open for extension: Add new extensions by implementing callbacks
 * - Closed for modification: No changes to afl-fuzz.c required
 * - Loose coupling: Extensions communicate through well-defined interfaces
 */

/* Forward declarations for data structures */
struct queue_entry;

/* ============================================================================
 * Extension Hook Points (Strategic Locations in Fuzzing Loop)
 * ============================================================================ */

typedef enum {
    HOOK_BEFORE_FUZZING_START,      // Called once before fuzzing begins
    HOOK_AFTER_QUEUE_INIT,          // Called after initial queue is populated
    HOOK_BEFORE_QUEUE_CYCLE,        // Called at the start of each queue cycle
    HOOK_BEFORE_FUZZ_ONE,           // Called before fuzzing each queue entry
    HOOK_AFTER_EXECUTION,           // Called after executing a test case
    HOOK_ON_NEW_COVERAGE,           // Called when new coverage is found
    HOOK_ON_NEW_CRASH,              // Called when a crash is found
    HOOK_ON_QUEUE_UPDATE,           // Called when queue is updated
    HOOK_BEFORE_MUTATION,           // Called before mutating input
    HOOK_AFTER_MUTATION,            // Called after mutating input
    HOOK_ON_PLATEAU_DETECTED,       // Called when no progress for N execs
    HOOK_BEFORE_FUZZING_END,        // Called once before fuzzing ends
    HOOK_COUNT                       // Total number of hooks
} hook_point_t;

/* ============================================================================
 * Extension Context - Shared State Across Hooks
 * ============================================================================ */

typedef struct {
    /* AFL internal state (read-only for extensions) */
    uint64_t *virgin_bits;          // Coverage bitmap
    uint64_t total_execs;           // Total executions
    uint32_t queued_paths;          // Queue size
    uint32_t unique_crashes;        // Crash count
    uint32_t unique_hangs;          // Hang count
    
    /* Current execution state */
    struct queue_entry *current_queue_entry;
    uint8_t *current_input;         // Current test case data
    uint32_t current_input_len;     // Current test case length
    uint64_t current_exec_us;       // Execution time (microseconds)
    uint8_t current_fault;          // Fault status (crash, hang, etc.)
    
    /* Protocol-specific state (for network fuzzing) */
    char *protocol_name;            // e.g., "FTP", "HTTP"
    char *current_state;            // Protocol state name
    char *previous_state;           // Previous state
    char *sut_host;                 // System Under Test host
    int sut_port;                   // SUT port
    
    /* Extension private data */
    void *extension_private;        // Extension can store anything here
    
    /* Control flags */
    bool skip_current_mutation;     // Extension can set to skip mutation
    bool request_llm_assist;        // Extension can request LLM help
    bool stop_fuzzing;              // Extension can request stop
    
} extension_context_t;

/* ============================================================================
 * Extension Callback Definitions
 * ============================================================================ */

/* Generic hook callback signature */
typedef void (*hook_callback_t)(extension_context_t *ctx);

/* Specialized callbacks with additional parameters */

/* Called before mutating input - can modify mutation strategy */
typedef void (*before_mutation_callback_t)(
    extension_context_t *ctx,
    uint8_t **in_buf,              // Input buffer (can be modified)
    uint32_t *in_len,              // Input length (can be modified)
    uint32_t *mutation_strategy    // Mutation type (can be modified)
);

/* Called after execution - can analyze results */
typedef void (*after_execution_callback_t)(
    extension_context_t *ctx,
    uint8_t *trace_bits,           // Execution trace
    uint32_t trace_len,            // Trace length
    uint8_t fault_type,            // Fault type (0=none, 1=crash, 2=hang)
    char *server_response,         // Server response (for network fuzzing)
    int response_code              // Response code
);

/* Called on new coverage - can generate targeted inputs */
typedef void (*new_coverage_callback_t)(
    extension_context_t *ctx,
    uint64_t *new_bits,            // Newly covered bits
    uint32_t new_bits_count        // Number of new bits
);

/* Called on plateau - can request LLM assistance */
typedef void (*plateau_callback_t)(
    extension_context_t *ctx,
    uint32_t execs_without_progress, // Number of execs without new coverage
    uint32_t plateau_threshold       // Threshold for plateau detection
);

/* ============================================================================
 * Extension Registration Structure
 * ============================================================================ */

typedef struct fuzzer_extension {
    /* Extension metadata */
    const char *name;               // Extension name (e.g., "ChatAFL-Opt")
    const char *version;            // Extension version
    const char *description;        // Short description
    
    /* Lifecycle callbacks */
    int (*init)(extension_context_t *ctx);  // Initialize extension
    void (*cleanup)(extension_context_t *ctx); // Cleanup extension
    
    /* Generic hook callbacks (array indexed by hook_point_t) */
    hook_callback_t hooks[HOOK_COUNT];
    
    /* Specialized callbacks (optional) */
    before_mutation_callback_t before_mutation;
    after_execution_callback_t after_execution;
    new_coverage_callback_t on_new_coverage;
    plateau_callback_t on_plateau;
    
    /* Configuration */
    bool enabled;                   // Is extension enabled?
    int priority;                   // Execution priority (higher = earlier)
    
    /* Next extension in chain */
    struct fuzzer_extension *next;
    
} fuzzer_extension_t;

/* ============================================================================
 * Extension Manager - Manages All Registered Extensions
 * ============================================================================ */

typedef struct {
    fuzzer_extension_t *extensions; // Linked list of extensions
    int extension_count;            // Number of registered extensions
    extension_context_t *global_ctx; // Shared context
    bool initialized;               // Manager initialized?
} extension_manager_t;

/* ============================================================================
 * Public API - Used by afl-fuzz.c (Minimal Changes)
 * ============================================================================ */

/* Initialize extension manager (called once in main()) */
extension_manager_t* init_extension_manager(void);

/* Register an extension (called by each extension module) */
int register_extension(extension_manager_t *mgr, fuzzer_extension_t *ext);

/* Trigger a hook point (called at strategic locations in afl-fuzz.c) */
void trigger_hook(extension_manager_t *mgr, hook_point_t hook);

/* Specialized hook triggers with additional data */
void trigger_before_mutation(extension_manager_t *mgr, 
                            uint8_t **in_buf, uint32_t *in_len, 
                            uint32_t *mutation_strategy);

void trigger_after_execution(extension_manager_t *mgr,
                            uint8_t *trace_bits, uint32_t trace_len,
                            uint8_t fault_type,
                            char *server_response, int response_code);

void trigger_new_coverage(extension_manager_t *mgr,
                         uint64_t *new_bits, uint32_t new_bits_count);

void trigger_plateau(extension_manager_t *mgr,
                    uint32_t execs_without_progress,
                    uint32_t plateau_threshold);

/* Update extension context (called when AFL state changes) */
void update_extension_context(extension_manager_t *mgr,
                             struct queue_entry *q,
                             uint8_t *input, uint32_t input_len,
                             uint64_t exec_us, uint8_t fault);

/* Cleanup all extensions (called before exit) */
void cleanup_extensions(extension_manager_t *mgr);

/* ============================================================================
 * Helper Functions for Extensions
 * ============================================================================ */

/* Get AFL's virgin_bits (for coverage analysis) */
uint64_t* get_virgin_bits(extension_manager_t *mgr);

/* Get current execution count */
uint64_t get_total_execs(extension_manager_t *mgr);

/* Check if extension should be invoked based on config */
bool should_invoke_extension(fuzzer_extension_t *ext);

#endif /* __FUZZER_EXTENSION_H */
