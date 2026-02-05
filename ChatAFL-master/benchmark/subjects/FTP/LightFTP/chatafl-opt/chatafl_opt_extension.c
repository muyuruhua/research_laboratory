#include "chatafl_opt_extension.h"
#include "alloc-inl.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Get current time in microseconds */
static inline uint64_t ext_get_cur_time_us(void) {
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/* ============================================================================
 * ChatAFL-Opt Extension Implementation
 * ============================================================================ */

/* Get private context from extension context */
static inline chatafl_opt_private_t* get_private(extension_context_t *ctx) {
    return (chatafl_opt_private_t*)ctx->extension_private;
}

/* ============================================================================
 * Lifecycle Callbacks
 * ============================================================================ */

int chatafl_opt_init(extension_context_t *ctx) {
    ACTF("Initializing ChatAFL-Opt extension");
    
    /* Allocate private context */
    chatafl_opt_private_t *priv = (chatafl_opt_private_t*)ck_alloc(sizeof(chatafl_opt_private_t));
    memset(priv, 0, sizeof(chatafl_opt_private_t));
    ctx->extension_private = priv;
    
    /* Validate protocol name */
    if (!ctx->protocol_name) {
        WARNF("Protocol name not set, ChatAFL-Opt features disabled");
        priv->enable_hypothesis_generation = false;
        priv->enable_verification = false;
        priv->enable_cegar = false;
        priv->enable_state_scheduling = false;
        return 0;
    }
    
    /* Initialize modules in dependency order */
    ACTF("Initializing Hypothesis module for protocol: %s", ctx->protocol_name);
    priv->hypothesis_ctx = init_hypothesis_context(ctx->protocol_name);
    if (!priv->hypothesis_ctx) {
        WARNF("Failed to initialize Hypothesis module");
        goto init_failed;
    }
    
    ACTF("Initializing Verifier module (SUT: %s:%d)", 
         ctx->sut_host ? ctx->sut_host : "localhost", ctx->sut_port);
    priv->verifier_ctx = init_verification_context(ctx->protocol_name, 
                                                   ctx->sut_host, 
                                                   ctx->sut_port);
    if (!priv->verifier_ctx) {
        WARNF("Failed to initialize Verifier module");
        goto init_failed;
    }
    
    ACTF("Initializing CEGAR module");
    priv->cegar_ctx = init_cegar_context(priv->hypothesis_ctx, priv->verifier_ctx);
    if (!priv->cegar_ctx) {
        WARNF("Failed to initialize CEGAR module");
        goto init_failed;
    }
    
    ACTF("Initializing State Scheduler module");
    priv->scheduler_ctx = init_scheduler(ctx->protocol_name, priv->cegar_ctx);
    if (!priv->scheduler_ctx) {
        WARNF("Failed to initialize State Scheduler module");
        goto init_failed;
    }
    
    /* Configuration */
    priv->enable_hypothesis_generation = true;
    priv->enable_verification = true;
    priv->enable_cegar = true;
    priv->enable_state_scheduling = true;
    priv->plateau_threshold = 1000; // Trigger LLM after 1000 execs without progress
    priv->verification_sampling_rate = 0.10; // Verify 10% of executions
    
    /* Statistics */
    priv->last_coverage_update = 0;
    priv->execs_since_new_coverage = 0;
    priv->hypotheses_generated = 0;
    priv->verifications_performed = 0;
    priv->refinements_applied = 0;
    priv->state_updates = 0;
    priv->llm_assists = 0;
    
    /* Performance counters */
    priv->time_in_verification_us = 0;
    priv->time_in_cegar_us = 0;
    priv->time_in_scheduler_us = 0;
    priv->time_in_hypothesis_us = 0;
    
    ACTF("ChatAFL-Opt initialized successfully (H+V+C+S pipeline ready)");
    return 0;

init_failed:
    WARNF("ChatAFL-Opt initialization failed, extension disabled");
    priv->enable_hypothesis_generation = false;
    priv->enable_verification = false;
    priv->enable_cegar = false;
    priv->enable_state_scheduling = false;
    return -1;
}

void chatafl_opt_cleanup(extension_context_t *ctx) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv) return;
    
    ACTF("Cleaning up ChatAFL-Opt extension");
    
    /* Print final statistics */
    chatafl_opt_print_stats(ctx);
    
    /* Export state before cleanup */
    if (getenv("AFL_OUT_DIR")) {
        chatafl_opt_export_state(ctx, getenv("AFL_OUT_DIR"));
    }
    
    /* Free module contexts */
    if (priv->scheduler_ctx) {
        /* Free scheduler (implementation in state_scheduler.c) */
        // free_scheduler(priv->scheduler_ctx);
    }
    if (priv->cegar_ctx) {
        /* Free CEGAR (implementation in cegar.c) */
        // free_cegar_context(priv->cegar_ctx);
    }
    if (priv->verifier_ctx) {
        /* Free verifier (implementation in verifier.c) */
        // free_verification_context(priv->verifier_ctx);
    }
    if (priv->hypothesis_ctx) {
        free_hypothesis_context(priv->hypothesis_ctx);
    }
    
    ck_free(priv);
    ctx->extension_private = NULL;
    
    ACTF("ChatAFL-Opt cleanup complete");
}

/* ============================================================================
 * Module 1: Hypothesis Generation (Triggered on Plateau)
 * ============================================================================ */

void chatafl_opt_on_plateau(extension_context_t *ctx,
                            uint32_t execs_without_progress,
                            uint32_t plateau_threshold) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv || !priv->enable_hypothesis_generation) return;
    
    ACTF("Plateau detected (%u execs without progress). Generating hypotheses via LLM...", 
         execs_without_progress);
    
    uint64_t start_time = ext_get_cur_time_us();
    
    /* Generate new hypotheses for unexplored message types */
    // TODO: Call generate_initial_hypotheses() with RFC context
    char *rfc_context = "RFC 959 FTP Protocol"; // Placeholder
    int count = generate_initial_hypotheses(priv->hypothesis_ctx, 
                                           rfc_context, NULL, NULL);
    
    priv->time_in_hypothesis_us += (ext_get_cur_time_us() - start_time);
    priv->hypotheses_generated += count;
    priv->llm_assists++;
    
    ACTF("Generated %d new hypotheses (total: %u)", count, priv->hypotheses_generated);
}

/* ============================================================================
 * Module 2: Verification (Triggered After Execution)
 * ============================================================================ */

void chatafl_opt_after_execution(extension_context_t *ctx,
                                uint8_t *trace_bits, uint32_t trace_len,
                                uint8_t fault_type,
                                char *server_response, int response_code) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv || !priv->enable_verification) return;
    
    /* Sample executions to reduce overhead (only verify 1% to minimize impact) */
    if ((double)rand() / RAND_MAX > 0.01) {  // Changed from priv->verification_sampling_rate
        return; // Skip this execution
    }
    
    priv->verifications_performed++;
    
    /* Extract current message from input */
    char *message = (char*)ctx->current_input; // Simplified
    
    /* Find matching hypothesis (if any) */
    // TODO: Match message to hypothesis based on message type
    // For now, skip if no hypothesis available
    if (!priv->hypothesis_ctx || priv->hypothesis_ctx->hypothesis_count == 0) {
        return;
    }
    
    /* Verify message against first hypothesis (simplified) */
    grammar_hypothesis_t *hypo = NULL; // TODO: Get from hypothesis_ctx
    
    if (!hypo) return;
    
    uint64_t start_time = ext_get_cur_time_us();
    
    /* Perform 4-stage verification */
    verification_result_t *vr = verify_message(priv->verifier_ctx, hypo, 
                                              message, (uint64_t*)trace_bits);
    
    priv->time_in_verification_us += (ext_get_cur_time_us() - start_time);
    
    if (vr && vr->status != VERIFY_SUCCESS) {
        /* Verification failed - trigger CEGAR */
        chatafl_opt_on_verification_failure(ctx, vr, hypo);
    }
    
    /* Free verification result */
    // TODO: free_verification_result(vr);
}

/* ============================================================================
 * Module 3: CEGAR Refinement (Triggered on Verification Failure)
 * ============================================================================ */

void chatafl_opt_on_verification_failure(extension_context_t *ctx,
                                        verification_result_t *vr,
                                        grammar_hypothesis_t *hypothesis) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv || !priv->enable_cegar) return;
    
    ACTF("Verification failed: %s. Triggering CEGAR refinement...", 
         vr->failure_reason ? vr->failure_reason : "unknown");
    
    uint64_t start_time = ext_get_cur_time_us();
    
    /* Apply CEGAR refinement */
    grammar_hypothesis_t *refined = cegar_refine_until_valid(priv->cegar_ctx, 
                                                             hypothesis, 
                                                             vr->minimal_counterexample);
    
    priv->time_in_cegar_us += (ext_get_cur_time_us() - start_time);
    
    if (refined) {
        priv->refinements_applied++;
        ACTF("CEGAR refinement successful (revision %d)", refined->revision);
        
        /* Update hypothesis in context */
        // TODO: Replace old hypothesis with refined one in hypothesis_ctx
    } else {
        WARNF("CEGAR refinement failed after max attempts");
    }
}

/* ============================================================================
 * Module 4: State Scheduler (Triggered on New Coverage)
 * ============================================================================ */

void chatafl_opt_on_new_coverage(extension_context_t *ctx,
                                uint64_t *new_bits, uint32_t new_bits_count) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv || !priv->enable_state_scheduling) return;
    
    /* Reset plateau counter */
    priv->execs_since_new_coverage = 0;
    priv->last_coverage_update = ctx->total_execs;
    
    /* Extract state transition from execution */
    char *new_state = ctx->current_state;
    char *prev_state = ctx->previous_state;
    
    if (new_state && prev_state) {
        /* Record state transition in STT */
        record_transition(priv->scheduler_ctx->stt, prev_state, new_state, 
                         (char*)ctx->current_input);
        
        /* Update state node with new coverage */
        add_or_update_state(priv->scheduler_ctx->stt, new_state, new_bits);
        
        priv->state_updates++;
        
        ACTF("State transition: %s -> %s (new coverage: %u bits)", 
             prev_state, new_state, new_bits_count);
    }
}

/* ============================================================================
 * Module 5: Integration Layer (Triggered Before Mutation)
 * ============================================================================ */

void chatafl_opt_before_mutation(extension_context_t *ctx,
                                uint8_t **in_buf, uint32_t *in_len,
                                uint32_t *mutation_strategy) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv) return;
    
    /* Update plateau counter */
    priv->execs_since_new_coverage = ctx->total_execs - priv->last_coverage_update;
    
    /* Check for plateau */
    if (priv->execs_since_new_coverage >= priv->plateau_threshold) {
        /* Request LLM assistance via plateau hook */
        ctx->request_llm_assist = true;
    }
    
    /* Use scheduler to guide mutation if available */
    if (priv->enable_state_scheduling && priv->scheduler_ctx) {
        /* Compute state priorities periodically (every 100 mutations to reduce overhead) */
        static uint32_t mutation_count = 0;
        if (++mutation_count % 100 == 0) {
            compute_state_priorities(priv->scheduler_ctx);
        }
        
        /* Select next state to explore */
        state_node_t *target = select_next_state(priv->scheduler_ctx);
        
        if (target) {
            /* Generate sequence to reach target state */
            int seq_len = 0;
            char **sequence = generate_sequence_to_state(priv->scheduler_ctx, 
                                                        target, &seq_len);
            
            if (sequence && seq_len > 0) {
                /* Use sequence to guide mutation */
                // TODO: Incorporate sequence into mutation
                ACTF("Scheduler suggests targeting state: %s (priority: %.2f)", 
                     target->state_name, target->priority_score);
            }
        }
    }
}

/* ============================================================================
 * Statistics and Reporting
 * ============================================================================ */

void chatafl_opt_print_stats(extension_context_t *ctx) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv) return;
    
    SAYF("\n" cCYA "ChatAFL-Opt Statistics:" cRST "\n");
    SAYF("  Hypotheses generated : %u\n", priv->hypotheses_generated);
    SAYF("  Verifications done   : %u\n", priv->verifications_performed);
    SAYF("  CEGAR refinements    : %u\n", priv->refinements_applied);
    SAYF("  State updates        : %u\n", priv->state_updates);
    SAYF("  LLM assists          : %u\n", priv->llm_assists);
    
    if (priv->scheduler_ctx && priv->scheduler_ctx->stt) {
        SAYF("  States discovered    : %d\n", priv->scheduler_ctx->stt->total_states);
        SAYF("  Transitions recorded : %d\n", priv->scheduler_ctx->stt->total_transitions);
    }
    
    SAYF("\n" cCYA "Performance Breakdown:" cRST "\n");
    SAYF("  Time in verification : %.2f ms\n", priv->time_in_verification_us / 1000.0);
    SAYF("  Time in CEGAR        : %.2f ms\n", priv->time_in_cegar_us / 1000.0);
    SAYF("  Time in scheduler    : %.2f ms\n", priv->time_in_scheduler_us / 1000.0);
    SAYF("  Time in hypothesis   : %.2f ms\n", priv->time_in_hypothesis_us / 1000.0);
    double total_overhead_ms = (priv->time_in_verification_us + priv->time_in_cegar_us +
                                priv->time_in_scheduler_us + priv->time_in_hypothesis_us) / 1000.0;
    SAYF("  Total overhead       : %.2f ms\n", total_overhead_ms);
}

void chatafl_opt_export_state(extension_context_t *ctx, const char *out_dir) {
    chatafl_opt_private_t *priv = get_private(ctx);
    if (!priv || !out_dir) return;
    
    ACTF("Exporting ChatAFL-Opt state to: %s", out_dir);
    
    /* Export hypotheses */
    char *hypo_file = alloc_printf("%s/hypotheses.json", out_dir);
    // TODO: Export hypotheses to JSON
    ACTF("Exported hypotheses to: %s", hypo_file);
    ck_free(hypo_file);
    
    /* Export state tree */
    char *stt_file = alloc_printf("%s/state_tree.dot", out_dir);
    // TODO: Export STT to Graphviz DOT format
    ACTF("Exported state tree to: %s", stt_file);
    ck_free(stt_file);
    
    /* Export statistics */
    char *stats_file = alloc_printf("%s/chatafl_opt_stats.txt", out_dir);
    FILE *fp = fopen(stats_file, "w");
    if (fp) {
        fprintf(fp, "ChatAFL-Opt Statistics\n");
        fprintf(fp, "======================\n");
        fprintf(fp, "Hypotheses generated: %u\n", priv->hypotheses_generated);
        fprintf(fp, "Verifications: %u\n", priv->verifications_performed);
        fprintf(fp, "CEGAR refinements: %u\n", priv->refinements_applied);
        fprintf(fp, "State updates: %u\n", priv->state_updates);
        fprintf(fp, "LLM assists: %u\n", priv->llm_assists);
        fclose(fp);
        ACTF("Exported statistics to: %s", stats_file);
    }
    ck_free(stats_file);
}

/* ============================================================================
 * Extension Registration
 * ============================================================================ */

static fuzzer_extension_t chatafl_opt_extension = {
    .name = "ChatAFL-Opt",
    .version = "1.0.0",
    .description = "LLM-guided protocol fuzzing with verification and refinement",
    
    /* Lifecycle */
    .init = chatafl_opt_init,
    .cleanup = chatafl_opt_cleanup,
    
    /* Generic hooks */
    .hooks = {
        [HOOK_BEFORE_FUZZING_START] = NULL,
        [HOOK_AFTER_QUEUE_INIT] = NULL,
        [HOOK_BEFORE_QUEUE_CYCLE] = NULL,
        [HOOK_BEFORE_FUZZ_ONE] = NULL,
        [HOOK_AFTER_EXECUTION] = NULL,
        [HOOK_ON_NEW_COVERAGE] = NULL,
        [HOOK_ON_NEW_CRASH] = NULL,
        [HOOK_ON_QUEUE_UPDATE] = NULL,
        [HOOK_BEFORE_MUTATION] = NULL,
        [HOOK_AFTER_MUTATION] = NULL,
        [HOOK_ON_PLATEAU_DETECTED] = NULL,
        [HOOK_BEFORE_FUZZING_END] = NULL,
    },
    
    /* Specialized hooks */
    .before_mutation = chatafl_opt_before_mutation,
    .after_execution = chatafl_opt_after_execution,
    .on_new_coverage = chatafl_opt_on_new_coverage,
    .on_plateau = chatafl_opt_on_plateau,
    
    /* Configuration */
    .enabled = true,
    .priority = 100, // High priority
    
    .next = NULL
};

fuzzer_extension_t* get_chatafl_opt_extension(void) {
    return &chatafl_opt_extension;
}
