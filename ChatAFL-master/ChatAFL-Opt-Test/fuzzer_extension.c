#include "fuzzer_extension.h"
#include "alloc-inl.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Extension Manager Implementation
 * ============================================================================ */

/* Global extension manager instance */
static extension_manager_t *g_ext_manager = NULL;

/* Initialize extension manager */
extension_manager_t* init_extension_manager(void) {
    if (g_ext_manager) {
        WARNF("Extension manager already initialized");
        return g_ext_manager;
    }
    
    g_ext_manager = (extension_manager_t*)ck_alloc(sizeof(extension_manager_t));
    g_ext_manager->extensions = NULL;
    g_ext_manager->extension_count = 0;
    g_ext_manager->initialized = true;
    
    /* Allocate global context */
    g_ext_manager->global_ctx = (extension_context_t*)ck_alloc(sizeof(extension_context_t));
    memset(g_ext_manager->global_ctx, 0, sizeof(extension_context_t));
    
    ACTF("Extension manager initialized");
    return g_ext_manager;
}

/* Register an extension */
int register_extension(extension_manager_t *mgr, fuzzer_extension_t *ext) {
    if (!mgr || !ext) {
        WARNF("Invalid parameters to register_extension");
        return -1;
    }
    
    if (!ext->enabled) {
        ACTF("Extension '%s' is disabled, skipping registration", ext->name);
        return 0;
    }
    
    /* Initialize extension */
    if (ext->init && ext->init(mgr->global_ctx) != 0) {
        WARNF("Extension '%s' initialization failed", ext->name);
        return -1;
    }
    
    /* Insert into linked list (sorted by priority) */
    if (!mgr->extensions || ext->priority > mgr->extensions->priority) {
        /* Insert at head */
        ext->next = mgr->extensions;
        mgr->extensions = ext;
    } else {
        /* Insert in sorted order */
        fuzzer_extension_t *curr = mgr->extensions;
        while (curr->next && curr->next->priority >= ext->priority) {
            curr = curr->next;
        }
        ext->next = curr->next;
        curr->next = ext;
    }
    
    mgr->extension_count++;
    ACTF("Registered extension: %s v%s (priority=%d)", 
         ext->name, ext->version, ext->priority);
    
    return 0;
}

/* Trigger a generic hook point */
void trigger_hook(extension_manager_t *mgr, hook_point_t hook) {
    if (!mgr || !mgr->initialized || hook >= HOOK_COUNT) {
        return;
    }
    
    fuzzer_extension_t *ext = mgr->extensions;
    while (ext) {
        if (ext->enabled && ext->hooks[hook]) {
            ext->hooks[hook](mgr->global_ctx);
        }
        ext = ext->next;
    }
}

/* Trigger before mutation hook */
void trigger_before_mutation(extension_manager_t *mgr, 
                            uint8_t **in_buf, uint32_t *in_len, 
                            uint32_t *mutation_strategy) {
    if (!mgr || !mgr->initialized) {
        return;
    }
    
    fuzzer_extension_t *ext = mgr->extensions;
    while (ext) {
        if (ext->enabled && ext->before_mutation) {
            ext->before_mutation(mgr->global_ctx, in_buf, in_len, mutation_strategy);
        }
        ext = ext->next;
    }
}

/* Trigger after execution hook */
void trigger_after_execution(extension_manager_t *mgr,
                            uint8_t *trace_bits, uint32_t trace_len,
                            uint8_t fault_type,
                            char *server_response, int response_code) {
    if (!mgr || !mgr->initialized) {
        return;
    }
    
    fuzzer_extension_t *ext = mgr->extensions;
    while (ext) {
        if (ext->enabled && ext->after_execution) {
            ext->after_execution(mgr->global_ctx, trace_bits, trace_len, 
                               fault_type, server_response, response_code);
        }
        ext = ext->next;
    }
}

/* Trigger new coverage hook */
void trigger_new_coverage(extension_manager_t *mgr,
                         uint64_t *new_bits, uint32_t new_bits_count) {
    if (!mgr || !mgr->initialized) {
        return;
    }
    
    fuzzer_extension_t *ext = mgr->extensions;
    while (ext) {
        if (ext->enabled && ext->on_new_coverage) {
            ext->on_new_coverage(mgr->global_ctx, new_bits, new_bits_count);
        }
        ext = ext->next;
    }
}

/* Trigger plateau hook */
void trigger_plateau(extension_manager_t *mgr,
                    uint32_t execs_without_progress,
                    uint32_t plateau_threshold) {
    if (!mgr || !mgr->initialized) {
        return;
    }
    
    fuzzer_extension_t *ext = mgr->extensions;
    while (ext) {
        if (ext->enabled && ext->on_plateau) {
            ext->on_plateau(mgr->global_ctx, execs_without_progress, plateau_threshold);
        }
        ext = ext->next;
    }
}

/* Update extension context */
void update_extension_context(extension_manager_t *mgr,
                             struct queue_entry *q,
                             uint8_t *input, uint32_t input_len,
                             uint64_t exec_us, uint8_t fault) {
    if (!mgr || !mgr->global_ctx) {
        return;
    }
    
    extension_context_t *ctx = mgr->global_ctx;
    ctx->current_queue_entry = q;
    ctx->current_input = input;
    ctx->current_input_len = input_len;
    ctx->current_exec_us = exec_us;
    ctx->current_fault = fault;
}

/* Cleanup all extensions */
void cleanup_extensions(extension_manager_t *mgr) {
    if (!mgr) {
        return;
    }
    
    fuzzer_extension_t *ext = mgr->extensions;
    while (ext) {
        if (ext->cleanup) {
            ext->cleanup(mgr->global_ctx);
        }
        fuzzer_extension_t *next = ext->next;
        /* Note: Don't free ext itself - it's statically allocated by extension modules */
        ext = next;
    }
    
    if (mgr->global_ctx) {
        ck_free(mgr->global_ctx);
    }
    
    ck_free(mgr);
    g_ext_manager = NULL;
    
    ACTF("All extensions cleaned up");
}

/* Helper: Get virgin_bits (to be set by afl-fuzz.c) */
uint64_t* get_virgin_bits(extension_manager_t *mgr) {
    return mgr ? mgr->global_ctx->virgin_bits : NULL;
}

/* Helper: Get total execs */
uint64_t get_total_execs(extension_manager_t *mgr) {
    return mgr ? mgr->global_ctx->total_execs : 0;
}

/* Helper: Check if extension should be invoked */
bool should_invoke_extension(fuzzer_extension_t *ext) {
    return ext && ext->enabled;
}
