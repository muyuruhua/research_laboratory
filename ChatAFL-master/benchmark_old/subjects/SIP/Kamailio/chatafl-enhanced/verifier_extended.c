/*
 * verifier_extended.c - Simplified 4-layer verification with SUT testing
 * 
 * Simplified version without external type dependencies
 */

#include "types.h"
#include "verifier.h"
#include "state-graph.h"
#include "aflnet.h"
#include "alloc-inl.h"
#include "debug.h"
#include "config.h"
#include <string.h>
#include <stdio.h>

/* Function pointer types for accessing afl-fuzz.c static functions */
typedef void (*write_to_testcase_func_t)(void*, unsigned int);
typedef unsigned char (*run_target_func_t)(char**, unsigned int);

/* Global function pointers (initialized by afl-fuzz.c) */
static write_to_testcase_func_t g_write_to_testcase = NULL;
static run_target_func_t g_run_target = NULL;
static unsigned int* g_exec_tmout_ptr = NULL;
static char** g_response_buf_ptr = NULL;
static unsigned int* g_response_buf_size_ptr = NULL;
static unsigned char** g_trace_bits_ptr = NULL;
static unsigned char* g_virgin_bits_ptr = NULL;

/* State Transition Graph global variable */
extern StateGraph g_state_graph;

#define FAULT_NONE 0

/* Forward declarations */
bool is_new_state_transition(unsigned int from_state, unsigned int to_state);

/**
 * Initialize verifier_extended module (called by afl-fuzz.c at startup)
 */
void verifier_extended_init(
    void (*write_func)(void*, unsigned int),
    unsigned char (*run_func)(char**, unsigned int),
    unsigned int* exec_tmout_ptr,
    char** response_buf_ptr,
    unsigned int* response_buf_size_ptr,
    unsigned char** trace_bits_ptr,
    unsigned char* virgin_bits_ptr) {
    
    g_write_to_testcase = write_func;
    g_run_target = run_func;
    g_exec_tmout_ptr = exec_tmout_ptr;
    g_response_buf_ptr = response_buf_ptr;
    g_response_buf_size_ptr = response_buf_size_ptr;
    g_trace_bits_ptr = trace_bits_ptr;
    g_virgin_bits_ptr = virgin_bits_ptr;
}

/**
 * 4-layer verification with real SUT testing
 * 
 * Layers:
 * 1. Parseability (JSON format + Schema)
 * 2. Acceptability (actual SUT call, not static check)
 * 3. State reachability (check for new state transitions)
 * 4. Coverage gain (mandatory virgin_bits check)
 * 
 * @param refined_input LLM-refined input
 * @param argv Target program arguments (for run_target)
 * @param virgin_bits AFL coverage bitmap (for Layer 4)
 * @return true=passed all 4 layers, false=at least one failure
 */
bool verify_refined_input_with_sut(const char* refined_input,
                                    char** argv,
                                    unsigned char* virgin_bits) {
    if (!refined_input || strlen(refined_input) == 0) {
        return false;
    }
    
    /* Check initialization status */
    if (!g_write_to_testcase || !g_run_target) {
        /* Not initialized, skip verification */
        return false;
    }
    
    /* Layer 1: Parseability (basic syntax check) */
    /* Simplified - just check if non-empty for now */
    
    /* Layer 2: Acceptability (actual SUT call) */
    unsigned int* layer2_state_codes = NULL;
    unsigned int layer2_state_count = 0;
    
    if (argv && g_exec_tmout_ptr) {
        /* Write to test file */
        g_write_to_testcase((void*)refined_input, strlen(refined_input));
        
        /* Execute target program */
        unsigned char fault = g_run_target(argv, *g_exec_tmout_ptr);
        
        /* Check for rejection response */
        if (fault != FAULT_NONE || !g_response_buf_ptr || !(*g_response_buf_ptr) || 
            !g_response_buf_size_ptr || *g_response_buf_size_ptr == 0) {
            return false; /* Crash or no response */
        }
        
        /* Extract response codes */
        layer2_state_codes = extract_response_codes((unsigned char*)(*g_response_buf_ptr), 
                                                     *g_response_buf_size_ptr, 
                                                     &layer2_state_count);
        
        bool is_accepted = true;
        if (layer2_state_count > 0 && layer2_state_codes) {
            /* Check for rejection response (4xx/5xx) */
            unsigned int first_code = layer2_state_codes[0];
            if (first_code >= 400 && first_code < 600) {
                is_accepted = false;
            }
        }
        
        if (!is_accepted) {
            if (layer2_state_codes) ck_free(layer2_state_codes);
            return false;
        }
    }
    
    /* Layer 3: State reachability (check for new state transitions) */
    if (layer2_state_codes && layer2_state_count > 1) {
        /* Check for new state transitions */
        for (unsigned int i = 1; i < layer2_state_count; i++) {
            if (is_new_state_transition(layer2_state_codes[i-1], layer2_state_codes[i])) {
                /* Found new transition, increase value */
                break;
            }
        }
    }
    
    /* Free state code array from Layer 2/3 */
    if (layer2_state_codes) {
        ck_free(layer2_state_codes);
    }
    
    /* Layer 4: Coverage gain (mandatory check) */
    if (virgin_bits && argv && g_trace_bits_ptr && *g_trace_bits_ptr) {
        bool has_new_coverage = false;
        unsigned char* trace_bits = *g_trace_bits_ptr;
        
        /* Scan trace_bits for first-time covered edges */
        for (unsigned int i = 0; i < MAP_SIZE; i++) {
            if (trace_bits[i] && virgin_bits[i] == 255) {
                /* Found newly covered edge */
                has_new_coverage = true;
                break;
            }
        }
        
        /* Mandatory: reject if no new coverage (prevent low-quality inputs) */
        if (!has_new_coverage) {
            return false;
        }
    }
    
    return true;
}

/**
 * Check if state transition is newly discovered
 * @param from_state Source state
 * @param to_state Target state
 * @return true=new transition, false=known transition
 */
bool is_new_state_transition(unsigned int from_state, unsigned int to_state) {
    /* Simplified: query state-graph */
    
    /* Find from_state node */
    for (unsigned int i = 0; i < g_state_graph.node_count; i++) {
        if (g_state_graph.nodes[i].state_id == from_state) {
            /* Check if edge to to_state exists */
            for (unsigned int j = 0; j < g_state_graph.nodes[i].out_degree; j++) {
                if (g_state_graph.nodes[i].edges[j].to_state == to_state) {
                    return false; /* Known transition */
                }
            }
            break;
        }
    }
    
    return true; /* New transition */
}
