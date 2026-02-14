/*
 * ChatAFL-Opt: Grammar Hypothesis Module
 * ======================================
 * This module implements LLM-driven grammar hypothesis generation with
 * runtime validation and counterexample-driven refinement.
 * 
 * Key Features:
 * 1. Structured Grammar Representation (JSON Schema + ABNF-like constraints)
 * 2. Hypothesis Generation from RFC/PCAP/Response Codes
 * 3. Validation Metrics (parse success rate, field coverage, constraint violations)
 * 4. Counterexample-Driven Refinement
 * 
 * Design Philosophy: Hypothesis → Validation → Refinement (Closed Loop)
 */

#ifndef __GRAMMAR_HYPOTHESIS_H
#define __GRAMMAR_HYPOTHESIS_H

#include "klist.h"
#include "kvec.h"
#include "khash.h"
#include <json-c/json.h>

#define FITNESS_THRESHOLD 0.7

/* ============================================
 * Grammar Hypothesis Data Structures
 * ============================================ */

// Field constraint types
typedef enum {
    CONSTRAINT_LENGTH,      // Length range: min, max
    CONSTRAINT_ENUM,        // Enumerated values
    CONSTRAINT_REGEX,       // Regex pattern
    CONSTRAINT_DEPENDENCY,  // Depends on other fields
    CONSTRAINT_NUMERIC      // Numeric range
} constraint_type_t;

// Single field constraint
typedef struct field_constraint {
    constraint_type_t type;
    char *field_name;
    
    union {
        struct { size_t min; size_t max; } length;
        struct { char **values; size_t count; } enumeration;
        struct { char *pattern; } regex;
        struct { char *target_field; char *condition; } dependency;
        struct { long long min; long long max; } numeric;
    } data;
    
    // Validation metrics
    unsigned int violations;      // Times this constraint was violated
    unsigned int validations;     // Times this constraint was validated
    double confidence;            // violations / validations (lower is better)
    
} field_constraint_t;

// Message grammar hypothesis
typedef struct grammar_hypothesis {
    char *message_type;           // e.g., "FTP-USER", "HTTP-GET"
    char *description;            // LLM-generated description
    
    // Grammar representation (JSON Schema style)
    json_object *schema;          // Full JSON Schema (may be NULL, use schema_str instead)
    char *schema_str;             // Schema as string (safer than holding JSON object)
    
    // Field constraints
    field_constraint_t **constraints;
    size_t constraint_count;
    
    // ABNF-like production rules
    char **production_rules;      // e.g., "USER <SP> <username> <CRLF>"
    size_t rule_count;
    
    // Hypothesis metadata
    unsigned long long hypothesis_id;
    time_t created_at;
    time_t last_updated;
    
    // Validation statistics
    unsigned int parse_success;   // Successful parses
    unsigned int parse_failure;   // Failed parses
    unsigned int generated_count; // Messages generated from this hypothesis
    double fitness;               // Overall fitness score (0.0 - 1.0)
    
    // Counterexamples that violated this hypothesis
    char **counterexamples;
    size_t counterexample_count;
    
} grammar_hypothesis_t;

// Hypothesis generation context
typedef struct hypothesis_context {
    // Input sources
    char *rfc_text;               // RFC specification text
    char **pcap_samples;          // PCAP trace examples
    size_t pcap_count;
    
    char **server_responses;      // Server response codes/errors
    size_t response_count;
    
    char *protocol_name;          // e.g., "FTP", "HTTP", "SMTP"
    
    // Generated hypotheses
    grammar_hypothesis_t **hypotheses;
    size_t hypothesis_count;
    
    // Refinement history
    unsigned int refinement_iterations;
    
} hypothesis_context_t;


/* ============================================
 * Hash Tables for Hypothesis Management
 * ============================================ */

KHASH_MAP_INIT_STR(hypothesis_map, grammar_hypothesis_t*)

// Free functions for klist
#define __hypothesis_t_free(x) free_grammar_hypothesis(x)
KLIST_INIT(hyp, grammar_hypothesis_t *, __hypothesis_t_free)


/* ============================================
 * Core API Functions
 * ============================================ */

/**
 * Initialize hypothesis context from various input sources
 */
hypothesis_context_t* init_hypothesis_context(
    const char *protocol_name,
    const char *rfc_text,
    char **pcap_samples,
    size_t pcap_count
);

/**
 * Generate grammar hypotheses using LLM
 * 
 * @param ctx Hypothesis context
 * @param max_hypotheses Maximum number of hypotheses to generate
 * @return Number of hypotheses generated
 * 
 * This function constructs a detailed prompt including:
 * - RFC specification snippets
 * - PCAP samples
 * - Server response patterns
 * And asks LLM to generate structured grammar hypotheses in JSON Schema format
 */
int generate_grammar_hypotheses(hypothesis_context_t *ctx, int max_hypotheses);

/**
 * Validate a message against a grammar hypothesis
 * 
 * @param hyp Grammar hypothesis
 * @param message Message bytes
 * @param len Message length
 * @return 1 if valid, 0 if invalid (updates validation metrics)
 */
int validate_message_against_hypothesis(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len
);

/**
 * Add counterexample to hypothesis for refinement
 * 
 * @param hyp Grammar hypothesis
 * @param message Failed message
 * @param len Message length
 * @param error_reason Why this message violated the hypothesis
 */
void add_counterexample(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len,
    const char *error_reason
);

/**
 * Refine hypothesis based on accumulated counterexamples
 * 
 * @param ctx Hypothesis context
 * @param hyp Grammar hypothesis to refine
 * @return 1 if refined successfully, 0 otherwise
 * 
 * This function:
 * 1. Collects all counterexamples
 * 2. Constructs refinement prompt for LLM
 * 3. Updates hypothesis with refined grammar
 * 4. Clears counterexamples
 */
int refine_hypothesis_with_counterexamples(
    hypothesis_context_t *ctx,
    grammar_hypothesis_t *hyp
);

/**
 * Calculate fitness score for a hypothesis
 * 
 * Fitness = (parse_success / (parse_success + parse_failure)) * 
 *           (1 - avg_constraint_violation_rate)
 */
double calculate_hypothesis_fitness(grammar_hypothesis_t *hyp);

/**
 * Select best hypothesis for a message type
 */
grammar_hypothesis_t* select_best_hypothesis(
    hypothesis_context_t *ctx,
    const char *message_type
);

/**
 * Serialize hypothesis to JSON file for reproducibility
 */
int save_hypothesis_to_file(grammar_hypothesis_t *hyp, const char *filepath);

/**
 * Load hypothesis from JSON file
 */
grammar_hypothesis_t* load_hypothesis_from_file(const char *filepath);

/**
 * Free hypothesis context
 */
void free_hypothesis_context(hypothesis_context_t *ctx);

/**
 * Free grammar hypothesis
 */
void free_grammar_hypothesis(grammar_hypothesis_t *hyp);


/* ============================================
 * LLM Prompt Construction
 * ============================================ */

/**
 * Construct prompt for initial hypothesis generation
 * 
 * Prompt structure:
 * - Protocol name and description
 * - RFC snippets (focused on syntax)
 * - PCAP samples (3-5 examples)
 * - Request format: JSON Schema with constraints
 */
char* construct_hypothesis_generation_prompt(hypothesis_context_t *ctx);

/**
 * Construct prompt for hypothesis refinement
 * 
 * Prompt structure:
 * - Current hypothesis (JSON Schema)
 * - Counterexamples with error reasons
 * - Request: "Revise the grammar to accommodate these examples"
 */
char* construct_hypothesis_refinement_prompt(
    grammar_hypothesis_t *hyp,
    const char *protocol_name
);


/* ============================================
 * Utility Functions
 * ============================================ */

/**
 * Parse JSON Schema response from LLM into grammar_hypothesis_t
 */
grammar_hypothesis_t* parse_llm_hypothesis_response(const char *llm_response);

/**
 * Extract field constraints from JSON Schema
 */
void extract_constraints_from_schema(
    grammar_hypothesis_t *hyp,
    json_object *schema
);

/**
 * Check if a field value satisfies a constraint
 */
int check_constraint(
    field_constraint_t *constraint,
    const char *field_value,
    size_t value_len
);

/**
 * Log hypothesis validation event for debugging/analysis
 */
void log_hypothesis_event(
    grammar_hypothesis_t *hyp,
    const char *event_type,
    const char *details
);

#endif /* __GRAMMAR_HYPOTHESIS_H */
