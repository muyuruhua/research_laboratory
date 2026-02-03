#ifndef __HYPOTHESIS_H
#define __HYPOTHESIS_H

#include "klist.h"
#include "kvec.h"
#include "khash.h"
#include "chat-llm.h"
#include <json-c/json.h>
#include <time.h>

/* Grammar Hypothesis Module
 * Generates protocol grammar hypotheses from RFC, packet captures, and server responses
 */

// Grammar structure for a protocol message
typedef struct {
    char *message_type;           // e.g., "USER", "PASS", "RETR"
    char *grammar_spec;           // ABNF/CFG/JSON schema
    json_object *field_constraints; // Field-level constraints
    int confidence_score;         // 0-100, based on LLM temperature and validation
    time_t created_at;
    int revision;                 // Incremented on CEGAR refinement
} grammar_hypothesis_t;

// Field constraint types
typedef struct {
    char *field_name;
    char *field_type;             // "string", "int", "enum", etc.
    int min_length;
    int max_length;
    char **enum_values;           // For enumerated fields
    int enum_count;
    char *dependency;             // Field this depends on
    char *pattern;                // Regex pattern
} field_constraint_t;

// Forward declaration for free function
void free_grammar_hypothesis(grammar_hypothesis_t *h);

// KLIST and KHASH declarations - must come before using them
// Note: We store pointers to grammar_hypothesis_t
// Use a no-op free function since we'll manually free in free_hypothesis_context
#define __hypothesis_node_free(x) 
KLIST_INIT(hypo, grammar_hypothesis_t *, __hypothesis_node_free)

// Hypothesis context for a protocol
typedef struct {
    char *protocol_name;
    kl_hypo_t *grammar_list;  // List of grammar_hypothesis_t
    khash_t(strMap) *message_type_index; // Map message_type -> index in grammar_list
    char *rfc_snippet;            // Cached RFC context
    char *pcap_examples;          // Cached pcap examples
    int hypothesis_count;
} hypothesis_context_t;

// Initialize hypothesis context
hypothesis_context_t *init_hypothesis_context(const char *protocol_name);

// Generate initial grammar hypotheses from RFC and examples
int generate_initial_hypotheses(hypothesis_context_t *ctx, 
                                const char *rfc_snippet,
                                const char *pcap_examples,
                                const char *server_responses);

// Generate hypothesis for a specific message type
grammar_hypothesis_t *generate_message_hypothesis(const char *protocol_name,
                                                  const char *message_type,
                                                  const char *context,
                                                  int revision);

// Refine hypothesis based on counterexample (CEGAR)
grammar_hypothesis_t *refine_hypothesis(grammar_hypothesis_t *old_hypothesis,
                                        const char *counterexample,
                                        const char *failure_reason,
                                        const char *minimal_diff);

// Extract field constraints from grammar
field_constraint_t **extract_field_constraints(const char *grammar_spec, int *count);

// Free functions (free_grammar_hypothesis declared earlier)
void free_hypothesis_context(hypothesis_context_t *ctx);
void free_field_constraint(field_constraint_t *fc);

// Helper: construct LLM prompt for grammar generation
char *construct_grammar_hypothesis_prompt(const char *protocol_name,
                                          const char *message_type,
                                          const char *rfc_context,
                                          const char *examples);

// Helper: construct LLM prompt for refinement (CEGAR)
char *construct_refinement_prompt(grammar_hypothesis_t *hypothesis,
                                  const char *counterexample,
                                  const char *failure_reason,
                                  const char *field_to_fix);

// Parse LLM response into grammar_hypothesis_t
grammar_hypothesis_t *parse_hypothesis_from_llm_response(const char *llm_response,
                                                         const char *message_type,
                                                         int revision);

#endif /* __HYPOTHESIS_H */
