/*
 * Cleaned Grammar Hypothesis Header
 * - Remove duplicated content and ensure proper forward declarations
 */

#ifndef __GRAMMAR_HYPOTHESIS_H
#define __GRAMMAR_HYPOTHESIS_H

#include "klist.h"
#include "kvec.h"
#include "khash.h"
#include <json-c/json.h>
#include <time.h>

#define FITNESS_THRESHOLD 0.7

typedef enum {
    CONSTRAINT_LENGTH,
    CONSTRAINT_ENUM,
    CONSTRAINT_REGEX,
    CONSTRAINT_DEPENDENCY,
    CONSTRAINT_NUMERIC
} constraint_type_t;

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
    unsigned int violations;
    unsigned int validations;
    double confidence;
} field_constraint_t;

typedef struct grammar_hypothesis {
    char *message_type;
    char *description;
    json_object *schema;
    char *schema_str;
    field_constraint_t **constraints;
    size_t constraint_count;
    char **production_rules;
    size_t rule_count;
    unsigned long long hypothesis_id;
    time_t created_at;
    time_t last_updated;
    unsigned int parse_success;
    unsigned int parse_failure;
    unsigned int generated_count;
    double fitness;
    char **counterexamples;
    size_t counterexample_count;
} grammar_hypothesis_t;

typedef struct hypothesis_context {
    char *rfc_text;
    char **pcap_samples;
    size_t pcap_count;
    char **server_responses;
    size_t response_count;
    char *protocol_name;
    grammar_hypothesis_t **hypotheses;
    size_t hypothesis_count;
    unsigned int refinement_iterations;
} hypothesis_context_t;

/* forward declarations */
void free_grammar_hypothesis(grammar_hypothesis_t *hyp);

KHASH_MAP_INIT_STR(hypothesis_map, grammar_hypothesis_t*)
/* kmpfree_f receives a kl1_hyp* node pointer; access ->data to get the stored grammar_hypothesis_t* */
#define __hypothesis_t_free(x) free_grammar_hypothesis((x)->data)
KLIST_INIT(hyp, grammar_hypothesis_t *, __hypothesis_t_free)

/* API */
hypothesis_context_t* init_hypothesis_context(const char *protocol_name, const char *rfc_text, char **pcap_samples, size_t pcap_count);
int generate_grammar_hypotheses(hypothesis_context_t *ctx, int max_hypotheses);
int validate_message_against_hypothesis(grammar_hypothesis_t *hyp, const unsigned char *message, size_t len);
void add_counterexample(grammar_hypothesis_t *hyp, const unsigned char *message, size_t len, const char *error_reason);
int refine_hypothesis_with_counterexamples(hypothesis_context_t *ctx, grammar_hypothesis_t *hyp);
double calculate_hypothesis_fitness(grammar_hypothesis_t *hyp);
grammar_hypothesis_t* select_best_hypothesis(hypothesis_context_t *ctx, const char *message_type);
int save_hypothesis_to_file(grammar_hypothesis_t *hyp, const char *filepath);
grammar_hypothesis_t* load_hypothesis_from_file(const char *filepath);
void free_hypothesis_context(hypothesis_context_t *ctx);
grammar_hypothesis_t* parse_llm_hypothesis_response(const char *llm_response);
void update_hypothesis_fitness_dynamic(grammar_hypothesis_t *hyp, int is_success);
void extract_constraints_from_schema(grammar_hypothesis_t *hyp, json_object *schema);
int check_constraint(field_constraint_t *constraint, const char *field_value, size_t value_len);
char* collect_violation_details(grammar_hypothesis_t *hyp, const unsigned char *message, size_t len);
void log_hypothesis_event(grammar_hypothesis_t *hyp, const char *event_type, const char *details);

#endif /* __GRAMMAR_HYPOTHESIS_H */
