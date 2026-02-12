/*
 * ChatAFL-Opt: Grammar Hypothesis Implementation
 * ==============================================
 * Implementation of hypothesis-driven grammar learning with validation loop
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "grammar-hypothesis.h"
#include "chat-llm.h"
#include "alloc-inl.h"

#define MAX_HYPOTHESIS_PROMPT 4096
#define MAX_REFINEMENT_COUNTEREXAMPLES 10
#define FITNESS_THRESHOLD 0.7

/* ============================================
 * Initialization Functions
 * ============================================ */

hypothesis_context_t* init_hypothesis_context(
    const char *protocol_name,
    const char *rfc_text,
    char **pcap_samples,
    size_t pcap_count
) {
    hypothesis_context_t *ctx = ck_alloc(sizeof(hypothesis_context_t));
    
    ctx->protocol_name = ck_strdup(protocol_name);
    ctx->rfc_text = rfc_text ? ck_strdup(rfc_text) : NULL;
    
    // Copy PCAP samples
    ctx->pcap_count = pcap_count;
    if (pcap_count > 0) {
        ctx->pcap_samples = ck_alloc(pcap_count * sizeof(char*));
        for (size_t i = 0; i < pcap_count; i++) {
            ctx->pcap_samples[i] = ck_strdup(pcap_samples[i]);
        }
    } else {
        ctx->pcap_samples = NULL;
    }
    
    ctx->server_responses = NULL;
    ctx->response_count = 0;
    
    ctx->hypotheses = NULL;
    ctx->hypothesis_count = 0;
    ctx->refinement_iterations = 0;
    
    return ctx;
}

/* ============================================
 * LLM Prompt Construction
 * ============================================ */

char* construct_hypothesis_generation_prompt(hypothesis_context_t *ctx) {
    char *prompt = ck_alloc(MAX_HYPOTHESIS_PROMPT);
    int offset = 0;
    
    offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "[{\"role\": \"system\", \"content\": \"You are a protocol grammar expert. "
        "Generate structured message grammars in JSON Schema format with field constraints.\"},"
        "{\"role\": \"user\", \"content\": \"");
    
    // Protocol context
    offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Protocol: %s\\n\\n", ctx->protocol_name);
    
    // Add RFC snippet if available (truncated to fit)
    if (ctx->rfc_text) {
        offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "RFC Specification (excerpt):\\n%.*s\\n\\n",
            1000, ctx->rfc_text);  // Limit to 1000 chars
    }
    
    // Add PCAP samples
    if (ctx->pcap_count > 0) {
        offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "Example Messages:\\n");
        
        size_t sample_limit = ctx->pcap_count < 5 ? ctx->pcap_count : 5;
        for (size_t i = 0; i < sample_limit; i++) {
            offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
                "%zu. %s\\n", i + 1, ctx->pcap_samples[i]);
        }
        offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, "\\n");
    }
    
    // Request format
    offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Generate grammar hypotheses for this protocol. For each message type, provide:\\n"
        "1. message_type: Identifier (e.g., 'USER', 'GET')\\n"
        "2. description: What this message does\\n"
        "3. schema: JSON Schema with field definitions\\n"
        "4. constraints: Array of field constraints\\n"
        "5. production_rules: ABNF-like syntax rules\\n\\n"
        "Format your response as a JSON array of hypothesis objects:\\n"
        "[{\\\"message_type\\\": \\\"...\\\", \\\"description\\\": \\\"...\\\", "
        "\\\"schema\\\": {...}, \\\"constraints\\\": [...], "
        "\\\"production_rules\\\": [\\\"...\\\"]}]\\n\\n"
        "Include constraints like: length ranges, allowed values (enums), "
        "regex patterns, field dependencies, numeric ranges.\"}]");
    
    return prompt;
}

char* construct_hypothesis_refinement_prompt(
    grammar_hypothesis_t *hyp,
    const char *protocol_name
) {
    char *prompt = ck_alloc(MAX_HYPOTHESIS_PROMPT);
    int offset = 0;
    
    offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "[{\"role\": \"system\", \"content\": \"You are refining protocol grammar hypotheses "
        "based on counterexamples.\"},"
        "{\"role\": \"user\", \"content\": \"");
    
    offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Protocol: %s\\n"
        "Message Type: %s\\n\\n"
        "Current Hypothesis:\\n"
        "Description: %s\\n"
        "Schema: %s\\n\\n",
        protocol_name,
        hyp->message_type,
        hyp->description,
        json_object_to_json_string_ext(hyp->schema, JSON_C_TO_STRING_PRETTY)
    );
    
    // Add counterexamples
    offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Counterexamples (messages that violated the hypothesis):\\n");
    
    size_t ce_limit = hyp->counterexample_count < MAX_REFINEMENT_COUNTEREXAMPLES ? 
                      hyp->counterexample_count : MAX_REFINEMENT_COUNTEREXAMPLES;
    
    for (size_t i = 0; i < ce_limit; i++) {
        offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "%zu. %s\\n", i + 1, hyp->counterexamples[i]);
    }
    
    offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "\\nPlease revise the grammar hypothesis to accommodate these counterexamples. "
        "Return the updated hypothesis in the same JSON format as before.\"}]");
    
    return prompt;
}

/* ============================================
 * Hypothesis Generation
 * ============================================ */

int generate_grammar_hypotheses(hypothesis_context_t *ctx, int max_hypotheses) {
    char *prompt = construct_hypothesis_generation_prompt(ctx);
    
    // Call LLM with structured prompt
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.3);  // Low temperature for consistency
    ck_free(prompt);
    
    if (!response) {
        fprintf(stderr, "[!] Failed to generate hypotheses from LLM\n");
        return 0;
    }
    
    // Parse LLM response into hypotheses
    json_object *response_json = json_tokener_parse(response);
    if (!response_json || !json_object_is_type(response_json, json_type_array)) {
        fprintf(stderr, "[!] Invalid JSON response from LLM\n");
        free(response);
        return 0;
    }
    
    size_t hyp_count = json_object_array_length(response_json);
    if (hyp_count > (size_t)max_hypotheses) {
        hyp_count = max_hypotheses;
    }
    
    ctx->hypotheses = ck_alloc(hyp_count * sizeof(grammar_hypothesis_t*));
    ctx->hypothesis_count = 0;
    
    for (size_t i = 0; i < hyp_count; i++) {
        json_object *hyp_json = json_object_array_get_idx(response_json, i);
        grammar_hypothesis_t *hyp = parse_llm_hypothesis_response(
            json_object_to_json_string(hyp_json)
        );
        
        if (hyp) {
            hyp->hypothesis_id = (unsigned long long)time(NULL) * 1000 + i;
            hyp->created_at = time(NULL);
            hyp->last_updated = time(NULL);
            
            ctx->hypotheses[ctx->hypothesis_count++] = hyp;
        }
    }
    
    json_object_put(response_json);
    free(response);
    
    printf("[+] Generated %zu grammar hypotheses\n", ctx->hypothesis_count);
    return ctx->hypothesis_count;
}

grammar_hypothesis_t* parse_llm_hypothesis_response(const char *llm_response) {
    json_object *jobj = json_tokener_parse(llm_response);
    if (!jobj) return NULL;
    
    grammar_hypothesis_t *hyp = ck_alloc(sizeof(grammar_hypothesis_t));
    memset(hyp, 0, sizeof(grammar_hypothesis_t));
    
    // Extract message_type
    json_object *msg_type_obj;
    if (json_object_object_get_ex(jobj, "message_type", &msg_type_obj)) {
        hyp->message_type = ck_strdup(json_object_get_string(msg_type_obj));
    }
    
    // Extract description
    json_object *desc_obj;
    if (json_object_object_get_ex(jobj, "description", &desc_obj)) {
        hyp->description = ck_strdup(json_object_get_string(desc_obj));
    }
    
    // Extract schema
    json_object *schema_obj;
    if (json_object_object_get_ex(jobj, "schema", &schema_obj)) {
        hyp->schema = json_object_get(schema_obj);  // Increment ref count
        extract_constraints_from_schema(hyp, schema_obj);
    }
    
    // Extract production_rules
    json_object *rules_obj;
    if (json_object_object_get_ex(jobj, "production_rules", &rules_obj)) {
        if (json_object_is_type(rules_obj, json_type_array)) {
            hyp->rule_count = json_object_array_length(rules_obj);
            hyp->production_rules = ck_alloc(hyp->rule_count * sizeof(char*));
            
            for (size_t i = 0; i < hyp->rule_count; i++) {
                json_object *rule = json_object_array_get_idx(rules_obj, i);
                hyp->production_rules[i] = ck_strdup(json_object_get_string(rule));
            }
        }
    }
    
    // Initialize validation stats
    hyp->parse_success = 0;
    hyp->parse_failure = 0;
    hyp->generated_count = 0;
    hyp->fitness = 0.5;  // Neutral initial fitness
    
    hyp->counterexamples = NULL;
    hyp->counterexample_count = 0;
    
    json_object_put(jobj);
    return hyp;
}

void extract_constraints_from_schema(grammar_hypothesis_t *hyp, json_object *schema) {
    // Extract constraints from JSON Schema
    json_object *properties;
    if (!json_object_object_get_ex(schema, "properties", &properties)) {
        return;
    }
    
    // Count properties to allocate constraints
    size_t prop_count = json_object_object_length(properties);
    hyp->constraints = ck_alloc(prop_count * 10 * sizeof(field_constraint_t*));  // Over-allocate
    hyp->constraint_count = 0;
    
    json_object_object_foreach(properties, field_name, field_schema) {
        // Length constraints
        json_object *min_len, *max_len;
        if (json_object_object_get_ex(field_schema, "minLength", &min_len) ||
            json_object_object_get_ex(field_schema, "maxLength", &max_len)) {
            
            field_constraint_t *constraint = ck_alloc(sizeof(field_constraint_t));
            constraint->type = CONSTRAINT_LENGTH;
            constraint->field_name = ck_strdup(field_name);
            constraint->data.length.min = min_len ? json_object_get_int64(min_len) : 0;
            constraint->data.length.max = max_len ? json_object_get_int64(max_len) : SIZE_MAX;
            constraint->violations = 0;
            constraint->validations = 0;
            constraint->confidence = 1.0;
            
            hyp->constraints[hyp->constraint_count++] = constraint;
        }
        
        // Enum constraints
        json_object *enum_obj;
        if (json_object_object_get_ex(field_schema, "enum", &enum_obj)) {
            if (json_object_is_type(enum_obj, json_type_array)) {
                field_constraint_t *constraint = ck_alloc(sizeof(field_constraint_t));
                constraint->type = CONSTRAINT_ENUM;
                constraint->field_name = ck_strdup(field_name);
                
                size_t enum_count = json_object_array_length(enum_obj);
                constraint->data.enumeration.count = enum_count;
                constraint->data.enumeration.values = ck_alloc(enum_count * sizeof(char*));
                
                for (size_t i = 0; i < enum_count; i++) {
                    json_object *val = json_object_array_get_idx(enum_obj, i);
                    constraint->data.enumeration.values[i] = ck_strdup(json_object_get_string(val));
                }
                
                constraint->violations = 0;
                constraint->validations = 0;
                constraint->confidence = 1.0;
                
                hyp->constraints[hyp->constraint_count++] = constraint;
            }
        }
        
        // Pattern (regex) constraints
        json_object *pattern_obj;
        if (json_object_object_get_ex(field_schema, "pattern", &pattern_obj)) {
            field_constraint_t *constraint = ck_alloc(sizeof(field_constraint_t));
            constraint->type = CONSTRAINT_REGEX;
            constraint->field_name = ck_strdup(field_name);
            constraint->data.regex.pattern = ck_strdup(json_object_get_string(pattern_obj));
            constraint->violations = 0;
            constraint->validations = 0;
            constraint->confidence = 1.0;
            
            hyp->constraints[hyp->constraint_count++] = constraint;
        }
        
        // Numeric range constraints
        json_object *minimum, *maximum;
        if (json_object_object_get_ex(field_schema, "minimum", &minimum) ||
            json_object_object_get_ex(field_schema, "maximum", &maximum)) {
            
            field_constraint_t *constraint = ck_alloc(sizeof(field_constraint_t));
            constraint->type = CONSTRAINT_NUMERIC;
            constraint->field_name = ck_strdup(field_name);
            constraint->data.numeric.min = minimum ? json_object_get_int64(minimum) : LLONG_MIN;
            constraint->data.numeric.max = maximum ? json_object_get_int64(maximum) : LLONG_MAX;
            constraint->violations = 0;
            constraint->validations = 0;
            constraint->confidence = 1.0;
            
            hyp->constraints[hyp->constraint_count++] = constraint;
        }
    }
}

/* ============================================
 * Validation Functions
 * ============================================ */

int validate_message_against_hypothesis(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len
) {
    // Simple validation: check if message can be parsed according to schema
    // In a full implementation, this would parse the message and validate each field
    
    int valid = 1;
    
    // For now, we do basic validation on constraints
    for (size_t i = 0; i < hyp->constraint_count; i++) {
        field_constraint_t *c = hyp->constraints[i];
        c->validations++;
        
        // Simplified validation logic
        // In practice, you'd parse the message and extract field values
        if (!check_constraint(c, (const char*)message, len)) {
            c->violations++;
            valid = 0;
        }
        
        // Update constraint confidence
        if (c->validations > 0) {
            c->confidence = 1.0 - ((double)c->violations / (double)c->validations);
        }
    }
    
    if (valid) {
        hyp->parse_success++;
    } else {
        hyp->parse_failure++;
    }
    
    // Update fitness
    hyp->fitness = calculate_hypothesis_fitness(hyp);
    
    return valid;
}

int check_constraint(
    field_constraint_t *constraint,
    const char *field_value,
    size_t value_len
) {
    switch (constraint->type) {
        case CONSTRAINT_LENGTH:
            return value_len >= constraint->data.length.min && 
                   value_len <= constraint->data.length.max;
        
        case CONSTRAINT_ENUM:
            for (size_t i = 0; i < constraint->data.enumeration.count; i++) {
                if (strncmp(field_value, constraint->data.enumeration.values[i], value_len) == 0) {
                    return 1;
                }
            }
            return 0;
        
        case CONSTRAINT_REGEX:
            // Would use PCRE2 for actual regex matching
            return 1;  // Placeholder
        
        case CONSTRAINT_NUMERIC:
            // Would parse and check numeric value
            return 1;  // Placeholder
        
        case CONSTRAINT_DEPENDENCY:
            return 1;  // Placeholder
        
        default:
            return 1;
    }
}

double calculate_hypothesis_fitness(grammar_hypothesis_t *hyp) {
    if (hyp->parse_success + hyp->parse_failure == 0) {
        return 0.5;  // Neutral fitness with no data
    }
    
    // Parse success rate
    double parse_rate = (double)hyp->parse_success / 
                       (double)(hyp->parse_success + hyp->parse_failure);
    
    // Average constraint confidence
    double avg_confidence = 0.0;
    if (hyp->constraint_count > 0) {
        for (size_t i = 0; i < hyp->constraint_count; i++) {
            avg_confidence += hyp->constraints[i]->confidence;
        }
        avg_confidence /= hyp->constraint_count;
    } else {
        avg_confidence = 1.0;
    }
    
    // Combined fitness: 70% parse rate, 30% constraint confidence
    return 0.7 * parse_rate + 0.3 * avg_confidence;
}

/* ============================================
 * Counterexample & Refinement
 * ============================================ */

void add_counterexample(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len,
    const char *error_reason
) {
    // Add counterexample
    hyp->counterexamples = ck_realloc(hyp->counterexamples, 
                                      (hyp->counterexample_count + 1) * sizeof(char*));
    
    char *ce = ck_alloc(len + 256);  // Message + error reason
    snprintf(ce, len + 256, "%.*s [Reason: %s]", (int)len, message, error_reason);
    
    hyp->counterexamples[hyp->counterexample_count++] = ce;
    
    log_hypothesis_event(hyp, "COUNTEREXAMPLE", error_reason);
}

int refine_hypothesis_with_counterexamples(
    hypothesis_context_t *ctx,
    grammar_hypothesis_t *hyp
) {
    if (hyp->counterexample_count == 0) {
        return 0;  // Nothing to refine
    }
    
    char *prompt = construct_hypothesis_refinement_prompt(hyp, ctx->protocol_name);
    
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.3);
    ck_free(prompt);
    
    if (!response) {
        fprintf(stderr, "[!] Failed to refine hypothesis from LLM\n");
        return 0;
    }
    
    // Parse refined hypothesis
    grammar_hypothesis_t *refined_hyp = parse_llm_hypothesis_response(response);
    free(response);
    
    if (!refined_hyp) {
        fprintf(stderr, "[!] Failed to parse refined hypothesis\n");
        return 0;
    }
    
    // Update existing hypothesis with refined data
    if (hyp->schema) json_object_put(hyp->schema);
    hyp->schema = refined_hyp->schema;
    refined_hyp->schema = NULL;  // Transfer ownership
    
    // Update constraints
    for (size_t i = 0; i < hyp->constraint_count; i++) {
        ck_free(hyp->constraints[i]->field_name);
        ck_free(hyp->constraints[i]);
    }
    ck_free(hyp->constraints);
    
    hyp->constraints = refined_hyp->constraints;
    hyp->constraint_count = refined_hyp->constraint_count;
    refined_hyp->constraints = NULL;  // Transfer ownership
    
    // Clear counterexamples after refinement
    for (size_t i = 0; i < hyp->counterexample_count; i++) {
        ck_free(hyp->counterexamples[i]);
    }
    ck_free(hyp->counterexamples);
    hyp->counterexamples = NULL;
    hyp->counterexample_count = 0;
    
    hyp->last_updated = time(NULL);
    ctx->refinement_iterations++;
    
    free_grammar_hypothesis(refined_hyp);
    
    log_hypothesis_event(hyp, "REFINED", "Hypothesis updated from counterexamples");
    printf("[+] Refined hypothesis for %s (iteration %u)\n", 
           hyp->message_type, ctx->refinement_iterations);
    
    return 1;
}

grammar_hypothesis_t* select_best_hypothesis(
    hypothesis_context_t *ctx,
    const char *message_type
) {
    grammar_hypothesis_t *best = NULL;
    double best_fitness = -1.0;
    
    for (size_t i = 0; i < ctx->hypothesis_count; i++) {
        grammar_hypothesis_t *hyp = ctx->hypotheses[i];
        
        if (strcmp(hyp->message_type, message_type) == 0) {
            if (hyp->fitness > best_fitness) {
                best_fitness = hyp->fitness;
                best = hyp;
            }
        }
    }
    
    return best;
}

/* ============================================
 * Persistence Functions
 * ============================================ */

int save_hypothesis_to_file(grammar_hypothesis_t *hyp, const char *filepath) {
    FILE *f = fopen(filepath, "w");
    if (!f) return 0;
    
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "hypothesis_id", json_object_new_int64(hyp->hypothesis_id));
    json_object_object_add(jobj, "message_type", json_object_new_string(hyp->message_type));
    json_object_object_add(jobj, "description", json_object_new_string(hyp->description));
    json_object_object_add(jobj, "schema", json_object_get(hyp->schema));
    json_object_object_add(jobj, "parse_success", json_object_new_int(hyp->parse_success));
    json_object_object_add(jobj, "parse_failure", json_object_new_int(hyp->parse_failure));
    json_object_object_add(jobj, "fitness", json_object_new_double(hyp->fitness));
    json_object_object_add(jobj, "created_at", json_object_new_int64(hyp->created_at));
    json_object_object_add(jobj, "last_updated", json_object_new_int64(hyp->last_updated));
    
    fprintf(f, "%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY));
    json_object_put(jobj);
    
    fclose(f);
    return 1;
}

grammar_hypothesis_t* load_hypothesis_from_file(const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = ck_alloc(fsize + 1);
    fread(content, 1, fsize, f);
    content[fsize] = '\0';
    fclose(f);
    
    grammar_hypothesis_t *hyp = parse_llm_hypothesis_response(content);
    ck_free(content);
    
    return hyp;
}

/* ============================================
 * Cleanup Functions
 * ============================================ */

void free_grammar_hypothesis(grammar_hypothesis_t *hyp) {
    if (!hyp) return;
    
    ck_free(hyp->message_type);
    ck_free(hyp->description);
    
    if (hyp->schema) {
        json_object_put(hyp->schema);
    }
    
    for (size_t i = 0; i < hyp->constraint_count; i++) {
        field_constraint_t *c = hyp->constraints[i];
        ck_free(c->field_name);
        
        if (c->type == CONSTRAINT_ENUM) {
            for (size_t j = 0; j < c->data.enumeration.count; j++) {
                ck_free(c->data.enumeration.values[j]);
            }
            ck_free(c->data.enumeration.values);
        } else if (c->type == CONSTRAINT_REGEX) {
            ck_free(c->data.regex.pattern);
        } else if (c->type == CONSTRAINT_DEPENDENCY) {
            ck_free(c->data.dependency.target_field);
            ck_free(c->data.dependency.condition);
        }
        
        ck_free(c);
    }
    ck_free(hyp->constraints);
    
    for (size_t i = 0; i < hyp->rule_count; i++) {
        ck_free(hyp->production_rules[i]);
    }
    ck_free(hyp->production_rules);
    
    for (size_t i = 0; i < hyp->counterexample_count; i++) {
        ck_free(hyp->counterexamples[i]);
    }
    ck_free(hyp->counterexamples);
    
    ck_free(hyp);
}

void free_hypothesis_context(hypothesis_context_t *ctx) {
    if (!ctx) return;
    
    ck_free(ctx->protocol_name);
    ck_free(ctx->rfc_text);
    
    for (size_t i = 0; i < ctx->pcap_count; i++) {
        ck_free(ctx->pcap_samples[i]);
    }
    ck_free(ctx->pcap_samples);
    
    for (size_t i = 0; i < ctx->response_count; i++) {
        ck_free(ctx->server_responses[i]);
    }
    ck_free(ctx->server_responses);
    
    for (size_t i = 0; i < ctx->hypothesis_count; i++) {
        free_grammar_hypothesis(ctx->hypotheses[i]);
    }
    ck_free(ctx->hypotheses);
    
    ck_free(ctx);
}

/* ============================================
 * Utility Functions
 * ============================================ */

void log_hypothesis_event(
    grammar_hypothesis_t *hyp,
    const char *event_type,
    const char *details
) {
    // Log to stderr for debugging
    fprintf(stderr, "[HYPOTHESIS-%llu] %s: %s | Type: %s | Fitness: %.3f\n",
            hyp->hypothesis_id,
            event_type,
            details,
            hyp->message_type,
            hyp->fitness);
}
