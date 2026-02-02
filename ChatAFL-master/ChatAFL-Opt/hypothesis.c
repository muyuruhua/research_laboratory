#define _GNU_SOURCE
#include "hypothesis.h"
#include "chat-llm.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Grammar Hypothesis Implementation */

hypothesis_context_t *init_hypothesis_context(const char *protocol_name) {
    hypothesis_context_t *ctx = (hypothesis_context_t *)ck_alloc(sizeof(hypothesis_context_t));
    ctx->protocol_name = strdup(protocol_name);
    ctx->grammar_list = kl_init(hypo);
    ctx->message_type_index = kh_init(strMap);
    ctx->rfc_snippet = NULL;
    ctx->pcap_examples = NULL;
    ctx->hypothesis_count = 0;
    return ctx;
}

char *construct_grammar_hypothesis_prompt(const char *protocol_name,
                                          const char *message_type,
                                          const char *rfc_context,
                                          const char *examples) {
    char *prompt = NULL;
    asprintf(&prompt,
        "[{\"role\": \"system\", \"content\": \"You are a protocol grammar expert. Generate PRECISE and VERIFIABLE grammar specifications.\"}, "
        "{\"role\": \"user\", \"content\": \"Protocol: %s\\nMessage Type: %s\\n\\n"
        "RFC Context:\\n%s\\n\\nExamples:\\n%s\\n\\n"
        "Generate a JSON grammar specification with:\\n"
        "1. 'grammar': ABNF-style production rules\\n"
        "2. 'fields': Array of {name, type, min_length, max_length, pattern, enum_values, dependency}\\n"
        "3. 'constraints': Additional semantic constraints\\n\\n"
        "Response format:\\n"
        "```json\\n{\\\"message_type\\\": \\\"%s\\\", \\\"grammar\\\": \\\"...\\\", \\\"fields\\\": [...], \\\"constraints\\\": [...]}\\n```\"}]",
        protocol_name, message_type, rfc_context ? rfc_context : "Not provided",
        examples ? examples : "Not provided", message_type);
    return prompt;
}

grammar_hypothesis_t *parse_hypothesis_from_llm_response(const char *llm_response,
                                                         const char *message_type,
                                                         int revision) {
    if (!llm_response) return NULL;
    
    // Extract JSON from markdown code block
    const char *json_start = strstr(llm_response, "```json");
    if (json_start) {
        json_start += 7; // Skip "```json\n"
        const char *json_end = strstr(json_start, "```");
        if (json_end) {
            size_t json_len = json_end - json_start;
            char *json_str = strndup(json_start, json_len);
            
            json_object *jobj = json_tokener_parse(json_str);
            if (jobj) {
                grammar_hypothesis_t *h = (grammar_hypothesis_t *)ck_alloc(sizeof(grammar_hypothesis_t));
                h->message_type = strdup(message_type);
                
                json_object *grammar_obj;
                if (json_object_object_get_ex(jobj, "grammar", &grammar_obj)) {
                    h->grammar_spec = strdup(json_object_get_string(grammar_obj));
                } else {
                    h->grammar_spec = strdup("UNKNOWN");
                }
                
                json_object *fields_obj;
                if (json_object_object_get_ex(jobj, "fields", &fields_obj)) {
                    h->field_constraints = json_object_get(fields_obj);
                } else {
                    h->field_constraints = json_object_new_array();
                }
                
                h->confidence_score = 50; // Initial confidence
                h->created_at = time(NULL);
                h->revision = revision;
                
                json_object_put(jobj);
                free(json_str);
                return h;
            }
            free(json_str);
        }
    }
    
    return NULL;
}

grammar_hypothesis_t *generate_message_hypothesis(const char *protocol_name,
                                                  const char *message_type,
                                                  const char *context,
                                                  int revision) {
    char *prompt = construct_grammar_hypothesis_prompt(protocol_name, message_type, context, NULL);
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.3); // Low temperature for precision
    
    grammar_hypothesis_t *hypothesis = NULL;
    if (response) {
        hypothesis = parse_hypothesis_from_llm_response(response, message_type, revision);
        free(response);
    }
    free(prompt);
    
    return hypothesis;
}

int generate_initial_hypotheses(hypothesis_context_t *ctx,
                                const char *rfc_snippet,
                                const char *pcap_examples,
                                const char *server_responses) {
    if (rfc_snippet) {
        ctx->rfc_snippet = strdup(rfc_snippet);
    }
    if (pcap_examples) {
        ctx->pcap_examples = strdup(pcap_examples);
    }
    
    // First, get list of message types from LLM
    char *msg_types_prompt = NULL;
    asprintf(&msg_types_prompt,
        "[{\"role\": \"system\", \"content\": \"You are a protocol expert.\"}, "
        "{\"role\": \"user\", \"content\": \"Protocol: %s\\n\\n"
        "List all message types in this protocol (e.g., for FTP: USER, PASS, CWD, etc.).\\n"
        "Response format: JSON array [\\\"TYPE1\\\", \\\"TYPE2\\\", ...]\"}]",
        ctx->protocol_name);
    
    char *msg_types_response = chat_with_llm(msg_types_prompt, "gpt-4o-mini", 3, 0.3);
    free(msg_types_prompt);
    
    if (!msg_types_response) return 0;
    
    // Parse message types
    json_object *types_array = json_tokener_parse(msg_types_response);
    if (!types_array || !json_object_is_type(types_array, json_type_array)) {
        if (types_array) json_object_put(types_array);
        free(msg_types_response);
        return 0;
    }
    
    int count = 0;
    int array_len = json_object_array_length(types_array);
    for (int i = 0; i < array_len; i++) {
        json_object *type_obj = json_object_array_get_idx(types_array, i);
        const char *msg_type = json_object_get_string(type_obj);
        
        grammar_hypothesis_t *h = generate_message_hypothesis(ctx->protocol_name, msg_type, rfc_snippet, 0);
        if (h) {
            klnode_t(hypo) *node = kl_pushp(hypo, ctx->grammar_list);
            node->data = h;
            
            int ret;
            khiter_t k = kh_put(strMap, ctx->message_type_index, strdup(msg_type), &ret);
            kh_value(ctx->message_type_index, k) = count;
            
            count++;
        }
    }
    
    json_object_put(types_array);
    free(msg_types_response);
    
    ctx->hypothesis_count = count;
    return count;
}

char *construct_refinement_prompt(grammar_hypothesis_t *hypothesis,
                                  const char *counterexample,
                                  const char *failure_reason,
                                  const char *field_to_fix) {
    char *prompt = NULL;
    asprintf(&prompt,
        "[{\"role\": \"system\", \"content\": \"You are a grammar refinement expert. Make MINIMAL, TARGETED fixes only.\"}, "
        "{\"role\": \"user\", \"content\": \"Current Grammar (revision %d):\\n%s\\n\\n"
        "Counterexample (failed):\\n%s\\n\\n"
        "Failure Reason:\\n%s\\n\\n"
        "CONSTRAINT: Only modify field '%s'. Do not change other fields or structure.\\n\\n"
        "Provide refined grammar in same JSON format. Change ONLY the specified field constraint.\"}]",
        hypothesis->revision, hypothesis->grammar_spec, counterexample, failure_reason,
        field_to_fix ? field_to_fix : "UNKNOWN");
    return prompt;
}

grammar_hypothesis_t *refine_hypothesis(grammar_hypothesis_t *old_hypothesis,
                                        const char *counterexample,
                                        const char *failure_reason,
                                        const char *minimal_diff) {
    char *prompt = construct_refinement_prompt(old_hypothesis, counterexample, 
                                               failure_reason, minimal_diff);
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 2, 0.2); // Very low temperature
    
    grammar_hypothesis_t *refined = NULL;
    if (response) {
        refined = parse_hypothesis_from_llm_response(response, old_hypothesis->message_type,
                                                     old_hypothesis->revision + 1);
        if (refined) {
            refined->confidence_score = old_hypothesis->confidence_score - 10; // Penalize for failure
        }
        free(response);
    }
    free(prompt);
    
    return refined;
}

field_constraint_t **extract_field_constraints(const char *grammar_spec, int *count) {
    // Stub: would parse grammar_spec and extract field constraints
    *count = 0;
    return NULL;
}

void free_grammar_hypothesis(grammar_hypothesis_t *h) {
    if (!h) return;
    if (h->message_type) free(h->message_type);
    if (h->grammar_spec) free(h->grammar_spec);
    if (h->field_constraints) json_object_put(h->field_constraints);
    ck_free(h);
}

void free_hypothesis_context(hypothesis_context_t *ctx) {
    if (!ctx) return;
    if (ctx->protocol_name) free(ctx->protocol_name);
    if (ctx->rfc_snippet) free(ctx->rfc_snippet);
    if (ctx->pcap_examples) free(ctx->pcap_examples);
    
    // Free grammar list
    klnode_t(hypo) *node;
    for (node = ctx->grammar_list->head; node != ctx->grammar_list->tail; node = node->next) {
        free_grammar_hypothesis(node->data);
    }
    kl_destroy(hypo, ctx->grammar_list);
    
    // Free index
    khiter_t k;
    for (k = kh_begin(ctx->message_type_index); k != kh_end(ctx->message_type_index); ++k) {
        if (kh_exist(ctx->message_type_index, k)) {
            free((char *)kh_key(ctx->message_type_index, k));
        }
    }
    kh_destroy(strMap, ctx->message_type_index);
    
    ck_free(ctx);
}

void free_field_constraint(field_constraint_t *fc) {
    if (!fc) return;
    if (fc->field_name) free(fc->field_name);
    if (fc->field_type) free(fc->field_type);
    if (fc->dependency) free(fc->dependency);
    if (fc->pattern) free(fc->pattern);
    if (fc->enum_values) {
        for (int i = 0; i < fc->enum_count; i++) {
            free(fc->enum_values[i]);
        }
        free(fc->enum_values);
    }
    free(fc);
}
