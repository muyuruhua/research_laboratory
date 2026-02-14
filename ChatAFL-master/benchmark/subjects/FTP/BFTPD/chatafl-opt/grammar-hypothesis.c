/*
 * ChatAFL-Opt: Grammar Hypothesis Implementation
 * ==============================================
 * Implementation of hypothesis-driven grammar learning with validation loop
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // For strcasestr
#include <time.h>
#include <ctype.h>

#include "grammar-hypothesis.h"
#include "chat-llm.h"
#include "rfc-knowledge.h"
#include "alloc-inl.h"

#define MAX_HYPOTHESIS_PROMPT 65536  // 64KB for large RFC content
#define MAX_RFC_CHARS 20000             // Default RFC extraction limit
#define MAX_PCAP_SAMPLES 20             // Maximum PCAP samples to include
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
    hypothesis_context_t *ctx = (hypothesis_context_t*)ck_alloc(sizeof(hypothesis_context_t));
    
    ctx->protocol_name = (char*)ck_strdup((u8*)protocol_name);
    
    // RFC Knowledge Enhancement: Auto-fetch if not provided
    if (rfc_text) {
        ctx->rfc_text = (char*)ck_strdup((u8*)rfc_text);
    } else {
        // Attempt to fetch RFC text from database
        printf("[*] RFC text not provided, attempting auto-fetch for %s...\n", protocol_name);
        ctx->rfc_text = fetch_rfc_text(protocol_name);
        
        if (ctx->rfc_text) {
            printf("[+] Successfully fetched RFC for %s (%zu bytes)\n", 
                   protocol_name, strlen(ctx->rfc_text));
        } else {
            printf("[!] Could not fetch RFC for %s, proceeding without RFC knowledge\n", 
                   protocol_name);
        }
    }
    
    // Copy PCAP samples
    ctx->pcap_count = pcap_count;
    if (pcap_count > 0) {
        ctx->pcap_samples = (char**)ck_alloc(pcap_count * sizeof(char*));
        for (size_t i = 0; i < pcap_count; i++) {
            ctx->pcap_samples[i] = (char*)ck_strdup((u8*)pcap_samples[i]);
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

/* ============================================
 * RFC Smart Extraction Functions
 * ============================================ */

char* extract_rfc_key_sections(const char *rfc_text, size_t max_chars) {
    // Priority sections for protocol grammar learning:
    // 1. Command definitions (USER, PASS, GET, POST, etc.)
    // 2. ABNF grammar rules
    // 3. Response code tables (2xx, 3xx, 4xx, 5xx)
    // 4. State machine descriptions
    // 5. Message format specifications
    
    if (!rfc_text) return NULL;
    
    size_t rfc_len = strlen(rfc_text);
    
    // If RFC is small enough, use it all
    if (rfc_len <= max_chars) {
        return (char*)ck_strdup((u8*)rfc_text);
    }
    
    // Smart extraction: find key sections
    char *extracted = (char*)ck_alloc(max_chars + 1);
    size_t extracted_len = 0;
    
    // Section markers to prioritize
    const char *priority_markers[] = {
        "ABNF",
        "Command Syntax",
        "Commands",
        "Request",
        "Response",
        "Status Code",
        "Message Format",
        "Protocol State",
        "State Machine",
        "Grammar",
        "Syntax",
        NULL
    };
    
    // Extract sections around priority markers
    for (int i = 0; priority_markers[i] && extracted_len < max_chars - 1000; i++) {
        const char *marker = strcasestr(rfc_text, priority_markers[i]);
        if (marker) {
            // Extract up to 2000 chars around this marker
            const char *start = marker - 500;
            if (start < rfc_text) start = rfc_text;
            
            size_t extract_size = 2000;
            if (extracted_len + extract_size > max_chars) {
                extract_size = max_chars - extracted_len;
            }
            
            // Ensure we don't read beyond RFC text
            size_t available = rfc_len - (start - rfc_text);
            if (extract_size > available) {
                extract_size = available;
            }
            
            // Ensure we have space for header + content + safety margin
            if (extract_size > 50 && extracted_len + extract_size + 100 < max_chars) {
                int written = snprintf(extracted + extracted_len, max_chars - extracted_len,
                         "\n[--- %s Section ---]\n%.*s\n",
                         priority_markers[i], (int)(extract_size - 50), start);
                if (written > 0 && written < (int)(max_chars - extracted_len)) {
                    extracted_len += written;
                }
            }
        }
    }
    
    // If no priority sections found, take first max_chars
    if (extracted_len < 1000) {
        int written = snprintf(extracted, max_chars + 1, "%.*s", (int)max_chars, rfc_text);
        if (written > 0 && written < (int)(max_chars + 1)) {
            extracted_len = written;
        }
    }
    extracted[max_chars] = '\0';  // Ensure null termination
    
    return extracted;
}

/* JSON escape helper - escape special characters for JSON strings */
static char* json_escape_string(const char *str, size_t max_len) {
    if (!str) return NULL;
    
    // Worst case: every character needs escaping (e.g., all quotes)
    size_t src_len = strlen(str);
    if (src_len > max_len) src_len = max_len;
    
    // Allocate enough for worst case: every char becomes 2 chars + null terminator
    // Add extra space for safety (6x for unicode escape sequences if needed)
    size_t buf_size = src_len * 6 + 1;
    char *escaped = (char*)ck_alloc(buf_size);
    size_t j = 0;
    
    for (size_t i = 0; i < src_len && str[i] != '\0'; i++) {
        // Safety check to prevent buffer overflow
        if (j >= buf_size - 7) {  // Reserve 7 bytes for worst case escape + null
            break;
        }
        
        switch (str[i]) {
            case '"':  escaped[j++] = '\\'; escaped[j++] = '"'; break;
            case '\\': escaped[j++] = '\\'; escaped[j++] = '\\'; break;
            case '\n': escaped[j++] = '\\'; escaped[j++] = 'n'; break;
            case '\r': escaped[j++] = '\\'; escaped[j++] = 'r'; break;
            case '\t': escaped[j++] = '\\'; escaped[j++] = 't'; break;
            case '\b': escaped[j++] = '\\'; escaped[j++] = 'b'; break;
            case '\f': escaped[j++] = '\\'; escaped[j++] = 'f'; break;
            default:
                if ((unsigned char)str[i] < 32) {
                    // Control characters - skip them
                    continue;
                }
                escaped[j++] = str[i];
                break;
        }
    }
    escaped[j] = '\0';
    return escaped;
}

int should_include_pcap_sample(
    const char *new_sample,
    char **existing_samples,
    size_t existing_count
) {
    // Deduplication: check if this sample is too similar to existing ones
    // Use simple edit distance heuristic
    
    size_t new_len = strlen(new_sample);
    
    for (size_t i = 0; i < existing_count; i++) {
        size_t existing_len = strlen(existing_samples[i]);
        
        // If lengths are too similar and first 20 chars match, likely duplicate
        if (abs((int)new_len - (int)existing_len) < 5) {
            size_t cmp_len = new_len < 20 ? new_len : 20;
            if (strncmp(new_sample, existing_samples[i], cmp_len) == 0) {
                return 0;  // Too similar, skip
            }
        }
    }
    
    return 1;  // Include this sample
}

char* construct_hypothesis_generation_prompt(hypothesis_context_t *ctx) {
    char *prompt = (char*)ck_alloc(MAX_HYPOTHESIS_PROMPT);
    int offset = 0;
    int written;
    
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "[{\"role\": \"system\", \"content\": \"You are a protocol grammar expert. "
        "Generate structured message grammars in JSON Schema format with field constraints.\"},"
        "{\"role\": \"user\", \"content\": \"");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Prompt buffer overflow at system message\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    // Protocol context
    char *escaped_protocol = json_escape_string(ctx->protocol_name, 256);
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Protocol: %s\\n\\n", escaped_protocol);
    ck_free(escaped_protocol);
    
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Prompt buffer overflow at protocol name\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    // Add RFC specification with smart extraction
    if (ctx->rfc_text) {
        char *rfc_extract = extract_rfc_key_sections(ctx->rfc_text, MAX_RFC_CHARS);
        
        if (rfc_extract) {
            char *escaped_rfc = json_escape_string(rfc_extract, MAX_RFC_CHARS);
            size_t extract_len = strlen(escaped_rfc);
            
            written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
                "RFC Specification (%zu characters):\\n%s\\n\\n",
                extract_len, escaped_rfc);
            
            ck_free(escaped_rfc);
            ck_free(rfc_extract);
            
            if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
                fprintf(stderr, "[!] Prompt buffer overflow at RFC content\n");
                fprintf(stderr, "[!] Continuing without RFC content\n");
            } else {
                offset += written;
                printf("[+] Injected %zu chars of RFC content into LLM prompt\n", extract_len);
            }
        }
    }
    
    // Add PCAP samples with deduplication
    if (ctx->pcap_count > 0) {
        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "Example Messages (from initial seeds):\\n");
        if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
            fprintf(stderr, "[!] Prompt buffer overflow at PCAP header\n");
            goto finalize_prompt;
        }
        offset += written;
        
        // Apply smart sampling: up to MAX_PCAP_SAMPLES diverse samples
        size_t sample_limit = ctx->pcap_count < MAX_PCAP_SAMPLES ? 
                              ctx->pcap_count : MAX_PCAP_SAMPLES;
        
        char **selected_samples = (char**)ck_alloc(sample_limit * sizeof(char*));
        size_t selected_count = 0;
        
        // Select diverse samples
        for (size_t i = 0; i < ctx->pcap_count && selected_count < sample_limit; i++) {
            if (should_include_pcap_sample(ctx->pcap_samples[i], 
                                          selected_samples, 
                                          selected_count)) {
                selected_samples[selected_count++] = ctx->pcap_samples[i];
            }
        }
        
        // Inject selected samples
        for (size_t i = 0; i < selected_count; i++) {
            char *escaped_sample = json_escape_string(selected_samples[i], 512);
            written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
                "%zu. %s\\n", i + 1, escaped_sample);
            ck_free(escaped_sample);
            
            if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
                fprintf(stderr, "[!] Prompt buffer overflow at PCAP sample %zu\n", i);
                break;
            }
            offset += written;
        }
        
        ck_free(selected_samples);
        
        printf("[+] Injected %zu diverse PCAP samples (from %zu total) into LLM prompt\n",
               selected_count, ctx->pcap_count);
        
        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, "\\n");
        if (written > 0 && written < MAX_HYPOTHESIS_PROMPT - offset) {
            offset += written;
        }
    }
    
finalize_prompt:
    
    // Request format
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
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
    
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Prompt buffer overflow at final request format\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    printf("[+] Constructed LLM prompt (%d bytes total)\n", offset);
    
    // Debug: Save prompt to file for inspection
    FILE *debug_fp = fopen("/tmp/hypothesis_prompt_debug.json", "w");
    if (debug_fp) {
        fwrite(prompt, 1, offset, debug_fp);
        fclose(debug_fp);
        printf("[DEBUG] Prompt saved to /tmp/hypothesis_prompt_debug.json\n");
    }
    
    return prompt;
}

char* construct_hypothesis_refinement_prompt(
    grammar_hypothesis_t *hyp,
    const char *protocol_name
) {
    char *prompt = (char*)ck_alloc(MAX_HYPOTHESIS_PROMPT);
    int offset = 0;
    int written;
    
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "[{\"role\": \"system\", \"content\": \"You are refining protocol grammar hypotheses "
        "based on counterexamples.\"},"
        "{\"role\": \"user\", \"content\": \"");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at header\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
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
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at hypothesis details\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    // Add counterexamples
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Counterexamples (messages that violated the hypothesis):\\n");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at counterexamples header\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    size_t ce_limit = hyp->counterexample_count < MAX_REFINEMENT_COUNTEREXAMPLES ? 
                      hyp->counterexample_count : MAX_REFINEMENT_COUNTEREXAMPLES;
    
    for (size_t i = 0; i < ce_limit; i++) {
        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "%zu. %s\\n", i + 1, hyp->counterexamples[i]);
        if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
            fprintf(stderr, "[!] Refinement prompt buffer overflow at counterexample %zu\n", i);
            break;  // Stop adding counterexamples but continue with what we have
        }
        offset += written;
    }
    
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "\\nPlease revise the grammar hypothesis to accommodate these counterexamples. "
        "Return the updated hypothesis in the same JSON format as before.\"}]");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at footer\n");
        // Keep what we have, just add closing
        snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, "\"}]");
    }
    
    return prompt;
}

/* ============================================
 * Hypothesis Generation
 * ============================================ */

int generate_grammar_hypotheses(hypothesis_context_t *ctx, int max_hypotheses) {
    char *prompt = construct_hypothesis_generation_prompt(ctx);
    
    if (!prompt) {
        fprintf(stderr, "[!] Failed to construct hypothesis generation prompt (buffer overflow)\n");
        return 0;
    }
    
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
    
    ctx->hypotheses = (grammar_hypothesis_t**)ck_alloc(hyp_count * sizeof(grammar_hypothesis_t*));
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
    
    grammar_hypothesis_t *hyp = (grammar_hypothesis_t*)ck_alloc(sizeof(grammar_hypothesis_t));
    memset(hyp, 0, sizeof(grammar_hypothesis_t));
    
    // Extract message_type
    json_object *msg_type_obj;
    if (json_object_object_get_ex(jobj, "message_type", &msg_type_obj)) {
        hyp->message_type = (char*)ck_strdup((u8*)json_object_get_string(msg_type_obj));
    }
    
    // Extract description
    json_object *desc_obj;
    if (json_object_object_get_ex(jobj, "description", &desc_obj)) {
        hyp->description = (char*)ck_strdup((u8*)json_object_get_string(desc_obj));
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
            hyp->production_rules = (char**)ck_alloc(hyp->rule_count * sizeof(char*));
            
            for (size_t i = 0; i < hyp->rule_count; i++) {
                json_object *rule = json_object_array_get_idx(rules_obj, i);
                hyp->production_rules[i] = (char*)ck_strdup((u8*)json_object_get_string(rule));
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
            
            field_constraint_t *constraint = (field_constraint_t*)ck_alloc(sizeof(field_constraint_t));
            constraint->type = CONSTRAINT_LENGTH;
            constraint->field_name = (char*)ck_strdup((u8*)field_name);
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
                field_constraint_t *constraint = (field_constraint_t*)ck_alloc(sizeof(field_constraint_t));
                constraint->type = CONSTRAINT_ENUM;
                constraint->field_name = (char*)ck_strdup((u8*)field_name);
                
                size_t enum_count = json_object_array_length(enum_obj);
                constraint->data.enumeration.count = enum_count;
                constraint->data.enumeration.values = (char**)ck_alloc(enum_count * sizeof(char*));
                
                for (size_t i = 0; i < enum_count; i++) {
                    json_object *val = json_object_array_get_idx(enum_obj, i);
                    constraint->data.enumeration.values[i] = (char*)ck_strdup((u8*)json_object_get_string(val));
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
            field_constraint_t *constraint = (field_constraint_t*)ck_alloc(sizeof(field_constraint_t));
            constraint->type = CONSTRAINT_REGEX;
            constraint->field_name = (char*)ck_strdup((u8*)field_name);
            constraint->data.regex.pattern = (char*)ck_strdup((u8*)json_object_get_string(pattern_obj));
            constraint->violations = 0;
            constraint->validations = 0;
            constraint->confidence = 1.0;
            
            hyp->constraints[hyp->constraint_count++] = constraint;
        }
        
        // Numeric range constraints
        json_object *minimum, *maximum;
        if (json_object_object_get_ex(field_schema, "minimum", &minimum) ||
            json_object_object_get_ex(field_schema, "maximum", &maximum)) {
            
            field_constraint_t *constraint = (field_constraint_t*)ck_alloc(sizeof(field_constraint_t));
            constraint->type = CONSTRAINT_NUMERIC;
            constraint->field_name = (char*)ck_strdup((u8*)field_name);
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
    hyp->counterexamples = (char**)ck_realloc(hyp->counterexamples, 
                                      (hyp->counterexample_count + 1) * sizeof(char*));
    
    char *ce = (char*)ck_alloc(len + 256);  // Message + error reason
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
    
    char *content = (char*)ck_alloc(fsize + 1);
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
