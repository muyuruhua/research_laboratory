/*
 * cfg-parser.c - Context-Free Grammar Parser Implementation
 * 
 * Recursive descent parser supporting:
 * - Terminals (literal strings)
 * - Non-terminals (rule references)
 * - Alternatives (A | B | C)
 * - Optional symbols (A?)
 * - Repetition (A*, A+)
 * - Sequences (A B C)
 */

#include "cfg-parser.h"
#include "verifier.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_RECURSION_DEPTH 50
#define MAX_RULES 256

/* ============ Grammar Loading ============ */

static cfg_symbol_t *create_symbol_from_json(json_object *json_sym) {
    if (!json_sym) return NULL;
    
    cfg_symbol_t *sym = (cfg_symbol_t *)ck_alloc(sizeof(cfg_symbol_t));
    memset(sym, 0, sizeof(cfg_symbol_t));
    
    // Parse type
    json_object *type_obj = json_object_object_get(json_sym, "type");
    const char *type_str = type_obj ? json_object_get_string(type_obj) : "nonterminal";
    
    if (strcmp(type_str, "terminal") == 0) {
        sym->type = SYMBOL_TERMINAL;
    } else if (strcmp(type_str, "optional") == 0) {
        sym->type = SYMBOL_OPTIONAL;
        sym->min_occurs = 0;
        sym->max_occurs = 1;
    } else if (strcmp(type_str, "repetition") == 0) {
        sym->type = SYMBOL_REPETITION;
        sym->min_occurs = 0;
        sym->max_occurs = -1;
    } else if (strcmp(type_str, "one_or_more") == 0) {
        sym->type = SYMBOL_ONE_OR_MORE;
        sym->min_occurs = 1;
        sym->max_occurs = -1;
    } else {
        sym->type = SYMBOL_NONTERMINAL;
        sym->min_occurs = 1;
        sym->max_occurs = 1;
    }
    
    // Parse name
    json_object *name_obj = json_object_object_get(json_sym, "name");
    if (name_obj) {
        sym->name = ck_strdup(json_object_get_string(name_obj));
    }
    
    // Parse alternatives (for terminals)
    json_object *alt_obj = json_object_object_get(json_sym, "alternatives");
    if (alt_obj && json_object_is_type(alt_obj, json_type_array)) {
        sym->alt_count = json_object_array_length(alt_obj);
        sym->alternatives = (char **)ck_alloc(sym->alt_count * sizeof(char *));
        for (int i = 0; i < sym->alt_count; i++) {
            json_object *item = json_object_array_get_idx(alt_obj, i);
            sym->alternatives[i] = ck_strdup(json_object_get_string(item));
        }
    }
    
    // Parse production (for non-terminals)
    json_object *prod_obj = json_object_object_get(json_sym, "production");
    if (prod_obj && json_object_is_type(prod_obj, json_type_array)) {
        sym->production_len = json_object_array_length(prod_obj);
        sym->production = (cfg_symbol_t **)ck_alloc(sym->production_len * sizeof(cfg_symbol_t *));
        for (int i = 0; i < sym->production_len; i++) {
            json_object *child = json_object_array_get_idx(prod_obj, i);
            sym->production[i] = create_symbol_from_json(child);
        }
    }
    
    return sym;
}

cfg_grammar_t *cfg_load_grammar(json_object *json_grammar) {
    if (!json_grammar) return NULL;
    
    cfg_grammar_t *grammar = (cfg_grammar_t *)ck_alloc(sizeof(cfg_grammar_t));
    memset(grammar, 0, sizeof(cfg_grammar_t));
    grammar->max_recursion_depth = MAX_RECURSION_DEPTH;
    
    // Parse start rule
    json_object *start_obj = json_object_object_get(json_grammar, "start");
    if (start_obj) {
        grammar->start_rule = ck_strdup(json_object_get_string(start_obj));
    } else {
        grammar->start_rule = ck_strdup("Message");  // Default
    }
    
    // Parse rules
    json_object *rules_obj = json_object_object_get(json_grammar, "rules");
    if (rules_obj && json_object_is_type(rules_obj, json_type_array)) {
        grammar->rule_count = json_object_array_length(rules_obj);
        if (grammar->rule_count > MAX_RULES) grammar->rule_count = MAX_RULES;
        
        grammar->rules = (cfg_rule_t *)ck_alloc(grammar->rule_count * sizeof(cfg_rule_t));
        
        for (int i = 0; i < grammar->rule_count; i++) {
            json_object *rule_obj = json_object_array_get_idx(rules_obj, i);
            
            json_object *name_obj = json_object_object_get(rule_obj, "name");
            if (name_obj) {
                grammar->rules[i].rule_name = ck_strdup(json_object_get_string(name_obj));
            }
            
            grammar->rules[i].symbol = create_symbol_from_json(rule_obj);
        }
    }
    
    return grammar;
}

void cfg_free_grammar(cfg_grammar_t *grammar) {
    if (!grammar) return;
    
    if (grammar->start_rule) ck_free(grammar->start_rule);
    
    for (int i = 0; i < grammar->rule_count; i++) {
        if (grammar->rules[i].rule_name) ck_free(grammar->rules[i].rule_name);
        // TODO: Recursively free symbols
    }
    
    if (grammar->rules) ck_free(grammar->rules);
    ck_free(grammar);
}

/* ============ Parsing Implementation ============ */

static void skip_whitespace(parser_context_t *ctx) {
    while (ctx->pos < ctx->input_len && 
           (ctx->input[ctx->pos] == ' ' || ctx->input[ctx->pos] == '\t')) {
        ctx->pos++;
    }
}

static int match_literal(
    parser_context_t *ctx,
    const char *literal,
    parse_node_t **node_out) {
    
    size_t lit_len = strlen(literal);
    if (ctx->pos + lit_len > ctx->input_len) {
        return 0;
    }
    
    if (memcmp(&ctx->input[ctx->pos], literal, lit_len) == 0) {
        if (node_out) {
            parse_node_t *node = (parse_node_t *)ck_alloc(sizeof(parse_node_t));
            node->rule_name = ck_strdup("LITERAL");
            node->matched_start = &ctx->input[ctx->pos];
            node->matched_len = lit_len;
            node->children = NULL;
            node->child_count = 0;
            *node_out = node;
        }
        ctx->pos += lit_len;
        return 1;
    }
    
    return 0;
}

static cfg_rule_t *find_rule(cfg_grammar_t *grammar, const char *rule_name) {
    for (int i = 0; i < grammar->rule_count; i++) {
        if (grammar->rules[i].rule_name && 
            strcmp(grammar->rules[i].rule_name, rule_name) == 0) {
            return &grammar->rules[i];
        }
    }
    return NULL;
}

static int parse_terminal(
    parser_context_t *ctx,
    cfg_symbol_t *symbol,
    parse_node_t **node_out) {
    
    if (!symbol || symbol->type != SYMBOL_TERMINAL) return 0;
    
    // Try each alternative
    for (int i = 0; i < symbol->alt_count; i++) {
        size_t saved_pos = ctx->pos;
        if (match_literal(ctx, symbol->alternatives[i], node_out)) {
            return 1;
        }
        ctx->pos = saved_pos;
    }
    
    // Try name as literal if no alternatives
    if (symbol->alt_count == 0 && symbol->name) {
        return match_literal(ctx, symbol->name, node_out);
    }
    
    return 0;
}

static int parse_nonterminal(
    parser_context_t *ctx,
    cfg_symbol_t *symbol,
    parse_node_t **node_out) {
    
    if (!symbol || !symbol->name) return 0;
    
    // Recursion check
    ctx->recursion_depth++;
    if (ctx->recursion_depth > ctx->grammar->max_recursion_depth) {
        ctx->recursion_depth--;
        return 0;
    }
    
    // Find rule
    cfg_rule_t *rule = find_rule(ctx->grammar, symbol->name);
    if (!rule || !rule->symbol) {
        ctx->recursion_depth--;
        return 0;
    }
    
    size_t start_pos = ctx->pos;
    
    // Parse rule's production
    int result = 0;
    if (rule->symbol->production_len > 0) {
        result = parse_sequence(ctx, rule->symbol->production, 
                               rule->symbol->production_len, node_out);
    } else if (rule->symbol->alt_count > 0) {
        result = parse_terminal(ctx, rule->symbol, node_out);
    }
    
    if (result && node_out && *node_out) {
        (*node_out)->rule_name = ck_strdup(symbol->name);
        (*node_out)->matched_start = &ctx->input[start_pos];
        (*node_out)->matched_len = ctx->pos - start_pos;
    }
    
    ctx->recursion_depth--;
    return result;
}

static int parse_sequence(
    parser_context_t *ctx,
    cfg_symbol_t **symbols,
    int symbol_count,
    parse_node_t **node_out) {
    
    if (!symbols || symbol_count == 0) return 0;
    
    size_t start_pos = ctx->pos;
    parse_node_t *parent = NULL;
    
    if (node_out) {
        parent = (parse_node_t *)ck_alloc(sizeof(parse_node_t));
        parent->rule_name = ck_strdup("SEQUENCE");
        parent->matched_start = &ctx->input[start_pos];
        parent->children = (parse_node_t **)ck_alloc(symbol_count * sizeof(parse_node_t *));
        parent->child_count = 0;
    }
    
    for (int i = 0; i < symbol_count; i++) {
        cfg_symbol_t *sym = symbols[i];
        parse_node_t *child = NULL;
        
        int matched = 0;
        
        switch (sym->type) {
            case SYMBOL_TERMINAL:
                matched = parse_terminal(ctx, sym, &child);
                break;
                
            case SYMBOL_NONTERMINAL:
                matched = parse_nonterminal(ctx, sym, &child);
                break;
                
            case SYMBOL_OPTIONAL:
                // Try to match, but don't fail if can't
                if (sym->production_len > 0) {
                    parse_sequence(ctx, sym->production, sym->production_len, &child);
                }
                matched = 1;  // Always succeeds
                break;
                
            case SYMBOL_REPETITION:
            case SYMBOL_ONE_OR_MORE:
                {
                    int match_count = 0;
                    while (1) {
                        size_t saved_pos = ctx->pos;
                        parse_node_t *rep_child = NULL;
                        int rep_matched = 0;
                        
                        if (sym->production_len > 0) {
                            rep_matched = parse_sequence(ctx, sym->production, 
                                                        sym->production_len, &rep_child);
                        } else if (sym->name) {
                            rep_matched = parse_nonterminal(ctx, sym, &rep_child);
                        }
                        
                        if (!rep_matched) {
                            ctx->pos = saved_pos;
                            break;
                        }
                        match_count++;
                        
                        if (parent && rep_child) {
                            parent->children[parent->child_count++] = rep_child;
                        }
                    }
                    
                    matched = (sym->type == SYMBOL_REPETITION) ? 1 : (match_count >= 1);
                }
                break;
        }
        
        if (!matched) {
            // Sequence failed, rollback
            ctx->pos = start_pos;
            if (parent) {
                cfg_free_parse_tree(parent);
            }
            return 0;
        }
        
        if (parent && child) {
            parent->children[parent->child_count++] = child;
        }
        
        skip_whitespace(ctx);
    }
    
    if (parent) {
        parent->matched_len = ctx->pos - start_pos;
        if (node_out) *node_out = parent;
    }
    
    return 1;
}

int cfg_parse_message(
    cfg_grammar_t *grammar,
    const unsigned char *message,
    size_t msg_len,
    parse_node_t **parse_tree_out) {
    
    if (!grammar || !message || msg_len == 0) return 0;
    
    parser_context_t ctx = {0};
    ctx.input = message;
    ctx.input_len = msg_len;
    ctx.pos = 0;
    ctx.recursion_depth = 0;
    ctx.grammar = grammar;
    
    // Find start rule
    cfg_rule_t *start_rule = find_rule(grammar, grammar->start_rule);
    if (!start_rule) return 0;
    
    parse_node_t *tree = NULL;
    int result = parse_nonterminal(&ctx, start_rule->symbol, &tree);
    
    // Check if consumed entire input
    if (result && ctx.pos != msg_len) {
        result = 0;  // Partial match not acceptable
    }
    
    if (result && parse_tree_out) {
        *parse_tree_out = tree;
    } else if (tree) {
        cfg_free_parse_tree(tree);
    }
    
    return result;
}

/* ============ Field Extraction ============ */

static void extract_fields_recursive(
    parse_node_t *node,
    parsed_field_t **fields_array,
    int *field_count,
    int max_fields) {
    
    if (!node || !fields_array || !field_count) return;
    if (*field_count >= max_fields) return;
    
    // Add this node as a field if it has a meaningful name
    if (node->rule_name && strcmp(node->rule_name, "SEQUENCE") != 0 && 
        strcmp(node->rule_name, "LITERAL") != 0 && node->matched_len > 0) {
        
        parsed_field_t *field = &(*fields_array)[*field_count];
        field->start = node->matched_start - node->matched_start;  // Relative offset
        field->len = node->matched_len;
        field->name = ck_strdup(node->rule_name);
        field->type = ck_strdup("parsed");
        field->mutable = 1;
        (*field_count)++;
    }
    
    // Recurse into children
    for (int i = 0; i < node->child_count && *field_count < max_fields; i++) {
        extract_fields_recursive(node->children[i], fields_array, field_count, max_fields);
    }
}

int cfg_extract_fields(
    parse_node_t *parse_tree,
    parsed_field_t **fields_out,
    int *field_count_out) {
    
    if (!parse_tree || !fields_out || !field_count_out) return 0;
    
    parsed_field_t *fields = (parsed_field_t *)ck_alloc(MAX_FIELDS * sizeof(parsed_field_t));
    int count = 0;
    
    extract_fields_recursive(parse_tree, &fields, &count, MAX_FIELDS);
    
    *fields_out = fields;
    *field_count_out = count;
    return count;
}

void cfg_free_parse_tree(parse_node_t *tree) {
    if (!tree) return;
    
    if (tree->rule_name) ck_free(tree->rule_name);
    
    for (int i = 0; i < tree->child_count; i++) {
        cfg_free_parse_tree(tree->children[i]);
    }
    
    if (tree->children) ck_free(tree->children);
    ck_free(tree);
}

/* ============ LLM Grammar Conversion ============ */

json_object *cfg_convert_llm_grammar(const char *llm_text) {
    if (!llm_text) return NULL;
    
    json_object *grammar = json_object_new_object();
    json_object *rules_array = json_object_new_array();
    
    // Parse LLM text line by line
    const char *line_start = llm_text;
    char first_rule[256] = {0};
    int first_rule_found = 0;
    
    while (*line_start) {
        const char *line_end = strchr(line_start, '\n');
        if (!line_end) line_end = line_start + strlen(line_start);
        
        size_t line_len = line_end - line_start;
        if (line_len > 0 && line_len < 1024) {
            char line[1024];
            strncpy(line, line_start, line_len);
            line[line_len] = '\0';
            
            // Look for pattern: "RuleName := production"
            char *assign = strstr(line, ":=");
            if (assign) {
                *assign = '\0';
                char *rule_name = line;
                char *production = assign + 2;
                
                // Trim whitespace
                while (*rule_name == ' ') rule_name++;
                while (*production == ' ') production++;
                
                if (!first_rule_found && strlen(rule_name) > 0) {
                    strncpy(first_rule, rule_name, sizeof(first_rule) - 1);
                    first_rule_found = 1;
                }
                
                // Create rule
                json_object *rule = json_object_new_object();
                json_object_object_add(rule, "name", json_object_new_string(rule_name));
                
                // Parse production (simple: split by |)
                json_object *alternatives = json_object_new_array();
                char *alt_start = production;
                while (*alt_start) {
                    char *pipe = strchr(alt_start, '|');
                    if (pipe) *pipe = '\0';
                    
                    // Trim
                    while (*alt_start == ' ') alt_start++;
                    char *alt_end = alt_start + strlen(alt_start) - 1;
                    while (alt_end > alt_start && *alt_end == ' ') *alt_end-- = '\0';
                    
                    if (strlen(alt_start) > 0) {
                        json_object_array_add(alternatives, json_object_new_string(alt_start));
                    }
                    
                    if (!pipe) break;
                    alt_start = pipe + 1;
                }
                
                json_object_object_add(rule, "alternatives", alternatives);
                json_object_object_add(rule, "type", json_object_new_string("terminal"));
                json_object_array_add(rules_array, rule);
            }
        }
        
        line_start = (*line_end == '\n') ? line_end + 1 : line_end;
    }
    
    json_object_object_add(grammar, "rules", rules_array);
    json_object_object_add(grammar, "start", 
        json_object_new_string(first_rule_found ? first_rule : "Message"));
    
    return grammar;
}
