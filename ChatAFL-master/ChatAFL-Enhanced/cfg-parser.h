/*
 * cfg-parser.h - Context-Free Grammar Parser for Protocol Message Validation
 * 
 * Implements recursive descent parser for ABNF-style grammars
 * Used by verifier.c for true parseability verification
 * 
 * Grammar format (JSON):
 * {
 *   "rules": [
 *     {
 *       "name": "HTTP-Request",
 *       "production": ["Request-Line", "Headers", "CRLF", "Body?"]
 *     },
 *     {
 *       "name": "Request-Line",
 *       "production": ["Method", "SP", "URI", "SP", "HTTP-Version", "CRLF"]
 *     },
 *     {
 *       "name": "Method",
 *       "alternatives": ["GET", "POST", "PUT", "DELETE"],
 *       "type": "terminal"
 *     }
 *   ],
 *   "start": "HTTP-Request"
 * }
 */

#ifndef __CFG_PARSER_H
#define __CFG_PARSER_H

#include <json-c/json.h>
#include <stdint.h>
#include <stdbool.h>

/* ============ Data Structures ============ */

typedef enum {
    SYMBOL_TERMINAL,      // Literal string or token
    SYMBOL_NONTERMINAL,   // References another rule
    SYMBOL_OPTIONAL,      // Can be omitted (?)
    SYMBOL_REPETITION,    // Zero or more (*)
    SYMBOL_ONE_OR_MORE    // One or more (+)
} symbol_type_t;

typedef struct cfg_symbol {
    symbol_type_t type;
    char *name;                      // Rule name or literal
    char **alternatives;             // For terminal: alternative literals
    int alt_count;
    struct cfg_symbol **production;  // For non-terminal: sequence of symbols
    int production_len;
    int min_occurs;                  // Min occurrences (for repetition)
    int max_occurs;                  // Max occurrences (-1 = unlimited)
} cfg_symbol_t;

typedef struct {
    char *rule_name;
    cfg_symbol_t *symbol;
} cfg_rule_t;

typedef struct {
    cfg_rule_t *rules;
    int rule_count;
    char *start_rule;
    int max_recursion_depth;  // Prevent infinite recursion
} cfg_grammar_t;

typedef struct {
    const unsigned char *input;
    size_t input_len;
    size_t pos;                 // Current parsing position
    int recursion_depth;
    cfg_grammar_t *grammar;
    
    // Parse tree (optional, for debugging)
    void *parse_tree_root;
} parser_context_t;

typedef struct parse_node {
    char *rule_name;
    const unsigned char *matched_start;
    size_t matched_len;
    struct parse_node **children;
    int child_count;
} parse_node_t;

/* ============ API Functions ============ */

/**
 * @brief Load grammar from JSON object
 * @param json_grammar JSON object containing grammar rules
 * @return Parsed grammar structure, or NULL on error
 */
cfg_grammar_t *cfg_load_grammar(json_object *json_grammar);

/**
 * @brief Free grammar structure
 */
void cfg_free_grammar(cfg_grammar_t *grammar);

/**
 * @brief Parse message against grammar
 * 
 * @param grammar CFG grammar
 * @param message Input message
 * @param msg_len Message length
 * @param parse_tree_out Optional output for parse tree
 * @return 1 if message matches grammar, 0 otherwise
 */
int cfg_parse_message(
    cfg_grammar_t *grammar,
    const unsigned char *message,
    size_t msg_len,
    parse_node_t **parse_tree_out
);

/**
 * @brief Extract fields from parse tree
 * 
 * @param parse_tree Root of parse tree
 * @param fields_out Output array of parsed fields
 * @return Number of fields extracted
 */
int cfg_extract_fields(
    parse_node_t *parse_tree,
    parsed_field_t **fields_out,
    int *field_count_out
);

/**
 * @brief Free parse tree
 */
void cfg_free_parse_tree(parse_node_t *tree);

/**
 * @brief Convert LLM grammar text to JSON
 * 
 * Parses LLM output like:
 *   "Method := GET | POST | PUT"
 *   "Request-Line := Method SP URI SP HTTP-Version CRLF"
 * 
 * @param llm_text Raw text from LLM
 * @return JSON object representing CFG
 */
json_object *cfg_convert_llm_grammar(const char *llm_text);

/* ============ Internal Functions ============ */

// Recursive descent parser for non-terminal
static int parse_nonterminal(
    parser_context_t *ctx,
    cfg_symbol_t *symbol,
    parse_node_t **node_out
);

// Match terminal symbol
static int parse_terminal(
    parser_context_t *ctx,
    cfg_symbol_t *symbol,
    parse_node_t **node_out
);

// Match sequence of symbols
static int parse_sequence(
    parser_context_t *ctx,
    cfg_symbol_t **symbols,
    int symbol_count,
    parse_node_t **node_out
);

// Match alternatives (A | B | C)
static int parse_alternatives(
    parser_context_t *ctx,
    cfg_symbol_t **alternatives,
    int alt_count,
    parse_node_t **node_out
);

// Skip whitespace
static void skip_whitespace(parser_context_t *ctx);

// Match literal string
static int match_literal(
    parser_context_t *ctx,
    const char *literal,
    parse_node_t **node_out
);

#endif /* __CFG_PARSER_H */
