#ifndef __VERIFIER_H
#define __VERIFIER_H

#include "types.h"  // Provides u32, u8, etc.
#include "cfg-parser.h"  // Provides cfg_grammar_t definition
#include <json-c/json.h>
#include <stdint.h>
#include <time.h>

/* ============ Constants ============ */
#define MAX_FIELDS 64
#define STATE_CACHE_SIZE 4096
#define MAX_RESPONSE_SIZE 65536

/*
 * Verifier v0: Grammar validation and message verification
 * 
 * Purpose:
 *   - Parseability: Can generated message be parsed by grammar?
 *   - Acceptability: Does SUT accept the message (non-error response)?
 *   - State Reachability: Does message sequence trigger new states?
 *   - Coverage Gain: Does message increase coverage/state count?
 */

/* ============ Data Structures ============ */

typedef struct parsed_field {
    int start;      // byte offset in message
    int len;        // byte length
    char *name;     // field name (e.g., "Content-Length")
    char *type;     // field type (e.g., "integer", "string", "enum")
    int mutable;    // can this field be mutated?
} parsed_field_t;

typedef struct {
    parsed_field_t *fields;
    int field_count;
} parsed_fields_t;

typedef enum {
    RESP_2XX = 200,  // Success
    RESP_3XX = 300,  // Redirect
    RESP_4XX = 400,  // Client error (rejection)
    RESP_5XX = 500,  // Server error
    RESP_UNKNOWN = -1
} response_class_t;

typedef struct {
    int status_code;          // HTTP or protocol-specific status
    char *status_message;     // e.g., "200 OK", "550 Access denied"
    char **headers;           // key-value pairs
    int header_count;
    unsigned char *body;      // response body
    int body_len;
    response_class_t classification;
    time_t timestamp;
} response_t;

typedef struct {
    unsigned int state_id;         // hash(response codes + coverage)
    int visitation_count;          // how many times visited
    int is_new;                    // discovered in this fuzzing round
    float coverage;                // code coverage at this state
    time_t last_visited;
} state_node_t;

typedef struct {
    unsigned int from_state;       // source state
    unsigned int to_state;         // target state
    char *message_type;            // message that triggers transition
    int transition_count;          // how many times triggered
    int frequency;                 // alias for transition_count (for rarity calculation)
    int coverage_gain;             // code coverage gained at to_state
} state_transition_t;

typedef struct {
    state_node_t *nodes;           // state transition tree nodes
    int node_count;
    state_transition_t *transitions;
    int transition_count;
    unsigned int current_state;    // current state in tree
} state_transition_tree_t;

typedef struct {
    unsigned char *message;        // the failing message
    size_t msg_len;
    int field_idx;                 // which field failed?
    char *failure_reason;          // "parse error" / "status 400" / etc.
    response_t response;
    parsed_fields_t *parsed_fields;
} counterexample_t;

typedef struct {
    int enable_logging;
    int debug_mode;
    char *log_file;
    state_transition_tree_t *stt;
} verifier_config_t;

typedef struct {
    unsigned char **messages;
    size_t *msg_lens;
    int message_count;
    response_t *responses;
} message_sequence_t;

/* ============ Verifier Functions ============ */

/**
 * @brief Initialize verifier context
 */
void verifier_init(verifier_config_t *config);

/**
 * @brief Check if message can be parsed according to grammar
 * @return 1 if parseable, 0 if parse error
 */
int verify_parseability(
    const unsigned char *message,
    size_t msg_len,
    json_object *grammar,
    parsed_fields_t **fields_out
);

/**
 * @brief Send message to SUT and check if response is non-error
 * @return 1 if accepted (2xx/3xx), 0 if rejected (4xx/5xx or timeout)
 */
int verify_acceptability(
    const char *host,
    int port,
    const unsigned char *request,
    size_t req_len,
    response_t *response_out,
    int timeout_ms
);

/**
 * @brief Check if message sequence reaches a new state (STT)
 * @return 1 if new state discovered, 0 otherwise
 */
int verify_state_reachability(
    const unsigned int *state_sequence,
    int state_count,
    state_transition_tree_t *stt,
    int *is_new_state_out
);

/**
 * @brief Calculate coverage gain from single message
 * Simple approximation: new state node → gain
 */
float calculate_coverage_gain(
    const state_transition_tree_t *stt,
    const response_t *response
);

/**
 * @brief Calculate coverage gain from AFL bitmap (MODULARIZED)
 * Used by afl-fuzz.c to delegate coverage calculation to verifier module
 */
float calculate_coverage_gain_from_bitmap(
    const unsigned char *bitmap,
    size_t bitmap_size,
    u32 previous_total,
    u32 current_total,
    const state_transition_tree_t *stt
);

/**
 * @brief CFG-based parseability check (uses recursive descent parser)
 * @return 1 if message matches CFG grammar, 0 otherwise
 */
int verify_parseability_with_cfg(
    const unsigned char *message,
    size_t msg_len,
    cfg_grammar_t *grammar,
    parsed_fields_t **fields_out
);

/**
 * @brief Minimize counterexample using delta-debugging
 * Remove/modify fields one by one until message still fails
 */
unsigned char *minimize_counterexample(
    const unsigned char *message,
    size_t msg_len,
    json_object *grammar,
    size_t *minimized_len_out
);

/**
 * @brief Log verification result for reproducibility
 */
void log_verification_result(
    const char *message_hex,
    int parseability,
    int acceptability,
    int state_reachability,
    const response_t *response
);

/**
 * @brief Update STT with new response sequence
 */
void update_state_transition_tree(
    state_transition_tree_t *stt,
    const unsigned int *response_codes,
    int response_count,
    const char *triggering_message_type
);

/**
 * @brief Get state ID from response sequence hash
 */
unsigned int compute_state_id(
    const unsigned int *response_sequence,
    int count,
    const unsigned char *coverage_bitmap,
    int bitmap_size
);

/**
 * @brief Free verification structures
 */
void verifier_cleanup(void);

/**
 * @brief Clean up response_t structure (frees status_message, headers, body)
 */
void response_cleanup(response_t *response);

#endif // __VERIFIER_H
