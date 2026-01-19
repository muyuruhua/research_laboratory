/*
 * verifier.c - Grammar and message verification engine
 * 
 * Part of ChatAFL-Enhanced: Verified Loop Architecture
 * 
 * Implements the Verification phase:
 *  1. Parseability: Can message be parsed by grammar?
 *  2. Acceptability: Does SUT accept the message?
 *  3. State Reachability: Does message trigger new states?
 *  4. Coverage Gain: Does it improve coverage metrics?
 */

#include "verifier.h"
#include "cfg-parser.h"
#include "alloc-inl.h"
#include "hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_RESPONSE_SIZE (1024 * 1024)  // 1MB max response
#define MAX_FIELDS 256
#define STATE_CACHE_SIZE 4096

// Global state
static state_transition_tree_t *g_stt = NULL;
static FILE *g_verification_log = NULL;
static unsigned int g_state_id_counter = 0;

// Helper: FNV-1a hash for state computation
static unsigned int fnv1a_hash(const unsigned char *data, size_t len) {
    unsigned int hash = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

void verifier_init(verifier_config_t *config) {
    if (config->enable_logging && config->log_file) {
        g_verification_log = fopen(config->log_file, "a");
        if (!g_verification_log) {
            fprintf(stderr, "[VERIFIER] Failed to open log file: %s\n", config->log_file);
        }
    }
    
    g_stt = config->stt;
    if (!g_stt) {
        g_stt = (state_transition_tree_t *)calloc(1, sizeof(state_transition_tree_t));
        g_stt->nodes = (state_node_t *)calloc(STATE_CACHE_SIZE, sizeof(state_node_t));
        g_stt->node_count = 0;
        g_stt->transitions = (state_transition_t *)calloc(STATE_CACHE_SIZE * 4, sizeof(state_transition_t));
        g_stt->transition_count = 0;
        g_stt->current_state = 0;
    }
    
    if (config->enable_logging) {
        fprintf(stderr, "[VERIFIER] Initialized (STT capacity: %d nodes)\n", STATE_CACHE_SIZE);
    }
}

/**
 * Simple regex-based parseability check
 * Matches field patterns against grammar rules
 */
int verify_parseability(
    const unsigned char *message,
    size_t msg_len,
    json_object *grammar,
    parsed_fields_t **fields_out) {
    
    if (!message || msg_len == 0) {
        return 0;
    }
    
    // For v0: Simple line-by-line check
    // Full CFG parsing would be more robust but expensive
    parsed_fields_t *fields = (parsed_fields_t *)calloc(1, sizeof(parsed_fields_t));
    fields->fields = (parsed_field_t *)calloc(MAX_FIELDS, sizeof(parsed_field_t));
    fields->field_count = 0;
    
    // Split by CRLF (common in network protocols)
    const char *line_start = (const char *)message;
    const char *msg_end = (const char *)message + msg_len;
    int line_idx = 0;
    
    while (line_start < msg_end && fields->field_count < MAX_FIELDS) {
        const char *line_end = strchr(line_start, '\r');
        if (!line_end) line_end = strchr(line_start, '\n');
        if (!line_end) line_end = msg_end;
        
        size_t line_len = line_end - line_start;
        
        // Skip empty lines
        if (line_len > 0) {
            parsed_field_t *field = &fields->fields[fields->field_count];
            field->start = line_start - (const char *)message;
            field->len = line_len;
            field->name = (char *)calloc(line_len + 1, 1);
            strncpy(field->name, line_start, line_len);
            field->type = "string";  // v0 assumes all strings
            field->mutable = 1;
            fields->field_count++;
        }
        
        // Move to next line
        line_start = line_end;
        while (line_start < msg_end && (*line_start == '\r' || *line_start == '\n')) {
            line_start++;
        }
    }
    
    if (fields_out) {
        *fields_out = fields;
    }
    
    // v0: Simple heuristic - if has at least 1 field, consider it parseable
    return fields->field_count > 0 ? 1 : 0;
}

/**
 * CFG-based parseability check (FULL IMPLEMENTATION)
 * Uses recursive descent parser with structured grammar
 */
int verify_parseability_with_cfg(
    const unsigned char *message,
    size_t msg_len,
    cfg_grammar_t *grammar,
    parsed_fields_t **fields_out) {
    
    if (!message || msg_len == 0 || !grammar) {
        return 0;
    }
    
    // Attempt to parse message with CFG
    parse_node_t *parse_tree = NULL;
    int parse_result = cfg_parse_message(grammar, message, msg_len, &parse_tree);
    
    if (!parse_result) {
        // Parse failed
        if (g_verification_log) {
            fprintf(g_verification_log, \"[PARSEABILITY] CFG parse FAILED (len=%zu)\\n\", msg_len);
            fflush(g_verification_log);
        }
        return 0;
    }
    
    // Extract fields from parse tree
    if (fields_out && parse_tree) {
        parsed_fields_t *fields = (parsed_fields_t *)calloc(1, sizeof(parsed_fields_t));
        parsed_field_t *field_array = NULL;
        int field_count = 0;
        
        cfg_extract_fields(parse_tree, &field_array, &field_count);
        
        fields->fields = field_array;
        fields->field_count = field_count;
        *fields_out = fields;
    }
    
    // Cleanup
    if (parse_tree) {
        cfg_free_parse_tree(parse_tree);
    }
    
    if (g_verification_log) {
        fprintf(g_verification_log, \"[PARSEABILITY] CFG parse SUCCESS (len=%zu)\\n\", msg_len);
        fflush(g_verification_log);
    }
    
    return 1;
}

// Helper: curl write callback
static size_t write_response_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **response = (char **)userp;
    char *ptr;
    
    if (!*response) {
        ptr = (char *)malloc(realsize + 1);
    } else {
        ptr = (char *)realloc(*response, strlen(*response) + realsize + 1);
    }
    
    if (!ptr) return 0;
    
    *response = ptr;
    memcpy(&((*response)[strlen(*response)]), contents, realsize);
    (*response)[strlen(*response) + realsize] = 0;
    
    return realsize;
}

int verify_acceptability(
    const char *host,
    int port,
    const unsigned char *request,
    size_t req_len,
    response_t *response_out,
    int timeout_ms) {
    
    if (!host || port <= 0 || !request || req_len == 0) {
        return 0;
    }
    
    // Create socket and send request
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[VERIFIER] Socket creation failed\n");
        return 0;
    }
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "[VERIFIER] Invalid IP address\n");
        close(sock);
        return 0;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        // Connection refused = SUT not accepting (fail acceptability)
        close(sock);
        if (response_out) {
            response_out->status_code = RESP_5XX;
            response_out->classification = RESP_5XX;
            response_out->status_message = strdup("Connection refused");
        }
        return 0;
    }
    
    // Send request
    if (send(sock, request, req_len, 0) < 0) {
        fprintf(stderr, "[VERIFIER] Send failed\n");
        close(sock);
        return 0;
    }
    
    // Receive response
    unsigned char response_buf[MAX_RESPONSE_SIZE];
    memset(response_buf, 0, sizeof(response_buf));
    int recv_len = recv(sock, response_buf, sizeof(response_buf) - 1, 0);
    close(sock);
    
    if (recv_len <= 0) {
        if (response_out) {
            response_out->status_code = RESP_5XX;
            response_out->classification = RESP_5XX;
            response_out->status_message = strdup("No response from SUT");
        }
        return 0;
    }
    
    // Parse response (simple HTTP/text protocol)
    if (response_out) {
        response_out->body = (unsigned char *)calloc(recv_len + 1, 1);
        memcpy(response_out->body, response_buf, recv_len);
        response_out->body_len = recv_len;
        
        // Try to extract status code (simplistic)
        // Look for patterns like "200", "400", "500", etc.
        char *status_str = NULL;
        for (int i = 0; i < recv_len - 2; i++) {
            if (isdigit(response_buf[i]) && isdigit(response_buf[i+1]) && 
                isdigit(response_buf[i+2])) {
                int code = atoi((const char *)&response_buf[i]);
                if (code >= 100 && code < 600) {
                    response_out->status_code = code;
                    if (code >= 200 && code < 300) response_out->classification = RESP_2XX;
                    else if (code >= 300 && code < 400) response_out->classification = RESP_3XX;
                    else if (code >= 400 && code < 500) response_out->classification = RESP_4XX;
                    else response_out->classification = RESP_5XX;
                    break;
                }
            }
        }
        
        if (response_out->status_code == 0) {
            response_out->status_code = -1;
            response_out->classification = RESP_UNKNOWN;
        }
        
        response_out->timestamp = time(NULL);
    }
    
    // Accept if status is 2xx or 3xx (non-error)
    return (response_out->classification == RESP_2XX || 
            response_out->classification == RESP_3XX) ? 1 : 0;
}

unsigned int compute_state_id(
    const unsigned int *response_sequence,
    int count,
    const unsigned char *coverage_bitmap,
    int bitmap_size) {
    
    if (!response_sequence || count <= 0) {
        return 0;
    }
    
    // Hash last k response codes + coverage signature
    unsigned int state_hash = fnv1a_hash((unsigned char *)response_sequence, count * sizeof(unsigned int));
    
    if (coverage_bitmap && bitmap_size > 0) {
        // Hash first 256 bytes of coverage bitmap
        int hash_len = (bitmap_size < 256) ? bitmap_size : 256;
        unsigned int cov_hash = fnv1a_hash(coverage_bitmap, hash_len);
        state_hash ^= cov_hash;
    }
    
    return state_hash;
}

int verify_state_reachability(
    const unsigned int *state_sequence,
    int state_count,
    state_transition_tree_t *stt,
    int *is_new_state_out) {
    
    if (!state_sequence || state_count <= 0 || !stt) {
        if (is_new_state_out) *is_new_state_out = 0;
        return 0;
    }
    
    unsigned int state_id = compute_state_id(state_sequence, state_count, NULL, 0);
    
    // Check if state already in STT
    for (int i = 0; i < stt->node_count; i++) {
        if (stt->nodes[i].state_id == state_id) {
            stt->nodes[i].visitation_count++;
            stt->nodes[i].last_visited = time(NULL);
            if (is_new_state_out) *is_new_state_out = 0;
            return 1;
        }
    }
    
    // New state discovered
    if (stt->node_count < STATE_CACHE_SIZE) {
        state_node_t *node = &stt->nodes[stt->node_count];
        node->state_id = state_id;
        node->visitation_count = 1;
        node->is_new = 1;
        node->coverage = 0.0f;
        node->last_visited = time(NULL);
        stt->node_count++;
        
        if (is_new_state_out) *is_new_state_out = 1;
        return 1;
    }
    
    if (is_new_state_out) *is_new_state_out = 0;
    return 0;
}

float calculate_coverage_gain(
    const state_transition_tree_t *stt,
    const response_t *response) {
    
    if (!stt || !response) return 0.0f;
    
    // v0 simple: coverage gain = 1.0 if response indicates new state
    // In practice, would integrate with AFL's coverage bitmap
    float gain = 0.0f;
    
    // Heuristic: 2xx responses often indicate progress
    if (response->classification == RESP_2XX) {
        gain = 1.0f;
    }
    
    return gain;
}

/**
 * Calculate coverage gain from AFL bitmap (MODULARIZED VERSION)
 * 
 * @param bitmap AFL coverage bitmap (trace_bits)
 * @param bitmap_size Size of bitmap (MAP_SIZE)
 * @param previous_total Previous total edge count
 * @param current_total Current total edge count
 * @param stt State transition tree (for state-aware coverage)
 * @return Coverage gain as percentage (0.0 to 1.0)
 */
float calculate_coverage_gain_from_bitmap(
    const unsigned char *bitmap,
    size_t bitmap_size,
    u32 previous_total,
    u32 current_total,
    const state_transition_tree_t *stt) {
    
    if (!bitmap || bitmap_size == 0) return 0.0f;
    
    // Basic coverage gain: new edges / total possible edges
    float basic_gain = (float)(current_total - previous_total) / (float)bitmap_size;
    
    // State-aware adjustment: if discovered new state, boost gain
    float state_bonus = 0.0f;
    if (stt) {
        for (int i = 0; i < stt->node_count; i++) {
            if (stt->nodes[i].is_new) {
                state_bonus += 0.05f;  // +5% per new state
            }
        }
    }
    
    // Combined gain with cap at 1.0
    float total_gain = basic_gain + state_bonus;
    if (total_gain > 1.0f) total_gain = 1.0f;
    if (total_gain < 0.0f) total_gain = 0.0f;
    
    return total_gain;
}

void update_state_transition_tree(
    state_transition_tree_t *stt,
    const unsigned int *response_codes,
    int response_count,
    const char *triggering_message_type) {
    
    if (!stt || !response_codes || response_count <= 0) {
        return;
    }
    
    // Update or create state nodes
    for (int i = 0; i < response_count; i++) {
        unsigned int response_code = response_codes[i];
        
        // Find or create state node
        int found = 0;
        for (int j = 0; j < stt->node_count; j++) {
            if (stt->nodes[j].state_id == response_code) {
                stt->nodes[j].visitation_count++;
                found = 1;
                break;
            }
        }
        
        if (!found && stt->node_count < STATE_CACHE_SIZE) {
            state_node_t *node = &stt->nodes[stt->node_count];
            node->state_id = response_code;
            node->visitation_count = 1;
            node->is_new = 1;
            node->coverage = 0.0f;
            node->last_visited = time(NULL);
            stt->node_count++;
        }
    }
    
    // Record state transitions
    for (int i = 0; i < response_count - 1; i++) {
        unsigned int from_state = response_codes[i];
        unsigned int to_state = response_codes[i + 1];
        
        int found = 0;
        for (int j = 0; j < stt->transition_count; j++) {
            if (stt->transitions[j].from_state == from_state && 
                stt->transitions[j].to_state == to_state) {
                stt->transitions[j].transition_count++;
                found = 1;
                break;
            }
        }
        
        if (!found && stt->transition_count < STATE_CACHE_SIZE * 4) {
            state_transition_t *trans = &stt->transitions[stt->transition_count];
            trans->from_state = from_state;
            trans->to_state = to_state;
            if (triggering_message_type) {
                trans->message_type = strdup(triggering_message_type);
            } else {
                trans->message_type = strdup("unknown");
            }
            trans->transition_count = 1;
            trans->coverage_gain = 0;
            stt->transition_count++;
        }
    }
}

unsigned char *minimize_counterexample(
    const unsigned char *message,
    size_t msg_len,
    json_object *grammar,
    size_t *minimized_len_out) {
    
    if (!message || msg_len == 0) {
        if (minimized_len_out) *minimized_len_out = 0;
        return NULL;
    }
    
    // Allocate working buffer
    unsigned char *current = (unsigned char *)calloc(msg_len, 1);
    memcpy(current, message, msg_len);
    size_t current_len = msg_len;
    
    // Delta-debugging: start with coarse granularity, refine to 1-byte
    int granularity = 8;  // Start with 8 chunks
    int improvements = 1;
    
    if (g_verification_log) {
        fprintf(g_verification_log, "[DELTA-DEBUG] Starting minimization (len=%zu)\n", msg_len);
        fflush(g_verification_log);
    }
    
    while (granularity > 0 && improvements > 0) {
        improvements = 0;
        size_t chunk_size = (current_len + granularity - 1) / granularity;
        if (chunk_size == 0) chunk_size = 1;
        
        // Try removing each chunk
        for (int chunk_idx = 0; chunk_idx < granularity; chunk_idx++) {
            size_t remove_start = chunk_idx * chunk_size;
            if (remove_start >= current_len) break;
            
            size_t remove_end = remove_start + chunk_size;
            if (remove_end > current_len) remove_end = current_len;
            
            // Create candidate with chunk removed
            size_t candidate_len = current_len - (remove_end - remove_start);
            if (candidate_len == 0) continue;  // Don't remove everything
            
            unsigned char *candidate = (unsigned char *)calloc(candidate_len, 1);
            memcpy(candidate, current, remove_start);
            memcpy(candidate + remove_start, current + remove_end, 
                   current_len - remove_end);
            
            // Test if candidate still triggers failure
            // For now, use parseability as proxy (fails if unparseable)
            parsed_fields_t *test_fields = NULL;
            int still_parseable = verify_parseability(candidate, candidate_len, 
                                                      grammar, &test_fields);
            
            if (test_fields) {
                for (int i = 0; i < test_fields->field_count; i++) {
                    if (test_fields->fields[i].name) free(test_fields->fields[i].name);
                    if (test_fields->fields[i].type) free(test_fields->fields[i].type);
                }
                free(test_fields->fields);
                free(test_fields);
            }
            
            // If still behaves same (parseable or not), keep reduction
            if (still_parseable == 0) {  // Still fails → good candidate
                free(current);
                current = candidate;
                current_len = candidate_len;
                improvements++;
                
                if (g_verification_log) {
                    fprintf(g_verification_log, 
                            "[DELTA-DEBUG] Reduced to %zu bytes (chunk %d/%d)\n",
                            current_len, chunk_idx, granularity);
                    fflush(g_verification_log);
                }
                break;  // Restart with new current
            } else {
                free(candidate);
            }
        }
        
        // Increase granularity (smaller chunks) if no improvements
        if (improvements == 0) {
            granularity *= 2;
            if (granularity > (int)current_len) break;
        }
    }
    
    if (minimized_len_out) *minimized_len_out = current_len;
    
    if (g_verification_log) {
        fprintf(g_verification_log, 
                "[DELTA-DEBUG] Final size: %zu bytes (%.1f%% of original)\n",
                current_len, 100.0 * current_len / msg_len);
        fflush(g_verification_log);
    }
    
    return current;
}

void log_verification_result(
    const char *message_hex,
    int parseability,
    int acceptability,
    int state_reachability,
    const response_t *response) {
    
    if (!g_verification_log) return;
    
    fprintf(g_verification_log, 
            "[VERIFY] msg=%s parse=%d accept=%d state=%d status=%d\n",
            message_hex ? message_hex : "?",
            parseability, acceptability, state_reachability,
            response ? response->status_code : -1);
    fflush(g_verification_log);
}

void verifier_cleanup(void) {
    if (g_verification_log) {
        fclose(g_verification_log);
        g_verification_log = NULL;
    }
    
    if (g_stt) {
        for (int i = 0; i < g_stt->transition_count; i++) {
            if (g_stt->transitions[i].message_type) {
                free(g_stt->transitions[i].message_type);
            }
        }
        if (g_stt->transitions) free(g_stt->transitions);
        if (g_stt->nodes) free(g_stt->nodes);
        free(g_stt);
        g_stt = NULL;
    }
}
