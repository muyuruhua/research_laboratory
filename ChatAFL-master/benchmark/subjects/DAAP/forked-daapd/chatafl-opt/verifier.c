#define _GNU_SOURCE
#include "verifier.h"
#include "alloc-inl.h"
#include "hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <pcre2.h>

/* Verifier Implementation */

verification_context_t *init_verification_context(const char *protocol_name,
                                                  const char *sut_host,
                                                  int sut_port) {
    verification_context_t *ctx = (verification_context_t *)ck_alloc(sizeof(verification_context_t));
    ctx->protocol_name = strdup(protocol_name);
    ctx->sut_host = strdup(sut_host);
    ctx->sut_port = sut_port;
    ctx->sut_socket = -1;
    ctx->baseline_coverage = (uint64_t *)ck_alloc(sizeof(uint64_t) * 65536);
    memset(ctx->baseline_coverage, 0, sizeof(uint64_t) * 65536);
    ctx->known_states = kh_init(strSet);
    ctx->state_transition_count = kh_init(strMap);
    return ctx;
}

bool verify_parseability(const char *message,
                        grammar_hypothesis_t *hypothesis,
                        char **failure_reason) {
    if (!message || !hypothesis) {
        if (failure_reason) *failure_reason = strdup("NULL input");
        return false;
    }
    
    // Parse grammar spec to extract patterns
    json_object *fields = hypothesis->field_constraints;
    if (!fields || !json_object_is_type(fields, json_type_array)) {
        // No field constraints means we accept anything (fallback)
        return true;
    }
    
    int field_count = json_object_array_length(fields);
    bool all_fields_valid = true;
    char error_buf[512] = {0};
    
    for (int i = 0; i < field_count; i++) {
        json_object *field = json_object_array_get_idx(fields, i);
        json_object *name_obj, *pattern_obj;
        
        if (!json_object_object_get_ex(field, "name", &name_obj)) continue;
        if (!json_object_object_get_ex(field, "pattern", &pattern_obj)) continue;
        
        const char *field_name = json_object_get_string(name_obj);
        const char *pattern = json_object_get_string(pattern_obj);
        
        // Compile regex pattern
        int errornumber;
        PCRE2_SIZE erroroffset;
        pcre2_code *re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                                       0, &errornumber, &erroroffset, NULL);
        
        if (!re) {
            snprintf(error_buf, sizeof(error_buf), "Invalid pattern for field '%s'", field_name);
            all_fields_valid = false;
            break;
        }
        
        // Try to match pattern against message
        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
        int rc = pcre2_match(re, (PCRE2_SPTR)message, strlen(message), 0, 0, match_data, NULL);
        
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        
        if (rc < 0) {
            snprintf(error_buf, sizeof(error_buf), "Field '%s' failed pattern match", field_name);
            all_fields_valid = false;
            break;
        }
    }
    
    if (!all_fields_valid && failure_reason) {
        *failure_reason = strdup(error_buf);
    }
    
    return all_fields_valid;
}

bool verify_acceptability(verification_context_t *ctx,
                         const char *message,
                         char **server_response,
                         int *response_code,
                         char **failure_reason) {
    if (!ctx || !message) {
        if (failure_reason) *failure_reason = strdup("Invalid context or message");
        return false;
    }
    
    // Connect to SUT (simplified - real impl would handle connection pooling)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        if (failure_reason) *failure_reason = strdup("Socket creation failed");
        return false;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ctx->sut_port);
    inet_pton(AF_INET, ctx->sut_host, &server_addr.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        if (failure_reason) *failure_reason = strdup("Connection failed");
        return false;
    }
    
    // Send message
    ssize_t sent = send(sock, message, strlen(message), 0);
    if (sent < 0) {
        close(sock);
        if (failure_reason) *failure_reason = strdup("Send failed");
        return false;
    }
    
    // Receive response
    char buffer[4096] = {0};
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);
    
    if (received <= 0) {
        if (failure_reason) *failure_reason = strdup("No response from server");
        return false;
    }
    
    if (server_response) {
        *server_response = strndup(buffer, received);
    }
    
    // Parse response code
    int code = parse_response_code(buffer, ctx->protocol_name);
    if (response_code) *response_code = code;
    
    // Check for error codes
    if (code >= 400 && code < 600) { // Generic error range
        if (failure_reason) {
            char *reason = NULL;
            asprintf(&reason, "Server returned error code %d", code);
            *failure_reason = reason;
        }
        return false;
    }
    
    return true;
}

int parse_response_code(const char *response, const char *protocol_name) {
    if (!response) return -1;
    
    // Protocol-specific parsing
    if (strcasecmp(protocol_name, "FTP") == 0 || strcasecmp(protocol_name, "SMTP") == 0) {
        // FTP/SMTP: first 3 digits are the code
        int code = 0;
        if (sscanf(response, "%3d", &code) == 1) {
            return code;
        }
    } else if (strcasecmp(protocol_name, "HTTP") == 0) {
        // HTTP: "HTTP/1.x CODE"
        int code = 0;
        if (sscanf(response, "HTTP/%*s %d", &code) == 1) {
            return code;
        }
    }
    
    return -1;
}

bool verify_state_reachability(verification_context_t *ctx,
                              const char *message,
                              const char *server_response,
                              char ***new_states,
                              int *new_states_count) {
    if (!ctx || !server_response) return false;
    
    char *state = extract_state_from_response(server_response, ctx->protocol_name);
    if (!state) return false;
    
    int ret;
    khiter_t k = kh_put(strSet, ctx->known_states, state, &ret);
    
    if (ret > 0) { // New state discovered
        if (new_states && new_states_count) {
            *new_states = (char **)ck_alloc(sizeof(char *));
            (*new_states)[0] = strdup(state);
            *new_states_count = 1;
        }
        free(state);
        return true;
    }
    
    free(state);
    return false;
}

char *extract_state_from_response(const char *response, const char *protocol_name) {
    if (!response) return NULL;
    
    int code = parse_response_code(response, protocol_name);
    if (code < 0) return strdup("UNKNOWN");
    
    // Map response code to state (protocol-specific)
    char *state = NULL;
    if (strcasecmp(protocol_name, "FTP") == 0) {
        if (code == 220) state = strdup("CONNECTED");
        else if (code == 331) state = strdup("USER_OK");
        else if (code == 230) state = strdup("LOGGED_IN");
        else if (code == 250) state = strdup("COMMAND_OK");
        else if (code >= 500) state = strdup("ERROR");
        else asprintf(&state, "STATE_%d", code);
    } else {
        asprintf(&state, "STATE_%d", code);
    }
    
    return state;
}

bool verify_coverage_gain(verification_context_t *ctx,
                         uint64_t *current_coverage,
                         uint64_t *new_coverage,
                         double *gain_percentage) {
    if (!ctx || !current_coverage || !new_coverage) return false;
    
    uint64_t current_bits = 0, new_bits = 0, gained_bits = 0;
    
    for (int i = 0; i < 65536; i++) {
        current_bits += __builtin_popcountll(current_coverage[i]);
        new_bits += __builtin_popcountll(new_coverage[i]);
        gained_bits += __builtin_popcountll(new_coverage[i] & ~current_coverage[i]);
    }
    
    if (gain_percentage && current_bits > 0) {
        *gain_percentage = (double)gained_bits / (double)current_bits * 100.0;
    }
    
    return gained_bits > 0;
}

verification_result_t *verify_message(verification_context_t *ctx,
                                      grammar_hypothesis_t *hypothesis,
                                      const char *generated_message,
                                      uint64_t *current_coverage) {
    verification_result_t *result = (verification_result_t *)ck_alloc(sizeof(verification_result_t));
    memset(result, 0, sizeof(verification_result_t));
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Step 1: Parseability
    if (!verify_parseability(generated_message, hypothesis, &result->failure_reason)) {
        result->status = VERIFY_PARSE_FAILED;
        goto cleanup;
    }
    
    // Step 2: Acceptability
    if (!verify_acceptability(ctx, generated_message, &result->server_response,
                             &result->response_code, &result->failure_reason)) {
        result->status = VERIFY_ACCEPT_FAILED;
        result->minimal_counterexample = minimize_counterexample(ctx, hypothesis,
                                                                generated_message,
                                                                VERIFY_ACCEPT_FAILED);
        goto cleanup;
    }
    
    // Step 3: State Reachability
    if (!verify_state_reachability(ctx, generated_message, result->server_response,
                                  &result->new_states, &result->new_states_count)) {
        result->status = VERIFY_STATE_FAILED;
        goto cleanup;
    }
    
    // Step 4: Coverage Gain (would integrate with AFL coverage)
    // Stub: in real implementation, would capture coverage from AFL execution
    uint64_t dummy_coverage[65536] = {0};
    double gain = 0.0;
    if (!verify_coverage_gain(ctx, current_coverage, dummy_coverage, &gain)) {
        result->status = VERIFY_COVERAGE_FAILED;
        goto cleanup;
    }
    
    result->status = VERIFY_SUCCESS;
    
cleanup:
    gettimeofday(&end, NULL);
    result->verification_time = (end.tv_sec - start.tv_sec) +
                               (end.tv_usec - start.tv_usec) / 1000000.0;
    return result;
}

char *minimize_counterexample(verification_context_t *ctx,
                             grammar_hypothesis_t *hypothesis,
                             const char *failing_message,
                             verify_status_t failure_type) {
    // Delta debugging: iteratively remove parts and check if still fails
    size_t len = strlen(failing_message);
    if (len <= 1) return strdup(failing_message);
    
    // Binary search for minimal substring
    size_t left = 0, right = len;
    char *minimal = strdup(failing_message);
    
    while (left < right) {
        size_t mid = (left + right) / 2;
        char *candidate = strndup(failing_message, mid);
        
        verification_result_t *test = verify_message(ctx, hypothesis, candidate, NULL);
        
        if (test->status == failure_type) {
            // Still fails with shorter input
            free(minimal);
            minimal = candidate;
            right = mid;
        } else {
            free(candidate);
            left = mid + 1;
        }
        
        free_verification_result(test);
    }
    
    return minimal;
}

char *minimize_by_field(verification_context_t *ctx,
                       grammar_hypothesis_t *hypothesis,
                       const char *failing_message,
                       field_constraint_t **fields,
                       int field_count) {
    // Field-level minimization (stub)
    return strdup(failing_message);
}

void free_verification_result(verification_result_t *result) {
    if (!result) return;
    if (result->failure_reason) free(result->failure_reason);
    if (result->minimal_counterexample) free(result->minimal_counterexample);
    if (result->server_response) free(result->server_response);
    if (result->new_states) {
        for (int i = 0; i < result->new_states_count; i++) {
            free(result->new_states[i]);
        }
        free(result->new_states);
    }
    ck_free(result);
}

void free_verification_context(verification_context_t *ctx) {
    if (!ctx) return;
    if (ctx->protocol_name) free(ctx->protocol_name);
    if (ctx->sut_host) free(ctx->sut_host);
    if (ctx->baseline_coverage) ck_free(ctx->baseline_coverage);
    kh_destroy(strSet, ctx->known_states);
    kh_destroy(strMap, ctx->state_transition_count);
    ck_free(ctx);
}

verification_result_t *lookup_verification_cache(khash_t(verify_cache) *cache,
                                                const char *message) {
    if (!cache || !message) return NULL;
    
    char hash_str[16];
    snprintf(hash_str, sizeof(hash_str), "%08x", hash32((u8 *)message, strlen(message), 0));
    
    khiter_t k = kh_get(verify_cache, cache, hash_str);
    if (k != kh_end(cache)) {
        return kh_value(cache, k)->result;
    }
    return NULL;
}

void update_verification_cache(khash_t(verify_cache) *cache,
                              const char *message,
                              verification_result_t *result) {
    if (!cache || !message || !result) return;
    
    char hash_str[16];
    snprintf(hash_str, sizeof(hash_str), "%08x", hash32((u8 *)message, strlen(message), 0));
    
    verification_cache_entry_t *entry = (verification_cache_entry_t *)ck_alloc(sizeof(verification_cache_entry_t));
    entry->message_hash = strdup(hash_str);
    entry->result = result;
    entry->cached_at = time(NULL);
    
    int ret;
    khiter_t k = kh_put(verify_cache, cache, entry->message_hash, &ret);
    kh_value(cache, k) = entry;
}
