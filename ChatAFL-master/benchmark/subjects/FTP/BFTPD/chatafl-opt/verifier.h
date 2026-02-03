#ifndef __VERIFIER_H
#define __VERIFIER_H

#include "hypothesis.h"
#include "klist.h"
#include "kvec.h"
#include <stdint.h>
#include <stdbool.h>

/* Verifier Module
 * Validates grammar hypotheses through multiple criteria:
 * 1. Parseability - can local parser parse it?
 * 2. Acceptability - does SUT accept it (non-error response)?
 * 3. State Reachability - does it trigger new states/transitions?
 * 4. Coverage Gain - does it increase coverage?
 */

// Verification result
typedef enum {
    VERIFY_SUCCESS = 0,
    VERIFY_PARSE_FAILED = 1,
    VERIFY_ACCEPT_FAILED = 2,
    VERIFY_STATE_FAILED = 3,
    VERIFY_COVERAGE_FAILED = 4
} verify_status_t;

typedef struct {
    verify_status_t status;
    char *failure_reason;         // Detailed error message
    char *minimal_counterexample; // Delta-debugged minimal failing input
    char *server_response;        // SUT response (for acceptability check)
    int response_code;            // Parsed response code (e.g., FTP 500, HTTP 400)
    uint64_t coverage_bitmap[65536]; // Coverage bitmap snapshot
    int new_states_count;         // Number of new states discovered
    char **new_states;            // List of new state names
    double verification_time;     // Time spent verifying (seconds)
} verification_result_t;

// Verification context
typedef struct {
    char *protocol_name;
    int sut_socket;               // Socket to SUT (system under test)
    char *sut_host;
    int sut_port;
    uint64_t *baseline_coverage;  // Baseline coverage bitmap
    khash_t(strSet) *known_states; // Set of known states
    khash_t(strMap) *state_transition_count; // State transition frequency
} verification_context_t;

// Initialize verification context
verification_context_t *init_verification_context(const char *protocol_name,
                                                  const char *sut_host,
                                                  int sut_port);

// Verify a generated message against all criteria
verification_result_t *verify_message(verification_context_t *ctx,
                                      grammar_hypothesis_t *hypothesis,
                                      const char *generated_message,
                                      uint64_t *current_coverage);

// Individual verification checks
bool verify_parseability(const char *message, 
                        grammar_hypothesis_t *hypothesis,
                        char **failure_reason);

bool verify_acceptability(verification_context_t *ctx,
                         const char *message,
                         char **server_response,
                         int *response_code,
                         char **failure_reason);

bool verify_state_reachability(verification_context_t *ctx,
                              const char *message,
                              const char *server_response,
                              char ***new_states,
                              int *new_states_count);

bool verify_coverage_gain(verification_context_t *ctx,
                         uint64_t *current_coverage,
                         uint64_t *new_coverage,
                         double *gain_percentage);

// Delta debugging for minimal counterexample
char *minimize_counterexample(verification_context_t *ctx,
                             grammar_hypothesis_t *hypothesis,
                             const char *failing_message,
                             verify_status_t failure_type);

// Field-level minimization
char *minimize_by_field(verification_context_t *ctx,
                       grammar_hypothesis_t *hypothesis,
                       const char *failing_message,
                       field_constraint_t **fields,
                       int field_count);

// State extraction from server response
char *extract_state_from_response(const char *response, 
                                 const char *protocol_name);

// Response code parser
int parse_response_code(const char *response, const char *protocol_name);

// Free functions
void free_verification_result(verification_result_t *result);
void free_verification_context(verification_context_t *ctx);

// Cache management for verification results
typedef struct {
    char *message_hash;           // Hash of message
    verification_result_t *result;
    time_t cached_at;
} verification_cache_entry_t;

KHASH_MAP_INIT_STR(verify_cache, verification_cache_entry_t *)

verification_result_t *lookup_verification_cache(khash_t(verify_cache) *cache,
                                                const char *message);
void update_verification_cache(khash_t(verify_cache) *cache,
                              const char *message,
                              verification_result_t *result);

#endif /* __VERIFIER_H */
