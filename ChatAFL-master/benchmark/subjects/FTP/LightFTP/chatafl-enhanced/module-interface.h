/*
 * module-interface.h - Decoupled Module Interfaces
 * 
 * Defines event-driven interfaces between Verifier, CEGAR, and Scheduler
 * to eliminate global variable dependencies and tight coupling
 * 
 * Design pattern: Observer/Publisher-Subscriber
 */

#ifndef __MODULE_INTERFACE_H
#define __MODULE_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>
#include "verifier.h"
#include "cegar-refinement.h"
#include "state-scheduler.h"

/* ============ Event Types ============ */

typedef enum {
    EVENT_VERIFICATION_COMPLETE,    // Verifier finished 4D check
    EVENT_CEGAR_PATCH_APPLIED,      // CEGAR successfully patched message
    EVENT_NEW_STATE_DISCOVERED,     // New state found in STT
    EVENT_COVERAGE_PLATEAU,         // Coverage stalled
    EVENT_RARE_TRANSITION_FOUND     // Rare state transition detected
} module_event_type_t;

/* ============ Event Data Structures ============ */

typedef struct {
    uint32_t state_id;
    int visitation_count;
    float coverage;
    bool is_new;
} state_event_data_t;

typedef struct {
    uint32_t from_state;
    uint32_t to_state;
    int frequency;
    float coverage_delta;
} transition_event_data_t;

typedef struct {
    int parseability;
    int acceptability;
    int state_reachability;
    float coverage_gain;
    response_t response;
    uint32_t current_state_id;
    parsed_fields_t *parsed_fields;
} verification_event_data_t;

typedef struct {
    cegar_patch_t *patch;
    unsigned char *patched_message;
    size_t patched_len;
    int success;
    char *patch_description;
} cegar_event_data_t;

typedef struct {
    float current_coverage;
    float previous_coverage;
    int plateau_counter;
    uint32_t suggested_target_state;
} plateau_event_data_t;

typedef struct {
    module_event_type_t type;
    uint64_t timestamp;
    
    union {
        verification_event_data_t verification;
        cegar_event_data_t cegar;
        state_event_data_t state;
        transition_event_data_t transition;
        plateau_event_data_t plateau;
    } data;
} module_event_t;

/* ============ Event Callback System ============ */

typedef void (*module_event_callback_t)(module_event_t *event, void *user_data);

typedef struct event_subscriber {
    module_event_type_t event_type;
    module_event_callback_t callback;
    void *user_data;
    struct event_subscriber *next;
} event_subscriber_t;

typedef struct {
    event_subscriber_t *subscribers;
    int subscriber_count;
} event_bus_t;

/* ============ Event Bus API ============ */

/**
 * @brief Initialize global event bus
 */
event_bus_t *event_bus_create(void);

/**
 * @brief Subscribe to event type
 * 
 * @param bus Event bus
 * @param event_type Type of event to listen for
 * @param callback Function to call when event occurs
 * @param user_data User context passed to callback
 */
void event_bus_subscribe(
    event_bus_t *bus,
    module_event_type_t event_type,
    module_event_callback_t callback,
    void *user_data
);

/**
 * @brief Publish event to all subscribers
 * 
 * @param bus Event bus
 * @param event Event to publish
 */
void event_bus_publish(
    event_bus_t *bus,
    module_event_t *event
);

/**
 * @brief Cleanup event bus
 */
void event_bus_destroy(event_bus_t *bus);

/* ============ Module Context Structures (Decoupled) ============ */

/**
 * Verifier Context - No dependencies on global state
 */
typedef struct {
    event_bus_t *event_bus;
    state_transition_tree_t *local_stt;  // Own copy of STT
    cfg_grammar_t **grammars;
    int grammar_count;
    verifier_config_t config;
} verifier_module_ctx_t;

/**
 * CEGAR Context - No dependencies on global state
 */
typedef struct {
    event_bus_t *event_bus;
    char *cache_dir;
    cegar_failure_t *failure_cache;
    int failure_cache_size;
    cegar_patch_t *patch_cache;
    int patch_cache_size;
} cegar_module_ctx_t;

/**
 * Scheduler Context - No dependencies on global state
 */
typedef struct {
    event_bus_t *event_bus;
    state_transition_tree_t *local_stt;  // Own copy of STT
    state_stats_t *state_stats;
    rare_transition_t *rare_transitions;
    int plateau_threshold;
    float last_coverage;
} scheduler_module_ctx_t;

/* ============ Module Interface Functions ============ */

/**
 * @brief Initialize verifier module with decoupled context
 */
verifier_module_ctx_t *verifier_module_create(
    event_bus_t *event_bus,
    verifier_config_t *config
);

/**
 * @brief Run verification and publish results as event
 */
void verifier_module_verify(
    verifier_module_ctx_t *ctx,
    const unsigned char *message,
    size_t msg_len,
    const unsigned int *state_sequence,
    int state_count
);

/**
 * @brief Initialize CEGAR module with decoupled context
 */
cegar_module_ctx_t *cegar_module_create(
    event_bus_t *event_bus,
    const char *cache_dir
);

/**
 * @brief Handle verification failure event (called via event bus)
 */
void cegar_module_on_verification_failure(
    module_event_t *event,
    void *user_data  // cegar_module_ctx_t*
);

/**
 * @brief Initialize scheduler module with decoupled context
 */
scheduler_module_ctx_t *scheduler_module_create(
    event_bus_t *event_bus,
    int plateau_threshold
);

/**
 * @brief Handle new state event (called via event bus)
 */
void scheduler_module_on_new_state(
    module_event_t *event,
    void *user_data  // scheduler_module_ctx_t*
);

/**
 * @brief Select next seed based on state rarity
 */
struct queue_entry *scheduler_module_select_seed(
    scheduler_module_ctx_t *ctx,
    struct queue_entry *queue_head
);

/* ============ Utility: STT Synchronization ============ */

/**
 * @brief Sync STT between modules without global state
 * 
 * Each module has local copy of STT; this merges updates
 */
void stt_sync_from_event(
    state_transition_tree_t *local_stt,
    const module_event_t *event
);

#endif /* __MODULE_INTERFACE_H */
