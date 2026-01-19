/*
 * module-interface.c - Event-Driven Module Communication
 * 
 * Implements decoupled interfaces to eliminate global variable dependencies
 */

#include "module-interface.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============ Event Bus Implementation ============ */

event_bus_t *event_bus_create(void) {
    event_bus_t *bus = (event_bus_t *)ck_alloc(sizeof(event_bus_t));
    bus->subscribers = NULL;
    bus->subscriber_count = 0;
    return bus;
}

void event_bus_subscribe(
    event_bus_t *bus,
    module_event_type_t event_type,
    module_event_callback_t callback,
    void *user_data) {
    
    if (!bus || !callback) return;
    
    event_subscriber_t *sub = (event_subscriber_t *)ck_alloc(sizeof(event_subscriber_t));
    sub->event_type = event_type;
    sub->callback = callback;
    sub->user_data = user_data;
    sub->next = bus->subscribers;
    
    bus->subscribers = sub;
    bus->subscriber_count++;
}

void event_bus_publish(
    event_bus_t *bus,
    module_event_t *event) {
    
    if (!bus || !event) return;
    
    event->timestamp = (uint64_t)time(NULL) * 1000;  // Milliseconds
    
    event_subscriber_t *sub = bus->subscribers;
    while (sub) {
        if (sub->event_type == event->type) {
            sub->callback(event, sub->user_data);
        }
        sub = sub->next;
    }
}

void event_bus_destroy(event_bus_t *bus) {
    if (!bus) return;
    
    event_subscriber_t *sub = bus->subscribers;
    while (sub) {
        event_subscriber_t *next = sub->next;
        ck_free(sub);
        sub = next;
    }
    
    ck_free(bus);
}

/* ============ Verifier Module Implementation ============ */

verifier_module_ctx_t *verifier_module_create(
    event_bus_t *event_bus,
    verifier_config_t *config) {
    
    verifier_module_ctx_t *ctx = (verifier_module_ctx_t *)ck_alloc(sizeof(verifier_module_ctx_t));
    ctx->event_bus = event_bus;
    
    // Create local STT (no global dependency)
    ctx->local_stt = (state_transition_tree_t *)calloc(1, sizeof(state_transition_tree_t));
    ctx->local_stt->nodes = (state_node_t *)calloc(STATE_CACHE_SIZE, sizeof(state_node_t));
    ctx->local_stt->transitions = (state_transition_t *)calloc(STATE_CACHE_SIZE * 4, sizeof(state_transition_t));
    
    if (config) {
        memcpy(&ctx->config, config, sizeof(verifier_config_t));
    }
    
    ctx->grammars = NULL;
    ctx->grammar_count = 0;
    
    return ctx;
}

void verifier_module_verify(
    verifier_module_ctx_t *ctx,
    const unsigned char *message,
    size_t msg_len,
    const unsigned int *state_sequence,
    int state_count) {
    
    if (!ctx || !message) return;
    
    // Run 4D verification
    parsed_fields_t *parsed_fields = NULL;
    int parseability = 0;
    
    if (ctx->grammar_count > 0 && ctx->grammars[0]) {
        parseability = verify_parseability_with_cfg(message, msg_len,
                                                     ctx->grammars[0], &parsed_fields);
    } else {
        parseability = verify_parseability(message, msg_len, NULL, &parsed_fields);
    }
    
    // Acceptability check
    int acceptability = 1;
    response_t response = {0};
    for (int i = 0; i < state_count; i++) {
        if (state_sequence[i] >= 400 && state_sequence[i] < 600) {
            acceptability = 0;
            response.status_code = state_sequence[i];
            response.classification = (state_sequence[i] >= 500) ? RESP_5XX : RESP_4XX;
            break;
        }
    }
    
    // State reachability
    int new_state_discovered = 0;
    uint32_t current_state_id = 0;
    if (state_count >= 2) {
        verify_state_reachability(state_sequence, state_count, 
                                  ctx->local_stt, &new_state_discovered);
        current_state_id = state_sequence[state_count - 1];
    }
    
    // Coverage gain (placeholder)
    float coverage_gain = new_state_discovered ? 0.1f : 0.0f;
    
    // Publish verification complete event
    module_event_t event = {0};
    event.type = EVENT_VERIFICATION_COMPLETE;
    event.data.verification.parseability = parseability;
    event.data.verification.acceptability = acceptability;
    event.data.verification.state_reachability = new_state_discovered;
    event.data.verification.coverage_gain = coverage_gain;
    event.data.verification.response = response;
    event.data.verification.current_state_id = current_state_id;
    event.data.verification.parsed_fields = parsed_fields;
    
    event_bus_publish(ctx->event_bus, &event);
    
    // Publish new state event if discovered
    if (new_state_discovered) {
        module_event_t state_event = {0};
        state_event.type = EVENT_NEW_STATE_DISCOVERED;
        state_event.data.state.state_id = current_state_id;
        state_event.data.state.is_new = true;
        state_event.data.state.coverage = coverage_gain;
        
        event_bus_publish(ctx->event_bus, &state_event);
    }
}

/* ============ CEGAR Module Implementation ============ */

cegar_module_ctx_t *cegar_module_create(
    event_bus_t *event_bus,
    const char *cache_dir) {
    
    cegar_module_ctx_t *ctx = (cegar_module_ctx_t *)ck_alloc(sizeof(cegar_module_ctx_t));
    ctx->event_bus = event_bus;
    ctx->cache_dir = cache_dir ? ck_strdup(cache_dir) : ck_strdup(".cegar_cache");
    
    ctx->failure_cache = (cegar_failure_t *)calloc(256, sizeof(cegar_failure_t));
    ctx->failure_cache_size = 0;
    ctx->patch_cache = (cegar_patch_t *)calloc(256, sizeof(cegar_patch_t));
    ctx->patch_cache_size = 0;
    
    // Subscribe to verification failure events
    event_bus_subscribe(event_bus, EVENT_VERIFICATION_COMPLETE,
                       cegar_module_on_verification_failure, ctx);
    
    return ctx;
}

void cegar_module_on_verification_failure(
    module_event_t *event,
    void *user_data) {
    
    cegar_module_ctx_t *ctx = (cegar_module_ctx_t *)user_data;
    if (!ctx || !event) return;
    
    // Only process if verification failed
    if (event->data.verification.acceptability == 1) return;
    
    // TODO: Trigger CEGAR refinement
    // For now, just log
    fprintf(stderr, "[CEGAR] Received verification failure event (state=%u)\n",
            event->data.verification.current_state_id);
    
    // Publish CEGAR patch applied event (placeholder)
    module_event_t patch_event = {0};
    patch_event.type = EVENT_CEGAR_PATCH_APPLIED;
    patch_event.data.cegar.success = 0;
    
    event_bus_publish(ctx->event_bus, &patch_event);
}

/* ============ Scheduler Module Implementation ============ */

scheduler_module_ctx_t *scheduler_module_create(
    event_bus_t *event_bus,
    int plateau_threshold) {
    
    scheduler_module_ctx_t *ctx = (scheduler_module_ctx_t *)ck_alloc(sizeof(scheduler_module_ctx_t));
    ctx->event_bus = event_bus;
    ctx->plateau_threshold = plateau_threshold ? plateau_threshold : 50;
    ctx->last_coverage = 0.0f;
    
    // Create local STT
    ctx->local_stt = (state_transition_tree_t *)calloc(1, sizeof(state_transition_tree_t));
    ctx->local_stt->nodes = (state_node_t *)calloc(STATE_CACHE_SIZE, sizeof(state_node_t));
    ctx->local_stt->transitions = (state_transition_t *)calloc(STATE_CACHE_SIZE * 4, sizeof(state_transition_t));
    
    ctx->state_stats = (state_stats_t *)calloc(4096, sizeof(state_stats_t));
    ctx->rare_transitions = (rare_transition_t *)calloc(8192, sizeof(rare_transition_t));
    
    // Subscribe to new state events
    event_bus_subscribe(event_bus, EVENT_NEW_STATE_DISCOVERED,
                       scheduler_module_on_new_state, ctx);
    
    return ctx;
}

void scheduler_module_on_new_state(
    module_event_t *event,
    void *user_data) {
    
    scheduler_module_ctx_t *ctx = (scheduler_module_ctx_t *)user_data;
    if (!ctx || !event) return;
    
    // Sync state to local STT
    stt_sync_from_event(ctx->local_stt, event);
    
    // Recompute state rarity
    // TODO: Call update_state_rarity equivalent
    fprintf(stderr, "[SCHEDULER] New state %u discovered\n",
            event->data.state.state_id);
}

struct queue_entry *scheduler_module_select_seed(
    scheduler_module_ctx_t *ctx,
    struct queue_entry *queue_head) {
    
    if (!ctx || !queue_head) return queue_head;
    
    // TODO: Implement state-aware selection
    // For now, return first seed
    return queue_head;
}

/* ============ STT Synchronization ============ */

void stt_sync_from_event(
    state_transition_tree_t *local_stt,
    const module_event_t *event) {
    
    if (!local_stt || !event) return;
    
    if (event->type == EVENT_NEW_STATE_DISCOVERED) {
        uint32_t state_id = event->data.state.state_id;
        
        // Check if state exists
        int found = 0;
        for (int i = 0; i < local_stt->node_count; i++) {
            if (local_stt->nodes[i].state_id == state_id) {
                found = 1;
                break;
            }
        }
        
        // Add new state
        if (!found && local_stt->node_count < STATE_CACHE_SIZE) {
            state_node_t *node = &local_stt->nodes[local_stt->node_count];
            node->state_id = state_id;
            node->visitation_count = 1;
            node->is_new = event->data.state.is_new;
            node->coverage = event->data.state.coverage;
            node->last_visited = time(NULL);
            local_stt->node_count++;
        }
    }
}
