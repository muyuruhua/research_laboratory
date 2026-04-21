#include "mqtt-cluster.h"

#include <string.h>

static u32 mqtt_o8_clamp_period(u32 period) {
  if (period == 0) return 1;
  if (period > 4096) return 4096;
  return period;
}

void mqtt_o8_init(mqtt_o8_state_t *state) {
  if (!state) return;
  memset(state, 0, sizeof(*state));
  state->current_probe_period = 1;
}

void mqtt_o8_reset_last_vote(mqtt_o8_state_t *state) {
  if (!state) return;
  memset(&state->last_vote, 0, sizeof(state->last_vote));
  state->last_vote_valid = 0;
}

void mqtt_o8_snapshot_impl_names(mqtt_o8_state_t *state,
                                 const mqtt_broker_endpoint_t *endpoints,
                                 u32 endpoint_count) {
  int limit;

  if (!state) return;

  state->impl_count = 0;
  if (!endpoints || endpoint_count == 0) return;

  limit = (endpoint_count > MQTT_DIFF_MAX_BROKERS) ? MQTT_DIFF_MAX_BROKERS : (int)endpoint_count;
  for (int i = 0; i < limit; i++) {
    snprintf(state->impl_name_buf[i], MQTT_O8_IMPL_NAME_LEN, "%s",
             endpoints[i].impl_name[0] ? endpoints[i].impl_name : "unknown");
    state->impl_names[i] = state->impl_name_buf[i];
  }
  state->impl_count = limit;
}

u32 mqtt_o8_effective_probe_period(mqtt_o8_state_t *state,
                                   u32 base_period,
                                   u64 now_ms,
                                   u64 last_path_time_ms) {
  u32 period = mqtt_o8_clamp_period(base_period);
  u64 idle_ms = 0;

  if (last_path_time_ms > 0 && now_ms > last_path_time_ms)
    idle_ms = now_ms - last_path_time_ms;

  if (idle_ms == 0 || idle_ms < 15000) {
    period = mqtt_o8_clamp_period(period * 4);
  } else if (idle_ms < 60000) {
    period = mqtt_o8_clamp_period(period * 2);
  } else if (idle_ms >= 180000) {
    period = mqtt_o8_clamp_period(period > 2 ? (period / 2) : 1);
  }

  if (state)
    state->current_probe_period = period;

  return period;
}

u8 mqtt_o8_should_cluster_probe(mqtt_o8_state_t *state,
                                u64 total_execs,
                                u32 base_period,
                                u64 now_ms,
                                u64 last_path_time_ms) {
  u32 effective_period;

  if (!state) return 1;

  effective_period = mqtt_o8_effective_probe_period(state, base_period,
                                                    now_ms, last_path_time_ms);
  if (effective_period <= 1) {
    state->cluster_last_probe_exec = total_execs;
    return 1;
  }

  if (total_execs > 0 && state->cluster_last_probe_exec > 0 &&
      (total_execs - state->cluster_last_probe_exec) < effective_period) {
    return 0;
  }

  state->cluster_last_probe_exec = total_execs;
  return 1;
}

mqtt_diff_result_t mqtt_o8_majority_vote(mqtt_o8_state_t *state,
                                         const mqtt_response_fields_t *fields,
                                         int broker_count) {
  mqtt_diff_result_t result;
  const char **impl_names = NULL;

  memset(&result, 0, sizeof(result));
  if (!state || !fields || broker_count < 3)
    return result;

  if (state->impl_count >= broker_count)
    impl_names = state->impl_names;

  result = mqtt_diff_majority_vote(fields, broker_count, impl_names,
                                   &state->last_vote);
  state->last_vote_valid = 1;
  state->majority_votes++;
  if (state->last_vote.outlier_count > 0)
    state->outlier_detections++;

  return result;
}

void mqtt_o8_note_fwd_outliers(mqtt_o8_state_t *state, int outlier_count) {
  if (!state || outlier_count <= 0) return;
  state->fwd_outlier_detections++;
}

int mqtt_o8_apply_cross_impl_boost(mqtt_o8_state_t *state,
                                   const mqtt_diff_result_t *result,
                                   int base_score) {
  int boosted;

  if (!state || !result || !state->last_vote_valid ||
      state->last_vote.outlier_count <= 0) {
    return base_score;
  }

  boosted = mqtt_diff_score_cross_impl(result, &state->last_vote,
                                       state->impl_names, state->impl_count);
  if (boosted > base_score)
    state->cross_impl_boosts++;
  return boosted;
}

int mqtt_o8_should_emit_report(mqtt_o8_state_t *state, u32 pattern_hash) {
  u32 slot;

  if (!state) return 1;
  if (!pattern_hash) pattern_hash = 0xA5A5A5A5u;

  slot = pattern_hash % MQTT_O8_REPORT_DEDUP_SLOTS;
  if (state->report_hashes[slot] == pattern_hash)
    return 0;

  state->report_hashes[slot] = pattern_hash;
  return 1;
}

void mqtt_o8_write_stats(FILE *f, const mqtt_o8_state_t *state) {
  if (!f || !state) return;

  fprintf(f, "mqtt_o8_majority_votes : %llu\n"
             "mqtt_o8_outlier_det    : %llu\n"
             "mqtt_o8_noncompliance  : %llu\n"
             "mqtt_o8_fwd_outlier    : %llu\n"
             "mqtt_o8_cross_boosts   : %llu\n"
             "mqtt_o8_probe_period   : %u\n",
          (unsigned long long)state->majority_votes,
          (unsigned long long)state->outlier_detections,
          (unsigned long long)state->noncompliance_reports,
          (unsigned long long)state->fwd_outlier_detections,
          (unsigned long long)state->cross_impl_boosts,
          state->current_probe_period);
}
