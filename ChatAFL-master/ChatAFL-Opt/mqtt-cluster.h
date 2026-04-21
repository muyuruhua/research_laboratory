#ifndef __MQTT_CLUSTER_H
#define __MQTT_CLUSTER_H

#include <stdio.h>
#include "types.h"
#include "mqtt-differential.h"

#define MQTT_O8_IMPL_NAME_LEN 32
#define MQTT_O8_REPORT_DEDUP_SLOTS 512

typedef struct {
  u8 *ip;
  u32 port;
  char impl_name[MQTT_O8_IMPL_NAME_LEN];
} mqtt_broker_endpoint_t;

typedef struct {
  u64 cluster_last_probe_exec;
  u64 majority_votes;
  u64 outlier_detections;
  u64 noncompliance_reports;
  u64 fwd_outlier_detections;
  u64 cross_impl_boosts;
  u32 current_probe_period;
  mqtt_majority_vote_t last_vote;
  u8 last_vote_valid;
  char impl_name_buf[MQTT_DIFF_MAX_BROKERS][MQTT_O8_IMPL_NAME_LEN];
  const char *impl_names[MQTT_DIFF_MAX_BROKERS];
  int impl_count;
  u32 report_hashes[MQTT_O8_REPORT_DEDUP_SLOTS];
} mqtt_o8_state_t;

void mqtt_o8_init(mqtt_o8_state_t *state);
void mqtt_o8_reset_last_vote(mqtt_o8_state_t *state);
void mqtt_o8_snapshot_impl_names(mqtt_o8_state_t *state,
                                 const mqtt_broker_endpoint_t *endpoints,
                                 u32 endpoint_count);
u32 mqtt_o8_effective_probe_period(mqtt_o8_state_t *state,
                                   u32 base_period,
                                   u64 now_ms,
                                   u64 last_path_time_ms);
u8 mqtt_o8_should_cluster_probe(mqtt_o8_state_t *state,
                                u64 total_execs,
                                u32 base_period,
                                u64 now_ms,
                                u64 last_path_time_ms);
mqtt_diff_result_t mqtt_o8_majority_vote(mqtt_o8_state_t *state,
                                         const mqtt_response_fields_t *fields,
                                         int broker_count);
void mqtt_o8_note_fwd_outliers(mqtt_o8_state_t *state, int outlier_count);
int mqtt_o8_apply_cross_impl_boost(mqtt_o8_state_t *state,
                                   const mqtt_diff_result_t *result,
                                   int base_score);
int mqtt_o8_should_emit_report(mqtt_o8_state_t *state, u32 pattern_hash);
void mqtt_o8_write_stats(FILE *f, const mqtt_o8_state_t *state);

#endif
