/* Production-source admission and execution contract checks.
 * Only target transport is replaced; queue, ledger, budget, and lifecycle
 * code are compiled from the real afl-fuzz.c translation unit. */
#define AFL_LIB 1
#ifndef BIN_PATH
#define BIN_PATH "/usr/local/bin"
#endif
#ifndef DOC_PATH
#define DOC_PATH "/usr/local/share/afl"
#endif
#include "config.h"
#include "types.h"

static u8 gating_test_driver(char **argv, u32 timeout);
#define LOOPFUZZ_EXECUTION_TEST_DRIVER gating_test_driver
#include "afl-fuzz.c"

#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>

static u8 test_trace_value = 1;
static const char test_reply[] = "220 ready\r\n";
static u32 test_reply_end = (u32)(sizeof(test_reply) - 1);

static u8 gating_test_driver(char **argv, u32 timeout) {
  (void)argv;
  (void)timeout;
  total_execs++;
  memset(trace_bits, 0, MAP_SIZE);
  trace_bits[11] = test_trace_value;
  response_buf = (char *)test_reply;
  response_buf_size = (int)sizeof(test_reply) - 1;
  response_bytes = &test_reply_end;
  messages_sent = 1;
  response_greeting_bytes = 0;
  response_single_connection = 1;
  return FAULT_NONE;
}

static void make_dir(const char *path) {
  if (mkdir(path, 0700) && errno != EEXIST) abort();
}

static void test_candidate_ids_without_log(void) {
  u8 old = event_log_enabled;
  event_log_enabled = 0;
  candidate_event_seq = 0;
  assert(candidate_log_event("selftest", "request", -1, 0, 0,
                             (const u8 *)"x", 1, 1) == 1);
  assert(candidate_log_event("selftest", "request", -1, 0, 0,
                             (const u8 *)"y", 1, 1) == 2);
  event_log_enabled = old;
}

static void test_wrapper_budget(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 7;
  root.is_provisional = 1;
  root.prov_candidate_id = 77;
  root.prov_budget_left = 64;
  root.prov_deadline_ms = get_cur_time() + 60000;
  queue = &root;
  queue_top = &root;
  llm_candidate_lineage_pin = 77;
  execution_kind = "mutation";
  target_invocation_seq = 0;
  total_execs = 0;
  for (u32 i = 0; i < 64; i++)
    assert(run_target(NULL, 1) == FAULT_NONE);
  assert(root.prov_desc_execs == 64 && root.prov_budget_left == 0);
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);
  assert(root.prov_desc_execs == 64 && total_execs == 64);
  root.is_provisional = 0;
  root.prov_converted = 1;
  llm_candidate_lineage_pin = 0;
  queue = queue_top = NULL;
}

static void test_expiry_pending_and_top_rated(void) {
  char dir[] = "/tmp/loopfuzz-gating-selftest-XXXXXX";
  assert(mkdtemp(dir));
  out_dir = (u8 *)dir;
  char queue_dir[PATH_MAX], region_dir[PATH_MAX], replay_dir[PATH_MAX];
  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", dir);
  snprintf(region_dir, sizeof(region_dir), "%s/regions", dir);
  snprintf(replay_dir, sizeof(replay_dir), "%s/replayable-queue", dir);
  make_dir(queue_dir); make_dir(region_dir); make_dir(replay_dir);
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 9;
  root.is_provisional = 1;
  root.prov_candidate_id = 91;
  root.fname = (u8 *)alloc_printf("%s/queue/id:000009,prov", dir);
  root.pending_accounted = 0;
  root.favored = 1;
  queued_favored = pending_favored = 1;
  pending_not_fuzzed = 1;
  top_rated[3] = &root;
  provisional_live = 1;
  queue = queue_top = &root;
  provisional_expire(&root, "selftest");
  assert(root.prov_expired && !root.is_provisional);
  assert(pending_not_fuzzed == 0 && pending_favored == 0);
  assert(top_rated[3] == NULL && root.tc_ref == 0);
  provisional_expire(&root, "repeat");
  assert(pending_not_fuzzed == 0 && provisional_live == 0);
  ck_free(root.fname);
  queue = queue_top = NULL;
}

static void test_calibration_gain_and_span(void) {
  struct queue_entry root, child;
  memset(&root, 0, sizeof(root));
  memset(&child, 0, sizeof(child));
  root.index = 20; root.is_provisional = 1; root.prov_candidate_id = 123;
  root.prov_budget_left = 64; root.prov_deadline_ms = get_cur_time() + 60000;
  child.index = 21; child.llm_origin_candidate_id = 123;
  child.lineage_parent_known = 1; child.lineage_parent_queue = 20;
  root.next = &child; queue = &root; queue_top = &child;
  provisional_live = 1; total_execs = 18; target_invocation_seq = 22;
  last_execution_kind = "calibration";
  provisional_note_gain(child.llm_origin_candidate_id, child.index);
  assert(root.prov_converted && !root.is_provisional);
  assert(root.prov_first_gain_queue == 21);
  assert(root.prov_first_gain_execution == 18);
  /* First gain is immutable once converted. */
  total_execs = 19; target_invocation_seq = 23;
  provisional_note_gain(child.llm_origin_candidate_id, 99);
  assert(root.prov_first_gain_queue == 21 && root.prov_first_gain_execution == 18);

  u32 ends[] = {4, 9, 15};
  u32 start = 0, end = 0;
  assert(admission_response_span(ends, 3, 15, 0, 1, 2, &start, &end));
  assert(start == 4 && end == 15);
  assert(!admission_response_span(ends, 3, 14, 0, 1, 2, &start, &end));
  assert(!admission_response_span(ends, 3, 15, 0, 2, 2, &start, &end));
  queue = queue_top = NULL;
}

static void test_direct_empty_session_rejected(void) {
  char dir[] = "/tmp/loopfuzz-direct-selftest-XXXXXX";
  assert(mkdtemp(dir));
  char queue_dir[PATH_MAX], region_dir[PATH_MAX], replay_dir[PATH_MAX];
  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", dir);
  snprintf(region_dir, sizeof(region_dir), "%s/regions", dir);
  snprintf(replay_dir, sizeof(replay_dir), "%s/replayable-queue", dir);
  make_dir(queue_dir); make_dir(region_dir); make_dir(replay_dir);
  out_dir = (u8 *)dir;
  kl_messages = kl_init(lms);
  messages_sent = 0;
  ablation_no_admission = 1;
  last_common_fuzz_saved = 0;
  last_common_fuzz_fault = FAULT_NONE;
  queued_paths = 0;
  assert(!admission_force_queue_candidate((u8 *)"candidate", 9));
  assert(queued_paths == 0 && queue == NULL);
  delete_kl_messages(kl_messages);
  kl_messages = NULL;
  ablation_no_admission = 0;
}

static void test_response_capture_is_frozen(void) {
  extract_response_codes = &extract_response_codes_ftp;
  protocol_name = "FTP";
  candidate_capture_armed = 1;
  candidate_message_first = 0;
  candidate_message_count = 1;
  gating_test_driver(NULL, 1);
  admission_capture_response();
  assert(candidate_observation_recorded && candidate_response_size > 0);
  admission_evidence_t ev;
  memset(&ev, 0, sizeof(ev));
  ev.state_seq = admission_collect_state_evidence(
      1, 0, 0, &ev.state_count, &ev.first_state, &ev.last_state,
      &ev.has_error, &ev.target_hit, &ev.edge_seq,
      &ev.obs_new_states, &ev.obs_new_transitions);
  assert(ev.state_count > 0 && ev.first_state > 0);
  admission_evidence_free(&ev);
  candidate_capture_armed = 0;
  admission_clear_response_capture();
  extract_response_codes = NULL;
}

static void test_decision_logs_trial_mode_snapshot(void) {
  char dir[] = "/tmp/loopfuzz-decision-selftest-XXXXXX";
  assert(mkdtemp(dir));
  out_dir = (u8 *)dir;
  event_log_enabled = 1;
  admission_accounting_enabled = 1;
  llm_cur_candidate_id = 314;
  admission_evidence_t ev;
  memset(&ev, 0, sizeof(ev));
  ev.trial_mode = 1;
  ev.disposition = EC_REJECT;
  admission_log_decision_event(&ev, "selftest", "request", -1, 0);
  char path[PATH_MAX], line[4096];
  snprintf(path, sizeof(path), "%s/admission-events.jsonl", dir);
  FILE *f = fopen(path, "r");
  assert(f && fgets(line, sizeof(line), f));
  fclose(f);
  assert(strstr(line, "\"trial_mode\": true") != NULL);
  admission_accounting_enabled = 0;
}

int main(void) {
  trace_bits = ck_alloc(MAP_SIZE);
  test_candidate_ids_without_log();
  test_wrapper_budget();
  test_expiry_pending_and_top_rated();
  test_calibration_gain_and_span();
  test_direct_empty_session_rejected();
  test_response_capture_is_frozen();
  test_decision_logs_trial_mode_snapshot();
  puts("gating contract selftest: PASS");
  return 0;
}
