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

/* Config metadata only: the selftest never links or calls an LLM client. */
double llm_active_top_p(void) { return 1.0; }
int llm_active_max_tokens(void) { return 4096; }
long chat_llm_cap_calls(void) { return -1; }
long chat_llm_cap_tokens(void) { return -1; }

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
  /* Emulates the freeze-time stamp send_over_network() applies when it
   * clears the response buffer: these responses belong to the invocation
   * that just ran. */
  response_invocation_id = target_invocation_seq;
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
  root.prov_trial_slots = ck_alloc(HNB_SLOT_SET_BYTES);
  root.prov_trial_evidence_valid = 1;
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
  assert(root.prov_trial_slots == NULL && !root.prov_trial_evidence_valid);
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
  provisional_note_gain(child.llm_origin_candidate_id, child.index, NULL,
                        child.llm_origin_candidate_id, 23,
                        PROV_EVIDENCE_INLINE_CALIBRATION);
  assert(root.prov_converted && !root.is_provisional);
  assert(root.prov_first_gain_queue == 21);
  assert(root.prov_first_gain_execution == 18);
  /* First gain is immutable once converted. */
  total_execs = 19; target_invocation_seq = 23;
  provisional_note_gain(child.llm_origin_candidate_id, 99, NULL,
                        child.llm_origin_candidate_id, 24,
                        PROV_EVIDENCE_INLINE_CALIBRATION);
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

/* P0-9 audit fix: admission_*_fail counters must count the OBSERVED tuple,
 * not the leave-one-out forced-pass values — otherwise lou8 reports
 * admission_u_fail=0 while U genuinely fails ~50x/run (20261031 batch:
 * lou8=0 vs wrapgate8=46/58/46). */
static void test_leave_one_out_counts_observed(void) {
  char dir[] = "/tmp/loopfuzz-lou-selftest-XXXXXX";
  assert(mkdtemp(dir));
  out_dir = (u8 *)dir;
  event_log_enabled = 1;
  admission_accounting_enabled = 1;
  u64 u_fail_before = admission_u_fail, total_before = admission_candidate_total;

  admission_snapshot_t snap;
  memset(&snap, 0, sizeof(snap));
  admission_evidence_t ev;
  memset(&ev, 0, sizeof(ev));
  /* lou8 semantics: U observed FAIL, forced to pass for the decision. */
  ev.p_pass = ev.p_pass_obs = 1;
  ev.r_pass = ev.r_pass_obs = 1;
  ev.u_pass = 1;          /* effective (forced) */
  ev.u_pass_obs = 0;      /* observed truth */
  ev.disposition = EC_REJECT;
  admission_log_candidate_event("selftest", "request", -1, 0,
                                (const u8 *)"x", 1, &snap, &snap, &snap,
                                &ev, NULL, 1, 0, 0, 0, 0);
  assert(admission_candidate_total == total_before + 1);
  assert(admission_u_fail == u_fail_before + 1);

  /* Without ablation both tuples agree — no phantom fail counted. */
  ev.u_pass = ev.u_pass_obs = 1;
  admission_log_candidate_event("selftest", "request", -1, 0,
                                (const u8 *)"x", 1, &snap, &snap, &snap,
                                &ev, NULL, 1, 0, 0, 0, 0);
  assert(admission_candidate_total == total_before + 2);
  assert(admission_u_fail == u_fail_before + 1);
  admission_accounting_enabled = 0;
}

/* Trial coverage is measured on a scratch virgin map. Faulting trials must
 * not enter the main crash/hang feedback path or create queue entries. */
static void test_trial_save_is_non_destructive(void) {
  memset(virgin_bits, 0xff, MAP_SIZE);
  memset(virgin_tmout, 0xff, MAP_SIZE);
  memset(virgin_crash, 0xff, MAP_SIZE);
  memset(trace_bits, 0, MAP_SIZE);
  for (u32 i = 0; i < 160; i++) trace_bits[i] = 1;
  u8 virgin_before[MAP_SIZE];
  u8 timeout_before[MAP_SIZE];
  u8 crash_before[MAP_SIZE];
  memcpy(virgin_before, virgin_bits, MAP_SIZE);
  memcpy(timeout_before, virgin_tmout, MAP_SIZE);
  memcpy(crash_before, virgin_crash, MAP_SIZE);

  u32 queued_before = queued_paths;
  u64 crashes_before = total_crashes;
  u64 unique_crashes_before = unique_crashes;
  u64 tmouts_before = total_tmouts;
  u64 unique_tmouts_before = unique_tmouts;
  u64 hangs_before = unique_hangs;
  u8 old_trial_mode = admission_trial_mode;
  u8 old_crash_mode = crash_mode;
  u8 old_bitmap_changed = bitmap_changed;
  const char *old_kind = execution_kind;
  u32 old_pin = llm_candidate_lineage_pin;
  u64 old_invocation = target_invocation_seq;
  u64 old_candidate_invocation = candidate_invocation_id;
  admission_trial_mode = 1;
  execution_kind = "candidate";
  llm_candidate_lineage_pin = 77;
  target_invocation_seq = 99;
  candidate_invocation_id = 99;
  crash_mode = FAULT_NONE;
  bitmap_changed = 0;

  assert(save_if_interesting(NULL, trace_bits, 1, FAULT_NONE) == 0);
  assert(last_trial_hnb == 2);
  assert(last_trial_evidence_valid && last_trial_slot_count == 160);
  assert(last_trial_candidate_id == 77 && last_trial_invocation_id == 99);
  assert(provisional_trial_evidence_matches_candidate(77));
  assert(!provisional_trial_evidence_matches_candidate(76));
  candidate_invocation_id = 98;
  assert(!provisional_trial_evidence_matches_candidate(77));
  candidate_invocation_id = 99;
  for (u32 i = 0; i < 160; i++)
    assert(last_trial_new_slots[i >> 3] & (u8)(1u << (i & 7)));
  assert(memcmp(virgin_bits, virgin_before, MAP_SIZE) == 0);
  assert(bitmap_changed == 0);
  assert(queued_paths == queued_before && queue == NULL);

  memset(trace_bits, 0, MAP_SIZE);
  trace_bits[200] = 1;
  virgin_bits[200] = 0x7f;
  assert(save_if_interesting(NULL, trace_bits, 1, FAULT_NONE) == 0);
  assert(last_trial_hnb == 1);
  assert(last_trial_evidence_valid && last_trial_slot_count == 0);
  assert(!prov_slot_set_nonempty(last_trial_new_slots));
  virgin_bits[200] = 0xff;

  assert(save_if_interesting(NULL, trace_bits, 1, FAULT_TMOUT) == 0);
  assert(last_trial_hnb == 0);
  assert(!last_trial_evidence_valid && last_trial_slot_count == 0);
  assert(save_if_interesting(NULL, trace_bits, 1, FAULT_CRASH) == 0);
  assert(last_trial_hnb == 0);
  assert(!last_trial_evidence_valid && last_trial_candidate_id == 0);
  assert(memcmp(virgin_bits, virgin_before, MAP_SIZE) == 0);
  assert(memcmp(virgin_tmout, timeout_before, MAP_SIZE) == 0);
  assert(memcmp(virgin_crash, crash_before, MAP_SIZE) == 0);
  assert(queued_paths == queued_before && queue == NULL);
  assert(total_crashes == crashes_before && unique_crashes == unique_crashes_before);
  assert(total_tmouts == tmouts_before && unique_tmouts == unique_tmouts_before);
  assert(unique_hangs == hangs_before);
  admission_trial_mode = old_trial_mode;
  crash_mode = old_crash_mode;
  bitmap_changed = old_bitmap_changed;
  execution_kind = old_kind;
  llm_candidate_lineage_pin = old_pin;
  target_invocation_seq = old_invocation;
  candidate_invocation_id = old_candidate_invocation;
}

/* CSV #8 (2026-11-02): the three U policies must differ exactly on the
 * error-veto dimension.  A 530 FTP suffix fails strict AND protocol, but
 * passes soft with the tolerated error recorded (mis-admission measurable).
 * Binary-protocol indicators veto only under the protocol policy. */
static unsigned int *fake_ftp_extractor(unsigned char *buf, unsigned int size,
                                        unsigned int *count_ref) {
  (void)buf; (void)size;
  /* Production contract: the caller frees the returned array. */
  unsigned int *states = ck_alloc(sizeof(unsigned int) * 2);
  states[0] = 530;
  states[1] = 220;
  *count_ref = 2;
  return states;
}

static void test_u_policy_semantics(void) {
  extract_response_codes = &fake_ftp_extractor;
  char *old_protocol = protocol_name;
  protocol_name = "FTP";
  candidate_single_connection = 1;
  static unsigned char reply[] = "530 login incorrect\r\n220 bye\r\n";
  candidate_response = reply;
  candidate_response_size = sizeof(reply) - 1;
  static u32 ends[2] = {21, sizeof(reply) - 1};
  candidate_response_ends = ends;
  candidate_messages_sent = 2;
  candidate_message_first = 0;
  candidate_message_count = 2;
  candidate_greeting_bytes = 0;
  last_common_fuzz_fault = FAULT_NONE;
  u64 rejected_before = u_policy_error_rejects;
  u64 tolerated_before = u_policy_soft_tolerated;

  admission_evidence_t ev;
  memset(&ev, 0, sizeof(ev));
  u_policy = 0; u_policy_name = "strict";
  admission_evaluate_candidate_u(&ev, 1);
  assert(ev.u_binding_valid && ev.u_suffix_count == 2);
  assert(ev.u_pass == 0 && ev.u_error_states == 1);
  assert(u_policy_error_rejects == rejected_before + 1);

  memset(&ev, 0, sizeof(ev));
  u_policy = 1; u_policy_name = "soft";
  admission_evaluate_candidate_u(&ev, 1);
  assert(ev.u_pass == 1 && ev.u_soft_tolerated == 1 && ev.u_error_states == 1);
  assert(u_policy_soft_tolerated == tolerated_before + 1);

  memset(&ev, 0, sizeof(ev));
  u_policy = 2; u_policy_name = "protocol";
  admission_evaluate_candidate_u(&ev, 1);
  assert(ev.u_pass == 0 && ev.u_error_states == 1); /* FTP keeps 4xx/5xx veto */

  /* Binary-protocol semantics: no 3-digit-code veto exists for these, so
   * strict cannot see their error indicators at all; the protocol policy
   * vetoes on the protocol's own indicator. */
  u_policy = 0;
  protocol_name = "SSH";
  assert(u_policy_state_is_error(1) == 0);   /* strict: SSH DISCONNECT invisible */
  u_policy = 2;
  assert(u_policy_state_is_error(1) == 1);   /* protocol: DISCONNECT is an error */
  protocol_name = "TLS";
  assert(u_policy_state_is_error(0x1502) == 1 && u_policy_state_is_error(0x1602) == 0);
  protocol_name = "DNS";
  assert(u_policy_state_is_error(0x0005) == 1 && u_policy_state_is_error(0x0000) == 0);
  protocol_name = "DICOM";
  assert(u_policy_state_is_error(3) == 1 && u_policy_state_is_error(6) == 1 &&
         u_policy_state_is_error(1) == 0);
  u_policy = 0;
  protocol_name = old_protocol;

  /* Manual reset: candidate_response points at static test storage, so the
   * freeing admission_clear_response_capture() must not run here. */
  candidate_response = NULL;
  candidate_response_ends = NULL;
  candidate_response_size = 0;
  candidate_messages_sent = 0;
  candidate_message_first = candidate_message_count = 0;
  candidate_single_connection = 0;
  candidate_response_span_valid = 0;
  extract_response_codes = NULL;
}

/* CSV #7 (2026-11-02): an ordinary-match root shares the exact 64-call
 * debit/refusal semantics, but its close RETAINS the corpus file — the
 * retention-policy difference must be the only asymmetry. */
static void test_ordinary_match_close_keeps_files(void) {
  char dir[] = "/tmp/loopfuzz-ordmatch-selftest-XXXXXX";
  assert(mkdtemp(dir));
  char queue_dir[PATH_MAX], region_dir[PATH_MAX], replay_dir[PATH_MAX];
  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", dir);
  snprintf(region_dir, sizeof(region_dir), "%s/regions", dir);
  snprintf(replay_dir, sizeof(replay_dir), "%s/replayable-queue", dir);
  make_dir(queue_dir); make_dir(region_dir); make_dir(replay_dir);
  out_dir = (u8 *)dir;
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 5;
  root.is_provisional = 1;
  root.prov_ordinary_match = 1;
  root.prov_candidate_id = 55;
  root.prov_budget_left = 2;
  root.prov_trial_slots = ck_alloc(HNB_SLOT_SET_BYTES);
  root.prov_trial_evidence_valid = 1;
  root.prov_deadline_ms = get_cur_time() + 60000;
  root.fname = (u8 *)alloc_printf("%s/queue/id:000005,ord", dir);
  FILE *fp = fopen((char *)root.fname, "w");
  assert(fp && fputs("USER x\r\n", fp) >= 0 && fclose(fp) == 0);
  queue = queue_top = &root;
  llm_candidate_lineage_pin = 55;
  execution_kind = "mutation";
  u64 closed_before = ordinary_match_closed;
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(root.prov_budget_left == 0 && root.prov_desc_execs == 2);
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);
  assert(root.prov_expired && !root.is_provisional);
  assert(root.prov_trial_slots == NULL && !root.prov_trial_evidence_valid);
  assert(ordinary_match_closed == closed_before + 1);
  struct stat st;
  assert(stat((char *)root.fname, &st) == 0);   /* file retained, not unlinked */
  ck_free(root.fname);
  queue = queue_top = NULL;
  llm_candidate_lineage_pin = 0;
}

/* The pre-annotation execution is logged as prov-annotate but is not a
 * descendant mutation. Verify that only a real mutation consumes the root's
 * validation ledger. */
static void test_probe_does_not_consume_descendant_budget(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.is_provisional = 1;
  root.prov_candidate_id = 77;
  root.prov_budget_left = 64;
  root.prov_deadline_ms = get_cur_time() + 60000;
  const char *old_kind = execution_kind;
  u64 saved_lin = lineage_invocation_total, saved_ord = ord_invocation_total;
  u64 saved_pin = llm_candidate_lineage_pin;
  llm_candidate_lineage_pin = 77;          /* probe carries the ancestry */
  execution_kind = "prov-annotate";
  assert(execution_admit(&root, 77));
  assert(root.prov_budget_left == 64 && root.prov_desc_execs == 0);
  assert(lineage_invocation_total == saved_lin + 1);   /* lineage, not ordinary */
  assert(ord_invocation_total == saved_ord);
  execution_kind = "mutation";
  assert(execution_admit(&root, 77));
  assert(root.prov_budget_left == 63 && root.prov_desc_execs == 1);
  execution_kind = old_kind;
  llm_candidate_lineage_pin = saved_pin;
  lineage_invocation_total = saved_lin; ord_invocation_total = saved_ord;
}

/* Ordinary-match roots defer to regular provisional roots, then receive a
 * deterministic fallback service so an all-ordinary campaign cannot finish
 * with probe-only evidence. */
static void test_select_service_ordinary_fallback(void) {
  struct queue_entry ord, prov;
  region_t ord_regions[1], prov_regions[1];
  memset(&ord, 0, sizeof(ord));
  memset(&prov, 0, sizeof(prov));
  memset(ord_regions, 0, sizeof(ord_regions));
  memset(prov_regions, 0, sizeof(prov_regions));
  static u32 seq = 220;
  ord_regions[0].state_sequence = &seq; ord_regions[0].state_count = 1;
  prov_regions[0].state_sequence = &seq; prov_regions[0].state_count = 1;
  ord.index = 1; ord.is_provisional = 1; ord.prov_ordinary_match = 1;
  ord.prov_candidate_id = 11; ord.prov_budget_left = 64;
  ord.prov_deadline_ms = get_cur_time() + 1000;   /* earlier deadline */
  ord.regions = ord_regions; ord.region_count = 1;
  prov.index = 2; prov.is_provisional = 1;
  prov.prov_candidate_id = 12; prov.prov_budget_left = 64;
  prov.prov_deadline_ms = get_cur_time() + 60000;
  prov.regions = prov_regions; prov.region_count = 1;
  ord.next = &prov;
  queue = &ord; queue_top = &prov;
  u32 state_out = 0;
  struct queue_entry *picked = provisional_select_service(&state_out);
  assert(picked == &prov);                     /* EDF picks the provisional root */
  prov.is_provisional = 0; prov.prov_converted = 1;
  picked = provisional_select_service(&state_out);
  assert(picked == &ord);                      /* fallback services ordinary */
  assert(ord.is_provisional && !ord.prov_expired);
  queue = queue_top = NULL;
}

/* The EDF arm uses provisional_expire's shared error paths. Ordinary
 * roots and their descendants must still retain every corpus file. */
static void test_ordinary_edf_expiry_keeps_files(void) {
  char dir[] = "/tmp/loopfuzz-ordedf-selftest-XXXXXX";
  assert(mkdtemp(dir));
  const char *subdirs[] = {"queue", "regions", "replayable-queue"};
  for (u32 i = 0; i < 3; i++) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, subdirs[i]);
    make_dir(path);
  }
  out_dir = (u8 *)dir;
  u8 old_edf = ordinary_edf_enabled, old_log = event_log_enabled;
  u64 old_live = provisional_live;
  ordinary_edf_enabled = 1;
  event_log_enabled = 0;
  for (u32 failure = 0; failure < 3; failure++) {
    struct queue_entry root, child;
    memset(&root, 0, sizeof(root));
    memset(&child, 0, sizeof(child));
    root.index = 100 + 2 * failure;
    root.is_provisional = root.prov_ordinary_match = 1;
    root.prov_candidate_id = 500 + failure;
    root.llm_origin_candidate_id = root.prov_candidate_id;
    root.prov_budget_left = failure == 0 ? 0 : 64;
    root.prov_deadline_ms = failure == 1 ? 0 : get_cur_time() + 60000;
    child.index = root.index + 1;
    child.llm_origin_candidate_id = root.prov_candidate_id;
    root.next = &child;
    struct queue_entry *entries[] = {&root, &child};
    for (u32 k = 0; k < 2; k++) {
      entries[k]->fname = (u8 *)alloc_printf("%s/queue/id:%06u,ord", dir,
                                            entries[k]->index);
      for (u32 i = 0; i < 3; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s/%s", dir, subdirs[i],
                 basename(entries[k]->fname));
        FILE *fp = fopen(path, "w");
        assert(fp && fputs("USER x\r\n", fp) >= 0 && fclose(fp) == 0);
      }
    }
    queue = &root; queue_top = &child;
    provisional_live = 7; /* ordinary roots never belong to this counter */
    u64 closed_before = ordinary_match_closed;
    u64 expired_before = provisional_expired_total;
    assert(provisional_select_service(NULL) == NULL);
    assert(root.prov_expired && child.prov_expired && !root.is_provisional);
    assert(ordinary_match_closed == closed_before + 1);
    assert(provisional_expired_total == expired_before && provisional_live == 7);
    for (u32 k = 0; k < 2; k++) {
      for (u32 i = 0; i < 3; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s/%s", dir, subdirs[i],
                 basename(entries[k]->fname));
        assert(access(path, F_OK) == 0);
      }
      ck_free(entries[k]->fname);
    }
  }
  provisional_live = old_live;
  ordinary_edf_enabled = old_edf;
  event_log_enabled = old_log;
  queue = queue_top = NULL;
}

/* Pipelining-aware binding (2026-11-03 fix): batched SMTP replies leave
 * zero-delta boundaries inside the candidate window; binding must hold with
 * >=1 non-empty span, still rejecting all-empty windows and non-monotonic
 * boundaries.  Measured exim: every trial had 895,895,895-style repeats and
 * U failed structurally 31/31 before the fix. */
static void test_pipelined_span_binding(void) {
  u32 start = 0, end = 0;
  u32 pipelined[] = {100, 100, 150, 150};
  assert(admission_response_span(pipelined, 4, 150, 0, 0, 4, &start, &end));
  assert(start == 0 && end == 150);
  u32 mixed[] = {40, 40, 40, 90};
  assert(admission_response_span(mixed, 4, 90, 20, 1, 3, &start, &end));
  u32 all_flat[] = {80, 80, 80};
  assert(!admission_response_span(all_flat, 3, 80, 80, 0, 3, &start, &end));
  u32 backwards[] = {50, 40, 60};
  assert(!admission_response_span(backwards, 3, 60, 0, 0, 3, &start, &end));
  /* Majority-annotated executability: 2/3 annotated passes, 1/3 fails. */
  struct queue_entry q;
  region_t regions[3];
  memset(&q, 0, sizeof(q));
  memset(regions, 0, sizeof(regions));
  static u32 seq = 220;
  regions[0].state_sequence = &seq; regions[0].state_count = 1;
  regions[2].state_sequence = &seq; regions[2].state_count = 1;
  q.regions = regions; q.region_count = 3;
  assert(entry_can_fuzz_full_session(&q));
  regions[2].state_sequence = NULL; regions[2].state_count = 0;
  assert(!entry_can_fuzz_full_session(&q));
}

/* Opportunity gate (2026-11-03 fix): EDF service parks while havoc runs hot
 * and resumes when it stalls, with window bookkeeping preserved. */
/* S1 prefix protection (2026-11-05): under forced provisional service the
 * M2 range must clamp to the entry's recorded candidate window so the
 * reaching prefix replays verbatim; unknown windows and the kill switch
 * keep the legacy whole-session behavior. */
static void test_prov_prefix_protect_m2(void) {
  struct queue_entry root;
  region_t regions[5];
  memset(&root, 0, sizeof(root));
  memset(regions, 0, sizeof(regions));
  static u32 seq = 230;
  for (int i = 0; i < 5; i++) {
    regions[i].state_sequence = &seq; regions[i].state_count = 1;
  }
  root.index = 4; root.is_provisional = 1;
  root.regions = regions; root.region_count = 5;
  u32 start = 999, count = 0;
  u8 saved_ov = full_session_m2_override, saved_pp = prov_prefix_protect;
  full_session_m2_override = 1; prov_prefix_protect = 1;

  /* window unknown (count==0) -> legacy full session */
  root.prov_cand_first = 0; root.prov_cand_count = 0;
  assert(entry_m2_range(&root, 0, &start, &count) == 1);
  assert(start == 0 && count == 5);

  /* window [2,3) -> M2 restricted to the candidate messages */
  root.prov_cand_first = 2; root.prov_cand_count = 2;
  assert(entry_m2_range(&root, 0, &start, &count) == 1);
  assert(start == 2 && count == 2);

  /* window overrun is clamped to the saved regions */
  root.prov_cand_first = 3; root.prov_cand_count = 9;
  assert(entry_m2_range(&root, 0, &start, &count) == 1);
  assert(start == 3 && count == 2);

  /* first beyond saved regions -> legacy full session */
  root.prov_cand_first = 7; root.prov_cand_count = 2;
  assert(entry_m2_range(&root, 0, &start, &count) == 1);
  assert(start == 0 && count == 5);

  /* kill switch restores whole-session M2 */
  prov_prefix_protect = 0;
  root.prov_cand_first = 2; root.prov_cand_count = 2;
  assert(entry_m2_range(&root, 0, &start, &count) == 1);
  assert(start == 0 && count == 5);
  prov_prefix_protect = 1;

  /* the S1 window path does not require per-region annotation (entry_
   * can_fuzz_full_session judges serviceability separately); the legacy
   * fallback still rejects unannotated sessions. */
  regions[1].state_sequence = NULL; regions[1].state_count = 0;
  root.prov_cand_first = 2; root.prov_cand_count = 2;
  assert(entry_m2_range(&root, 0, &start, &count) == 1);
  assert(start == 2 && count == 2);
  root.prov_cand_count = 0;
  assert(entry_m2_range(&root, 0, &start, &count) == 0);

  full_session_m2_override = saved_ov; prov_prefix_protect = saved_pp;
}

/* Channel-consistent accounting (2026-11-06, GLM53 audit): converted
 * roots and durable-lineage descendants must feed the LINEAGE channel,
 * never the ordinary denominator; ancestry-free calls feed ordinary. */
static void test_channel_accounting(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 11; root.is_provisional = 1;
  root.prov_candidate_id = 42; root.prov_budget_left = 64;
  root.prov_deadline_ms = get_cur_time() + 60000;
  queue = queue_top = &root;

  u64 saved_lin = lineage_invocation_total, saved_ord = ord_invocation_total;
  u64 saved_chg = prov_charged_total;

  /* Live root + ancestry: lineage channel + charged budget. */
  llm_candidate_lineage_pin = 42;
  execution_kind = "mutation";
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(lineage_invocation_total == saved_lin + 1);
  assert(ord_invocation_total == saved_ord);
  assert(prov_charged_total == saved_chg + 1);
  assert(root.prov_desc_execs == 1);

  /* Converted root: budget no longer debited, but the call STAYS in the
   * lineage channel (the 2026-11-05 bug let it vanish from both). */
  root.prov_converted = 1;
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(lineage_invocation_total == saved_lin + 2);
  assert(ord_invocation_total == saved_ord);
  assert(prov_charged_total == saved_chg + 1);
  assert(root.prov_desc_execs == 1);

  /* Durable-lineage call (no live provisional root): lineage channel,
   * never the ordinary denominator (numerator/denominator alignment). */
  root.is_provisional = 0;
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(lineage_invocation_total == saved_lin + 3);
  assert(ord_invocation_total == saved_ord);

  /* Ancestry-free call: ordinary channel. */
  llm_candidate_lineage_pin = 0;
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(lineage_invocation_total == saved_lin + 3);
  assert(ord_invocation_total == saved_ord + 1);

  llm_candidate_lineage_pin = 0;
  lineage_invocation_total = saved_lin; ord_invocation_total = saved_ord;
  prov_charged_total = saved_chg;
  queue = queue_top = NULL;
}

static void test_set_map_slot(u8 *slots, u32 slot) {
  slots[slot >> 3] |= (u8)(1u << (slot & 7));
}

/* Conversion classification refers to AFL map slots and must use only
 * candidate-bound trial evidence and the current gain invocation. */
static void test_conversion_classification(void) {
  struct queue_entry root, root2, root3, root4, root5;
  struct queue_entry *roots[] = {&root, &root2, &root3, &root4, &root5};
  const u32 candidate_ids[] = {42, 43, 44, 46, 47};
  const u64 trial_ids[] = {100, 110, 120, 130, 140};
  for (u32 i = 0; i < 5; i++) {
    memset(roots[i], 0, sizeof(*roots[i]));
    roots[i]->index = 21 + i;
    roots[i]->is_provisional = 1;
    roots[i]->prov_candidate_id = candidate_ids[i];
    roots[i]->prov_budget_left = 64;
    roots[i]->prov_deadline_ms = get_cur_time() + 60000;
    roots[i]->prov_trial_slots = ck_alloc(HNB_SLOT_SET_BYTES);
    roots[i]->prov_trial_evidence_valid = 1;
    roots[i]->prov_trial_candidate_id = candidate_ids[i];
    roots[i]->prov_trial_invocation_id = trial_ids[i];
    test_set_map_slot(roots[i]->prov_trial_slots, 5);
    test_set_map_slot(roots[i]->prov_trial_slots, 9);
    test_set_map_slot(roots[i]->prov_trial_slots, 20);
    roots[i]->prov_trial_slot_count = 3;
  }
  u64 saved_i = prov_conv_immediate_only, saved_b = prov_conv_beyond_trial;
  u64 saved_u = prov_conv_unclassified;

  u8 save_subset[HNB_SLOT_SET_BYTES] = {0};
  test_set_map_slot(save_subset, 5);
  test_set_map_slot(save_subset, 9);
  queue = queue_top = &root;
  provisional_note_gain(42, 100, save_subset, 42, 101,
                        PROV_EVIDENCE_MUTATION_SAVE);
  assert(root.prov_conv_class == 1);
  assert(prov_conv_immediate_only == saved_i + 1);
  assert(root.prov_converted == 1);
  assert(root.prov_trial_slots == NULL);
  assert(root.prov_conv_save_slot_count == 2);
  assert(root.prov_conv_overlap_slot_count == 2);
  assert(root.prov_conv_beyond_trial_slot_count == 0);

  /* Mixed overlap and new slots are reported as containing beyond-trial. */
  queue = &root2; queue_top = &root2;
  u8 save_mixed[HNB_SLOT_SET_BYTES] = {0};
  test_set_map_slot(save_mixed, 5);
  test_set_map_slot(save_mixed, 17);
  provisional_note_gain(43, 101, save_mixed, 43, 111,
                        PROV_EVIDENCE_MUTATION_SAVE);
  assert(root2.prov_conv_class == 2);
  assert(prov_conv_beyond_trial == saved_b + 1);
  assert(root2.prov_trial_slots == NULL);
  assert(root2.prov_conv_save_slot_count == 2);
  assert(root2.prov_conv_overlap_slot_count == 1);
  assert(root2.prov_conv_beyond_trial_slot_count == 1);

  /* Candidate mismatch and non-monotone invocation IDs are unclassified. */
  queue = &root3; queue_top = &root3;
  u8 save_one[HNB_SLOT_SET_BYTES] = {0};
  test_set_map_slot(save_one, 37);
  provisional_note_gain(44, 102, save_one, 45, 121,
                        PROV_EVIDENCE_MUTATION_SAVE);
  assert(root3.prov_conv_class == 0);
  assert(prov_conv_unclassified == saved_u + 1);

  queue = &root4; queue_top = &root4;
  provisional_note_gain(46, 103, save_one, 46, 131,
                        PROV_EVIDENCE_INLINE_CALIBRATION);
  assert(root4.prov_conv_class == 2);
  assert(root4.prov_conv_evidence_source ==
         PROV_EVIDENCE_INLINE_CALIBRATION);

  queue = &root5; queue_top = &root5;
  provisional_note_gain(47, 104, save_one, 47, 139,
                        PROV_EVIDENCE_MUTATION_SAVE);
  assert(root5.prov_conv_class == 0);
  assert(prov_conv_unclassified == saved_u + 2);

  u8 full_capture[HNB_SLOT_SET_BYTES] = {0};
  for (u32 i = 0; i < 160; i++) test_set_map_slot(full_capture, i);
  assert(prov_slot_set_count(full_capture) == 160);
  assert(prov_slot_set_subset(save_subset, full_capture));
  assert(!prov_slot_set_subset(full_capture, save_subset));

  prov_conv_immediate_only = saved_i; prov_conv_beyond_trial = saved_b;
  prov_conv_unclassified = saved_u;
  queue = queue_top = NULL;
}

static void test_censor_frees_trial_evidence(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.is_provisional = 1;
  root.prov_candidate_id = 88;
  root.prov_trial_slots = ck_alloc(HNB_SLOT_SET_BYTES);
  root.prov_trial_evidence_valid = 1;
  queue = queue_top = &root;
  u8 old_log = event_log_enabled;
  event_log_enabled = 0;
  provisional_censor_all_at_shutdown();
  assert(root.prov_expired && !root.is_provisional);
  assert(root.prov_trial_slots == NULL && !root.prov_trial_evidence_valid);
  event_log_enabled = old_log;
  queue = queue_top = NULL;
}

/* Witness tomb (2026-11-07): an expiring provisional root's session file
 * is MOVED to witness-tomb/ instead of unlinked; regions/replay copies
 * are still removed; the removal checkpoint ledger row is still written. */
static void test_witness_tomb_expiry_move(void) {
  char tmpl[] = "/tmp/wt-selftest-XXXXXX";
  if (!mkdtemp(tmpl)) return;
  u8 *old_out = out_dir;
  u8 *qdir = alloc_printf("%s/queue", tmpl);
  u8 *tdir = alloc_printf("%s/witness-tomb", tmpl);
  mkdir((char *)qdir, 0755); mkdir((char *)tdir, 0755);
  u8 *fname = alloc_printf("%s/queue/id:000042,prov", tmpl);
  FILE *f = fopen((char *)fname, "w");
  if (f) { fputs("SEED", f); fclose(f); }
  struct queue_entry q;
  memset(&q, 0, sizeof(q));
  q.fname = fname; q.index = 42;
  out_dir = (u8 *)tmpl;
  u64 before = witness_tomb_expiries;
  event_log_enabled = 0;

  provisional_invalidate_entry(&q, 0);

  u8 *moved = alloc_printf("%s/witness-tomb/expired-id:000042,prov", tmpl);
  FILE *m = fopen((char *)moved, "r");
  assert(m != NULL);                  /* session preserved in the tomb */
  if (m) fclose(m);
  assert(access((char *)fname, F_OK) != 0);  /* original gone */
  assert(witness_tomb_expiries == before + 1);

  ck_free(moved); ck_free(qdir); ck_free(tdir); ck_free(fname);
  out_dir = old_out;
  event_log_enabled = 1;
}

/* Stage-2 T03: fixed campaign call budget — admitted invocations count
 * against the cap, the cap refusal is a planned stop, and NO_REFLOW's
 * parked quota shrinks the effective cap. */
static void test_campaign_budget_cap(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 31; root.is_provisional = 1;
  root.prov_candidate_id = 91; root.prov_budget_left = 64;
  root.prov_deadline_ms = get_cur_time() + 60000;
  queue = queue_top = &root;
  u64 saved_budget = campaign_call_budget, saved_charged = campaign_charged_invocations;
  u64 saved_idle = q1_idle_total, saved_pool = q1_reflow_pool;
  u8  saved_exh = campaign_budget_exhausted, saved_rep = campaign_budget_stop_reported;
  const char *old_kind = execution_kind;
  execution_kind = "mutation";

  campaign_charged_invocations = 0;
  campaign_budget_exhausted = 0;
  campaign_budget_stop_reported = 0;
  q1_idle_total = 0;
  campaign_call_budget = 2;
  llm_candidate_lineage_pin = 91;

  assert(run_target(NULL, 1) == FAULT_NONE);   /* charged 1 */
  assert(run_target(NULL, 1) == FAULT_NONE);   /* charged 2 = cap */
  assert(campaign_budget_exhausted == 0);      /* AT cap still admits */
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);  /* cap+1 refused */
  assert(campaign_budget_exhausted == 1);
  assert(campaign_charged_invocations == 2);   /* refusal charges nothing */

  /* NO_REFLOW parked quota shrinks the effective cap. */
  campaign_budget_exhausted = 0;
  campaign_charged_invocations = 0;
  q1_idle_total = 1;                           /* cap 2 -> effective 1 */
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);
  assert(campaign_budget_exhausted == 1);

  /* All quota parked: effective cap is exactly zero, which is still an
   * enabled campaign budget and therefore must refuse the first invocation.
   * This catches the historical `if (cap && ...)` sentinel bug. */
  campaign_budget_exhausted = 0;
  campaign_charged_invocations = 0;
  q1_idle_total = 2;                           /* cap 2 -> effective 0 */
  assert(campaign_effective_call_cap() == 0);
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);
  assert(campaign_budget_exhausted == 1);

  campaign_call_budget = saved_budget;
  campaign_charged_invocations = saved_charged;
  q1_idle_total = saved_idle; q1_reflow_pool = saved_pool;
  campaign_budget_exhausted = saved_exh;
  campaign_budget_stop_reported = saved_rep;
  execution_kind = old_kind;
  llm_candidate_lineage_pin = 0;
  queue = queue_top = NULL;
}

/* REFLOW: ordinary mutations consume pool quota first; lineage calls do
 * not. */
static void test_q1_reflow_consumption(void) {
  u8 saved_reflow = q1_reflow;
  u64 saved_pool = q1_reflow_pool, saved_used = q1_reflow_consumed;
  u64 saved_ord = ord_invocation_total, saved_lin = lineage_invocation_total;
  q1_reflow_node_t *saved_head = q1_reflow_head, *saved_tail = q1_reflow_tail;
  u64 saved_next_id = q1_reflow_next_id;
  const char *old_kind = execution_kind;
  q1_reflow_head = q1_reflow_tail = NULL;
  q1_reflow_next_id = 0;
  q1_reflow = 1; q1_reflow_pool = 2; q1_reflow_consumed = 0;
  assert(q1_register_reflow(901, 2) != 0);
  execution_kind = "mutation";
  llm_candidate_lineage_pin = 0;

  assert(run_target(NULL, 1) == FAULT_NONE);   /* pool 2->1 */
  assert(q1_active_flow_id == 1 && q1_active_flow_source == 901 &&
         q1_active_flow_remaining == 1);
  assert(run_target(NULL, 1) == FAULT_NONE);   /* pool 1->0 */
  assert(q1_active_flow_id == 1 && q1_active_flow_source == 901 &&
         q1_active_flow_remaining == 0);
  assert(run_target(NULL, 1) == FAULT_NONE);   /* pool empty: no burn */
  assert(q1_reflow_consumed == 2 && q1_reflow_pool == 0);

  q1_reflow = saved_reflow;
  q1_reflow_pool = saved_pool; q1_reflow_consumed = saved_used;
  ord_invocation_total = saved_ord; lineage_invocation_total = saved_lin;
  q1_reflow_head = saved_head; q1_reflow_tail = saved_tail;
  q1_reflow_next_id = saved_next_id;
  execution_kind = old_kind;
}

/* Strategy A route: every executed p&r candidate — rejected OR durable —
 * becomes provisional-service when DIRECT_SERVICE is on; off restores the
 * gate decision. */
static void test_q1_direct_service_route(void) {
  admission_evidence_t ev;
  u8 saved = q1_direct_service;
  memset(&ev, 0, sizeof(ev));
  ev.p_pass = 1; ev.r_pass = 1; ev.u_pass = 0;
  ev.g_code_pass = 1; ev.g_state_pass = 0;   /* strict-U reject w/ code */
  ev.disposition = EC_REJECT;

  /* Route condition mirrored from admission_run_llm_candidate: with the
   * flag off the disposition is untouched (gate semantics); with it on,
   * both reject and durable outcomes satisfy the reroute predicate. */
  q1_direct_service = 0;
  assert(!(q1_direct_service && ev.p_pass && ev.r_pass &&
           (ev.disposition == EC_REJECT || ev.disposition == EC_DURABLE)));
  q1_direct_service = 1;
  assert(q1_direct_service && ev.p_pass && ev.r_pass && ev.disposition == EC_REJECT);
  ev.disposition = EC_DURABLE;
  assert(q1_direct_service && ev.p_pass && ev.r_pass &&
         (ev.disposition == EC_REJECT || ev.disposition == EC_DURABLE));
  ev.r_pass = 0;                                /* not replayable: no reroute */
  assert(!(q1_direct_service && ev.p_pass && ev.r_pass));
  q1_direct_service = saved;
}

/* S2 state-evidence retention (2026-11-05): the routing predicate must
 * upgrade exactly the strict-U rejects whose only evidence is response-
 * state novelty, and never override durable/provisional/code-retain. */
static void test_state_retain_route(void) {
  admission_evidence_t ev;
  u8 saved = state_retain_enabled;
  memset(&ev, 0, sizeof(ev));
  ev.p_pass = 1; ev.u_pass = 0; ev.r_pass = 1;
  ev.g_state_pass = 1; ev.g_code_pass = 0;
  ev.disposition = EC_REJECT;

  ev.u_binding_valid = 1;                   /* frozen candidate response binding */
  state_retain_enabled = 0;                 /* opt-in only */
  assert(state_retain_route(&ev) == 0);
  state_retain_enabled = 1;
  assert(state_retain_route(&ev) == 1);

  ev.g_code_pass = 1;                       /* code evidence -> code-retain path */
  assert(state_retain_route(&ev) == 0);
  ev.g_code_pass = 0;
  ev.u_pass = 1;                            /* natural cell -> provisional */
  assert(state_retain_route(&ev) == 0);
  ev.u_pass = 0;
  ev.r_pass = 0;                            /* not replayable */
  assert(state_retain_route(&ev) == 0);
  ev.r_pass = 1;
  ev.u_binding_valid = 0;                   /* no response binding -> stay rejected */
  assert(state_retain_route(&ev) == 0);
  ev.u_binding_valid = 1;
  ev.disposition = EC_PROVISIONAL;          /* never override non-rejects */
  assert(state_retain_route(&ev) == 0);
  ev.disposition = EC_CODE_RETAIN;
  assert(state_retain_route(&ev) == 0);

  assert(strcmp(ec_disposition_name(EC_STATE_RETAIN), "state-retain") == 0);
  state_retain_enabled = saved;
}

static void test_opportunity_gate(void) {
  struct queue_entry root;
  region_t regions[1];
  memset(&root, 0, sizeof(root));
  memset(regions, 0, sizeof(regions));
  static u32 seq = 220;
  regions[0].state_sequence = &seq; regions[0].state_count = 1;
  root.index = 3; root.is_provisional = 1;
  root.prov_candidate_id = 9; root.prov_budget_left = 64;
  root.prov_deadline_ms = get_cur_time() + 60000;
  root.regions = regions; root.region_count = 1;
  queue = queue_top = &root;
  u8 old_log = event_log_enabled;
  event_log_enabled = 0;

  double saved_th = salvage_opportunity_threshold;
  salvage_opportunity_threshold = 4.0;
  salvage_opportunity_parked = 0;
  opportunity_parked_windows = 0;
  u64 saved_c = opp_window_calls;
  u64 saved_vc = opp_win_val_calls, saved_vg = opp_win_val_gains;
  u64 saved_og = opp_win_ord_gains;
  u64 saved_gains = code_gain_events, saved_ord = ord_invocation_total;
  u64 saved_lin = llm_lineage_edge_gains, saved_chg = prov_charged_total;
  u64 saved_lin_calls = lineage_invocation_total;

  /* W1: ordinary out-yields, validation exposed -> park (#1). */
  opp_window_calls = 0; opp_win_val_calls = 0;
  opp_win_val_gains = 0; opp_win_ord_gains = 0;
  code_gain_events = 20; llm_lineage_edge_gains = 0;
  ord_invocation_total = 2000; lineage_invocation_total = 500;
  u32 state_out = 0;
  assert(provisional_select_service(&state_out) == NULL);
  assert(salvage_opportunity_parked == 1 && opportunity_parked_windows == 1);

  /* W2: ordinary still out-yields -> park (#2, at the cap). */
  code_gain_events += 20; ord_invocation_total += 2000;
  lineage_invocation_total += 100;
  assert(provisional_select_service(&state_out) == NULL);
  assert(salvage_opportunity_parked == 1 && opportunity_parked_windows == 2);

  /* W3: ordinary STILL out-yields, but the bounded park forces ONE
   * service window — validation cannot be starved past the cap. */
  code_gain_events += 20; ord_invocation_total += 2000;
  lineage_invocation_total += 100;
  struct queue_entry *picked = provisional_select_service(&state_out);
  assert(picked == &root);
  assert(salvage_opportunity_parked == 0 && opportunity_parked_windows == 0);

  /* W4: lineage out-yields ordinary (5/100 vs 2/4000) -> stays unparked
   * by decision (not by force). */
  code_gain_events += 2 + 5; llm_lineage_edge_gains += 5;
  ord_invocation_total += 4000; lineage_invocation_total += 100;
  assert(provisional_select_service(&state_out) == &root);
  assert(salvage_opportunity_parked == 0);

  /* W5 (underexposed, below cap): parked + fewer than 64 lineage calls
   * in window -> no decision; park kept even though ordinary runs hot. */
  salvage_opportunity_parked = 1; opportunity_parked_windows = 1;
  code_gain_events += 20; ord_invocation_total += 2000;
  lineage_invocation_total += 10;
  assert(provisional_select_service(&state_out) == NULL);
  assert(salvage_opportunity_parked == 1);

  /* W6 (underexposed AT the cap): the service guarantee fires regardless
   * of exposure — starvation bounding precedes the statistical decision
   * (batch-B run1 postmortem). */
  opportunity_parked_windows = OPPORTUNITY_PARK_WINDOW_CAP;
  code_gain_events += 20; ord_invocation_total += 2000;
  lineage_invocation_total += 5;
  struct queue_entry *forced = provisional_select_service(&state_out);
  assert(forced == &root);
  assert(salvage_opportunity_parked == 0 && opportunity_parked_windows == 0);

  /* off by default */
  salvage_opportunity_threshold = 0.0;
  salvage_opportunity_parked = 0;
  assert(provisional_select_service(&state_out) == &root);

  salvage_opportunity_threshold = saved_th;
  opp_window_calls = saved_c;
  opp_win_val_calls = saved_vc; opp_win_val_gains = saved_vg;
  opp_win_ord_gains = saved_og;
  code_gain_events = saved_gains; ord_invocation_total = saved_ord;
  llm_lineage_edge_gains = saved_lin; prov_charged_total = saved_chg;
  lineage_invocation_total = saved_lin_calls;
  salvage_opportunity_parked = 0; opportunity_parked_windows = 0;
  event_log_enabled = old_log;
  queue = queue_top = NULL;
}

/* Execute the production candidate path with a protocol-error response and
 * real bitmap novelty. The rescue must persist the observed input without
 * creating or charging a provisional subtree. */
static void test_code_durable_policy_and_witness_transaction(void) {
  char dir[] = "/tmp/loopfuzz-code-durable-selftest-XXXXXX";
  assert(mkdtemp(dir));
  char queue_dir[PATH_MAX], regions_dir[PATH_MAX], replay_dir[PATH_MAX];
  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", dir);
  snprintf(regions_dir, sizeof(regions_dir), "%s/regions", dir);
  snprintf(replay_dir, sizeof(replay_dir), "%s/replayable-queue", dir);
  make_dir(queue_dir); make_dir(regions_dir); make_dir(replay_dir);
  out_dir = (u8 *)dir;
  queue = queue_top = queue_cur = q_prev100 = NULL;
  cur_fuzz_provisional_root = NULL;
  cur_fuzz_lineage_candidate_id = llm_candidate_lineage_pin = 0;
  queued_paths = pending_not_fuzzed = 0;
  state_aware_mode = corpus_read_or_sync = 0;
  stop_soon = 0;
  q1_direct_service = q1_no_reflow = 0; q1_reflow = 1;
  ablation_no_admission = admission_native_retention = 0;
  code_retain_enabled = code_durable_enabled = test_force_code_retain = 0;
  provisional_enabled = 1; shadow_enabled = salvage_enabled = 0;
  state_retain_enabled = 0;
  adm_ablate_p = adm_ablate_u = adm_ablate_r = 0;
  adm_ablate_gcode = adm_ablate_gstate = 0;
  cal_episode_active = 0;
  campaign_call_budget = campaign_charged_invocations = 0;
  event_log_enabled = admission_accounting_enabled = 1;
  extract_requests = &extract_requests_ftp;
  extract_response_codes = &fake_ftp_extractor;
  protocol_name = "FTP"; u_policy = 0; u_policy_name = "strict";
  max_seed_region_count = 100;
  kl_messages = kl_init(lms);
  message_t *old = ck_alloc(sizeof(*old));
  old->msize = 6; old->mdata = (char *)ck_memdup("NOOP\r\n", 6);
  *kl_pushp(lms, kl_messages) = old;
  M2_prev = NULL; M2_next = kl_end(kl_messages);
  execution_kind = "mutation";
  memset(virgin_bits, 0xff, MAP_SIZE);
  u64 pv_admits = provisional_admitted, pv_converts = provisional_converted;
  u64 pv_calls = prov_charged_total, beyond = prov_conv_beyond_trial;
  u64 durable_before = code_durable_admitted, gains_before = admission_gain_events;
  u64 saved_before = q1_saved_total;
  u64 execs_before = total_execs;
  u8 candidate[] = "NOOP\r\n";

  /* Default off: the old hard rejection and its reflow registration remain. */
  assert(!admission_run_llm_candidate(NULL, "selftest", "request", -1, 0,
                                    candidate, sizeof(candidate) - 1, 1, "valid"));
  assert(queue == NULL && queued_paths == 0);
  assert(virgin_bits[11] == 0xff && q1_saved_total == saved_before + 64);
  assert(code_durable_admitted == durable_before);
  assert(total_execs == execs_before + 1);

  code_durable_enabled = 1;
  shadow_enabled = 1;
  u64 shadows_before = shadow_validations_total;
  u64 reflow_before_rescue = q1_saved_total;
  assert(!admission_run_llm_candidate(NULL, "selftest", "request", -1, 0,
                                    candidate, sizeof(candidate) - 1, 1, "valid"));
  assert(queued_paths == 1 && queue == queue_top);
  struct queue_entry *rescued = queue;
  assert(!rescued->is_provisional && !rescued->prov_candidate_id);
  assert(!rescued->prov_budget_left && !rescued->prov_code_retain);
  assert(rescued->llm_origin_candidate_id == (u32)llm_cur_candidate_id);
  assert(rescued->has_new_cov && virgin_bits[11] != 0xff);
  assert(code_durable_admitted == durable_before + 1);
  assert(admission_gain_events == gains_before + 1);
  assert(q1_saved_total == reflow_before_rescue);
  assert(provisional_admitted == pv_admits && provisional_converted == pv_converts);
  assert(prov_charged_total == pv_calls && prov_conv_beyond_trial == beyond);
  assert(total_execs == execs_before + 2); /* no annotate or forced 64 calls */
  assert(shadow_validations_total == shadows_before);
  shadow_enabled = 0;
  char *replay_path = (char *)alloc_printf("%s/%s", replay_dir, basename(rescued->fname));
  FILE *f = fopen((char *)rescued->fname, "rb");
  char raw[7] = {0};
  assert(f && fread(raw, 1, 6, f) == 6 && !memcmp(raw, candidate, 6)); fclose(f);
  f = fopen(replay_path, "rb"); u32 frame_len = 0;
  assert(f && fread(&frame_len, sizeof(frame_len), 1, f) == 1 && frame_len == 6);
  assert(fread(raw, 1, 6, f) == 6 && !memcmp(raw, candidate, 6)); fclose(f);
  char event_path[PATH_MAX], line[4096];
  snprintf(event_path, sizeof(event_path), "%s/code-durable-events.jsonl", dir);
  f = fopen(event_path, "r"); assert(f && fgets(line, sizeof(line), f)); fclose(f);
  struct json_object *j = json_tokener_parse(line), *value;
  assert(j && json_object_object_get_ex(j, "candidate_id", &value));
  assert(json_object_get_int64(value) == llm_cur_candidate_id);
  assert(json_object_object_get_ex(j, "trial_invocation_id", &value));
  assert((u64)json_object_get_int64(value) == last_trial_invocation_id);
  assert(last_trial_invocation_id == target_invocation_seq);
  assert(json_object_object_get_ex(j, "queue_id", &value) && json_object_get_int(value) == 0);
  assert(json_object_object_get_ex(j, "queue_filename", &value));
  assert(!strcmp(json_object_get_string(value), (char *)rescued->fname));
  assert(json_object_object_get_ex(j, "replay_filename", &value));
  assert(!strcmp(json_object_get_string(value), replay_path));
  assert(json_object_object_get_ex(j, "pv_conversion", &value) && !json_object_get_boolean(value));
  json_object_put(j);
  ck_free(replay_path);

  /* No root quota exists: ordinary scheduling can execute beyond 64 calls,
   * while lineage attribution remains separate from ancestry-free work. */
  cur_fuzz_lineage_candidate_id = rescued->llm_origin_candidate_id;
  for (u32 i = 0; i < 65; i++) assert(run_target(NULL, 1) == FAULT_NONE);
  assert(prov_charged_total == pv_calls);
  cur_fuzz_lineage_candidate_id = 0;

  /* Missing/cross-invocation evidence and forced passes cannot rescue. */
  admission_evidence_t ev;
  memset(&ev, 0, sizeof(ev));
  ev.disposition = EC_CODE_RETAIN; ev.trial_mode = 1;
  ev.p_pass = ev.r_pass = ev.g_code_pass = 1;
  ev.p_pass_obs = ev.r_pass_obs = ev.g_code_pass_obs = 1;
  ev.trial_hnb = last_trial_hnb = 2;
  last_trial_evidence_valid = 1;
  last_trial_candidate_id = (u32)llm_cur_candidate_id;
  candidate_invocation_id = last_trial_invocation_id = target_invocation_seq;
  last_trial_slot_count = 1;
  memset(last_trial_new_slots, 0, sizeof(last_trial_new_slots));
  last_trial_new_slots[11 >> 3] = 1u << (11 & 7);
  last_common_fuzz_fault = FAULT_NONE;
  assert(code_durable_route(&ev));
  ev.g_code_pass_obs = 0; assert(!code_durable_route(&ev)); ev.g_code_pass_obs = 1;
  ev.p_pass_obs = 0; assert(!code_durable_route(&ev)); ev.p_pass_obs = 1;
  ev.r_pass_obs = 0; assert(!code_durable_route(&ev)); ev.r_pass_obs = 1;
  ev.u_pass_obs = 1; assert(!code_durable_route(&ev)); ev.u_pass_obs = 0;
  ev.trial_hnb = 1; assert(!code_durable_route(&ev)); ev.trial_hnb = 2;
  last_trial_invocation_id--; assert(!code_durable_route(&ev)); last_trial_invocation_id++;
  last_trial_candidate_id++; assert(!code_durable_route(&ev)); last_trial_candidate_id--;
  last_trial_evidence_valid = 0; assert(!code_durable_route(&ev)); last_trial_evidence_valid = 1;
  q1_direct_service = 1; assert(!code_durable_route(&ev)); q1_direct_service = 0;

  /* The shared durable writer is transactional across raw/replay/map: a
   * missing replay directory must leave no raw file or committed novelty. */
  u8 map_before[MAP_SIZE]; memcpy(map_before, virgin_bits, MAP_SIZE);
  u8 old_changed = bitmap_changed; bitmap_changed = 0;
  memset(trace_bits, 0, MAP_SIZE); trace_bits[11] = 2;
  assert(!admission_promote_durable(candidate, sizeof(candidate) - 1));
  assert(memcmp(map_before, virgin_bits, MAP_SIZE) == 0 && !bitmap_changed);
  assert(queued_paths == 1); /* hit-count novelty is not durable evidence */
  memset(trace_bits, 0, MAP_SIZE); trace_bits[19] = 1;
  u64 old_gains = admission_gain_events;
  char missing[] = "/tmp/loopfuzz-durable-io-selftest-XXXXXX";
  assert(mkdtemp(missing));
  char missing_queue[PATH_MAX], failed_raw[PATH_MAX];
  snprintf(missing_queue, sizeof(missing_queue), "%s/queue", missing); make_dir(missing_queue);
  snprintf(failed_raw, sizeof(failed_raw), "%s/queue/id:%06u,llm-durable", missing, queued_paths);
  out_dir = (u8 *)missing;
  assert(!admission_promote_durable(candidate, sizeof(candidate) - 1));
  assert(memcmp(map_before, virgin_bits, MAP_SIZE) == 0 && !bitmap_changed);
  assert(access(failed_raw, F_OK) != 0 && queued_paths == 1);
  assert(admission_gain_events == old_gains && code_durable_admitted == durable_before + 1);
  /* First-file failure also leaves all feedback untouched. */
  assert(rmdir(missing_queue) == 0);
  assert(!admission_promote_durable(candidate, sizeof(candidate) - 1));
  assert(memcmp(map_before, virgin_bits, MAP_SIZE) == 0 && !bitmap_changed);
  bitmap_changed = old_changed;

  out_dir = (u8 *)dir;
  run_config_log("selftest", NULL);
  snprintf(event_path, sizeof(event_path), "%s/run-config.jsonl", dir);
  f = fopen(event_path, "r"); assert(f && fgets(line, sizeof(line), f)); fclose(f);
  j = json_tokener_parse(line);
  assert(j && json_object_object_get_ex(j, "code_durable", &value) && json_object_get_boolean(value));
  assert(json_object_object_get_ex(j, "code_durable_admitted", &value));
  assert((u64)json_object_get_int64(value) == code_durable_admitted);
  json_object_put(j);
  destroy_queue(); queue = queue_top = queue_cur = q_prev100 = NULL;
  delete_kl_messages(kl_messages); kl_messages = NULL;
  M2_prev = M2_next = NULL;
  extract_requests = NULL; extract_response_codes = NULL;
  code_durable_enabled = q1_reflow = 0;
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
  test_leave_one_out_counts_observed();
  test_trial_save_is_non_destructive();
  test_u_policy_semantics();
  test_ordinary_match_close_keeps_files();
  test_probe_does_not_consume_descendant_budget();
  test_select_service_ordinary_fallback();
  test_ordinary_edf_expiry_keeps_files();
  test_pipelined_span_binding();
  test_prov_prefix_protect_m2();
  test_state_retain_route();
  test_channel_accounting();
  test_conversion_classification();
  test_campaign_budget_cap();
  test_witness_tomb_expiry_move();
  test_q1_reflow_consumption();
  test_q1_direct_service_route();
  test_censor_frees_trial_evidence();
  test_opportunity_gate();
  test_code_durable_policy_and_witness_transaction();
  puts("gating contract selftest: PASS");
  return 0;
}
