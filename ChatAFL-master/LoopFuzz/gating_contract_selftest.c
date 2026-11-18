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
#include <sys/wait.h>

/* Config metadata only: the selftest never links or calls an LLM client. */
double llm_active_top_p(void) { return 1.0; }
int llm_active_max_tokens(void) { return 4096; }
long chat_llm_cap_calls(void) { return -1; }
long chat_llm_cap_tokens(void) { return -1; }

static u8 test_trace_value = 1;
static u8 stop_during_calibration = 0;
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
  if (stop_during_calibration) stop_soon = 1;
  return FAULT_NONE;
}

static void make_dir(const char *path) {
  if (mkdir(path, 0700) && errno != EEXIST) abort();
}

static void write_test_file(const char *path, const void *data, size_t len) {
  FILE *f = fopen(path, "wb");
  assert(f);
  assert(fwrite(data, 1, len, f) == len);
  assert(fclose(f) == 0);
}

static void assert_replay_seed(const char *path, const u8 *first,
                               u32 first_len, const u8 *second,
                               u32 second_len) {
  FILE *f = fopen(path, "rb");
  assert(f);
  u32 frame_len = 0;
  u8 payload[128];
  assert(fread(&frame_len, sizeof(frame_len), 1, f) == 1);
  assert(frame_len == first_len);
  assert(fread(payload, 1, frame_len, f) == frame_len);
  assert(memcmp(payload, first, first_len) == 0);
  assert(fread(&frame_len, sizeof(frame_len), 1, f) == 1);
  assert(frame_len == second_len);
  assert(fread(payload, 1, frame_len, f) == frame_len);
  assert(memcmp(payload, second, second_len) == 0);
  assert(fgetc(f) == EOF);
  assert(fclose(f) == 0);
}

static void test_initial_seed_replay_survives_interrupted_dry_run(void) {
  char root[] = "/tmp/loopfuzz-initial-replay-selftest-XXXXXX";
  assert(mkdtemp(root));
  u8 *input_dir = alloc_printf("%s/input", root);
  u8 *output_dir = alloc_printf("%s/output", root);
  u8 *queue_dir = alloc_printf("%s/queue", output_dir);
  u8 *replay_dir = alloc_printf("%s/replayable-queue", output_dir);
  u8 *input_a = alloc_printf("%s/seed-a", input_dir);
  u8 *input_b = alloc_printf("%s/seed-b", input_dir);
  make_dir((char *)input_dir); make_dir((char *)output_dir);
  make_dir((char *)queue_dir); make_dir((char *)replay_dir);

  static const u8 first_a[] = "USER a\r\n";
  static const u8 second_a[] = "PASS b\r\n";
  static const u8 first_b[] = "USER c\r\n";
  static const u8 second_b[] = "PASS d\r\n";
  static const u8 seed_a[] = "USER a\r\nPASS b\r\n";
  static const u8 seed_b[] = "USER c\r\nPASS d\r\n";
  write_test_file((char *)input_a, seed_a, sizeof(seed_a) - 1);
  write_test_file((char *)input_b, seed_b, sizeof(seed_b) - 1);

  struct queue_entry seeds[2];
  memset(seeds, 0, sizeof(seeds));
  seeds[0].fname = (u8 *)alloc_printf("%s", input_a);
  seeds[0].len = sizeof(seed_a) - 1;
  seeds[0].index = 0;
  seeds[0].regions = ck_alloc(2 * sizeof(region_t));
  seeds[0].region_count = 2;
  seeds[0].regions[0].start_byte = 0;
  seeds[0].regions[0].end_byte = sizeof(first_a) - 2;
  seeds[0].regions[1].start_byte = sizeof(first_a) - 1;
  seeds[0].regions[1].end_byte = seeds[0].len - 1;
  seeds[0].next = &seeds[1];
  seeds[1].fname = (u8 *)alloc_printf("%s", input_b);
  seeds[1].len = sizeof(seed_b) - 1;
  seeds[1].index = 1;
  seeds[1].regions = ck_alloc(2 * sizeof(region_t));
  seeds[1].region_count = 2;
  seeds[1].regions[0].start_byte = 0;
  seeds[1].regions[0].end_byte = sizeof(first_b) - 2;
  seeds[1].regions[1].start_byte = sizeof(first_b) - 1;
  seeds[1].regions[1].end_byte = seeds[1].len - 1;
  queue = &seeds[0];
  queue_top = &seeds[1];
  out_dir = output_dir;
  in_place_resume = 0;
  pivot_inputs();

  u8 *replay_a = alloc_printf("%s/%s", replay_dir,
                              basename((char *)seeds[0].fname));
  u8 *replay_b = alloc_printf("%s/%s", replay_dir,
                              basename((char *)seeds[1].fname));
  assert(seeds[0].is_initial_seed && seeds[1].is_initial_seed);
  assert(access(replay_a, F_OK) == 0 && access(replay_b, F_OK) == 0);
  struct stat source_before, queue_before;
  assert(stat((char *)input_a, &source_before) == 0);
  assert(stat((char *)seeds[0].fname, &queue_before) == 0);
  assert(source_before.st_dev == queue_before.st_dev &&
         source_before.st_ino == queue_before.st_ino);
  assert_replay_seed(replay_a, first_a, sizeof(first_a) - 1,
                     second_a, sizeof(second_a) - 1);
  assert_replay_seed(replay_b, first_b, sizeof(first_b) - 1,
                     second_b, sizeof(second_b) - 1);
  struct stat source_after, queue_after;
  assert(stat((char *)input_a, &source_after) == 0);
  assert(stat((char *)seeds[0].fname, &queue_after) == 0);
  assert(source_before.st_dev == source_after.st_dev &&
         source_before.st_ino == source_after.st_ino &&
         source_before.st_size == source_after.st_size &&
         queue_after.st_dev == source_after.st_dev &&
         queue_after.st_ino == source_after.st_ino);
  FILE *source = fopen((char *)input_a, "rb");
  u8 original[sizeof(seed_a)];
  assert(source && fread(original, 1, sizeof(seed_a) - 1, source) == sizeof(seed_a) - 1);
  assert(!memcmp(original, seed_a, sizeof(seed_a) - 1));
  assert(fgetc(source) == EOF && fclose(source) == 0);

  /* Empty seeds are excluded by read_testcases(); malformed/non-partitioning
   * parser output must fail closed without publishing a replay witness. */
  u8 *bad_input = alloc_printf("%s/bad-seed", input_dir);
  u8 *empty_input = alloc_printf("%s/empty-seed", input_dir);
  u8 *bad_replay = alloc_printf("%s/bad-seed", replay_dir);
  u8 *empty_replay = alloc_printf("%s/empty-seed", replay_dir);
  static const u8 malformed[] = "abcdef";
  write_test_file((char *)bad_input, malformed, sizeof(malformed) - 1);
  write_test_file((char *)empty_input, "", 0);
  region_t bad_region = {.start_byte = 1, .end_byte = sizeof(malformed) - 2};
  struct queue_entry bad_seed, empty_seed;
  memset(&bad_seed, 0, sizeof(bad_seed));
  bad_seed.fname = bad_input;
  bad_seed.len = sizeof(malformed) - 1;
  bad_seed.regions = &bad_region;
  bad_seed.region_count = 1;
  assert(!materialize_initial_seed_replay(&bad_seed));
  assert(access(bad_replay, F_OK) != 0);
  memset(&empty_seed, 0, sizeof(empty_seed));
  empty_seed.fname = empty_input;
  assert(!materialize_initial_seed_replay(&empty_seed));
  assert(access(empty_replay, F_OK) != 0);

  /* The first target execution aborts calibration. Both initial-seed
   * checkpoints and replay witnesses must already be published at that point. */
  u8 *checkpoints = alloc_printf("%s/queue-checkpoints.jsonl", output_dir);
  stop_soon = 0;
  stop_during_calibration = 1;
  dumb_mode = 1;
  no_forkserver = 1;
  cleanup_script = NULL;
  reset_completed_before_forkserver = 0;
  fast_cal = 1;
  state_aware_mode = 0;
  campaign_call_budget = campaign_charged_invocations = 0;
  mutation_call_budget = mutation_charged_calls = 0;
  llm_candidate_lineage_pin = cur_fuzz_lineage_candidate_id = 0;
  event_log_enabled = execution_log_enabled = 1;
  u64 execs_before_interrupt = total_execs;
  perform_dry_run(NULL);
  stop_during_calibration = 0;
  assert(stop_soon && total_execs == execs_before_interrupt + 1);
  assert(access(replay_a, F_OK) == 0 && access(replay_b, F_OK) == 0);
  assert_replay_seed(replay_a, first_a, sizeof(first_a) - 1,
                     second_a, sizeof(second_a) - 1);
  assert_replay_seed(replay_b, first_b, sizeof(first_b) - 1,
                     second_b, sizeof(second_b) - 1);

  FILE *f = fopen((char *)checkpoints, "r");
  assert(f);
  char line[1024];
  u32 initial_checkpoints = 0;
  while (fgets(line, sizeof(line), f))
    if (strstr(line, "initial-queue-name")) initial_checkpoints++;
  assert(fclose(f) == 0);
  assert(initial_checkpoints == 2);

  stop_soon = 0;
  queue = queue_top = queue_cur = q_prev100 = NULL;
  ck_free(seeds[0].fname); ck_free(seeds[1].fname);
  ck_free(seeds[0].regions); ck_free(seeds[1].regions);
  ck_free(checkpoints); ck_free(replay_a); ck_free(replay_b);
  ck_free(bad_replay); ck_free(empty_replay);
  ck_free(bad_input); ck_free(empty_input);
  ck_free(input_a); ck_free(input_b); ck_free(replay_dir);
  ck_free(queue_dir); ck_free(output_dir); ck_free(input_dir);
}

static void test_provisional_replay_is_published_before_discovery(void) {
  char root[] = "/tmp/loopfuzz-provisional-pair-selftest-XXXXXX";
  assert(mkdtemp(root));
  char queue_dir[PATH_MAX], replay_dir[PATH_MAX], staging_dir[PATH_MAX];
  char raw_path[PATH_MAX], replay_path[PATH_MAX], checkpoint_path[PATH_MAX];
  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", root);
  snprintf(replay_dir, sizeof(replay_dir), "%s/replayable-queue", root);
  snprintf(staging_dir, sizeof(staging_dir), "%s/.admission-staging", root);
  snprintf(checkpoint_path, sizeof(checkpoint_path),
           "%s/queue-checkpoints.jsonl", root);
#ifndef SIMPLE_FILES
  snprintf(raw_path, sizeof(raw_path), "%s/queue/id:%06u,prov", root, 0u);
#else
  snprintf(raw_path, sizeof(raw_path), "%s/queue/id_%06u_prov", root, 0u);
#endif
  snprintf(replay_path, sizeof(replay_path), "%s/replayable-queue/%s",
           root, strrchr(raw_path, '/') + 1);
  make_dir(queue_dir); make_dir(replay_dir);

  static const u8 first[] = "USER a\r\n";
  static const u8 second[] = "PASS b\r\n";
  klist_t(lms) *messages = kl_init(lms);
  message_t *m1 = ck_alloc(sizeof(*m1));
  m1->msize = sizeof(first) - 1;
  m1->mdata = (char *)ck_memdup((void *)first, m1->msize);
  *kl_pushp(lms, messages) = m1;
  message_t *m2 = ck_alloc(sizeof(*m2));
  m2->msize = sizeof(second) - 1;
  m2->mdata = (char *)ck_memdup((void *)second, m2->msize);
  *kl_pushp(lms, messages) = m2;

  u8 *old_out_dir = out_dir;
  klist_t(lms) *old_messages = kl_messages;
  struct queue_entry *old_queue = queue, *old_queue_top = queue_top;
  struct queue_entry *old_queue_cur = queue_cur, *old_q_prev100 = q_prev100;
  u32 old_queued_paths = queued_paths;
  u32 old_candidate_id = llm_cur_candidate_id;
  u64 old_invocation = target_invocation_seq;
  u32 old_messages_sent = messages_sent;
  u8 old_provisional = provisional_enabled;
  u8 old_event_log = event_log_enabled;
  u8 old_state_aware = state_aware_mode;
  region_t *(*old_extract_requests)(unsigned char *, unsigned int,
                                    unsigned int *) = extract_requests;

  out_dir = (u8 *)root;
  kl_messages = messages;
  queue = queue_top = queue_cur = q_prev100 = NULL;
  queued_paths = 0;
  llm_cur_candidate_id = 42;
  target_invocation_seq = 42;
  messages_sent = 2;
  provisional_enabled = 1;
  event_log_enabled = 1;
  state_aware_mode = 1;
  extract_requests = &extract_requests_ftp;
  admission_test_exit_after_replay_publish = 0;

  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    admission_test_exit_after_replay_publish = 1;
    (void)admission_provisional_queue_candidate_n(1, 42, "selftest", 0, 2);
    _exit(1);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child);
  pid_t replay_only_child = child;
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  assert(access(replay_path, F_OK) == 0);
  assert_replay_seed(replay_path, first, sizeof(first) - 1,
                     second, sizeof(second) - 1);
  assert(access(raw_path, F_OK) != 0);
  assert(access(checkpoint_path, F_OK) != 0);

  /* If the process stops after both final artifacts publish but before
   * queue insertion, strict archive replay must reject the uncommitted pair. */
  unlink(replay_path);
  admission_test_exit_after_replay_publish = 0;
  admission_test_exit_after_pair_publish = 0;
  child = fork();
  assert(child >= 0);
  if (child == 0) {
    admission_test_exit_after_pair_publish = 1;
    (void)admission_provisional_queue_candidate_n(1, 42, "selftest", 0, 2);
    _exit(1);
  }
  status = 0;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 78);
  assert(access(raw_path, F_OK) == 0);
  assert(access(replay_path, F_OK) == 0);
  assert(access(checkpoint_path, F_OK) != 0);

  /* A requested extent longer than the staged chain must fail before the
   * queue file or discovery checkpoint is created. */
  unlink(raw_path);
  unlink(replay_path);
  admission_test_exit_after_pair_publish = 0;
  assert(!admission_provisional_queue_candidate_n(1, 42, "selftest", 0, 3));
  assert(access(raw_path, F_OK) != 0);
  assert(access(replay_path, F_OK) != 0);
  assert(access(checkpoint_path, F_OK) != 0);

  u8 *staged_raw = alloc_printf("%s/%s-%ld-42.raw", staging_dir,
                                strrchr(raw_path, '/') + 1,
                                (long)replay_only_child);
  u8 *staged_raw_parent = alloc_printf("%s/%s-%ld-42.raw", staging_dir,
                                       strrchr(raw_path, '/') + 1,
                                       (long)getpid());
  u8 *staged_replay = alloc_printf("%s/%s-%ld-42.replay", staging_dir,
                                   strrchr(raw_path, '/') + 1, (long)getpid());
  assert(access((char *)staged_raw, F_OK) == 0);
  unlink((char *)staged_raw);
  assert(access((char *)staged_raw_parent, F_OK) != 0);
  assert(access((char *)staged_replay, F_OK) != 0);
  ck_free(staged_replay);
  ck_free(staged_raw_parent);
  ck_free(staged_raw);
  assert(rmdir(staging_dir) == 0);
  assert(rmdir(replay_dir) == 0);
  assert(rmdir(queue_dir) == 0);
  assert(rmdir(root) == 0);
  delete_kl_messages(messages);
  out_dir = old_out_dir;
  kl_messages = old_messages;
  queue = old_queue; queue_top = old_queue_top;
  queue_cur = old_queue_cur; q_prev100 = old_q_prev100;
  queued_paths = old_queued_paths;
  llm_cur_candidate_id = old_candidate_id;
  target_invocation_seq = old_invocation;
  messages_sent = old_messages_sent;
  provisional_enabled = old_provisional;
  event_log_enabled = old_event_log;
  state_aware_mode = old_state_aware;
  extract_requests = old_extract_requests;
  admission_test_exit_after_replay_publish = 0;
  admission_test_exit_after_pair_publish = 0;
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

static void test_replay_witness_extent_is_explicit(void) {
  char dir[] = "/tmp/loopfuzz-replay-extent-selftest-XXXXXX";
  assert(mkdtemp(dir));
  char corpus_path[PATH_MAX], replay_path[PATH_MAX];
  snprintf(corpus_path, sizeof(corpus_path), "%s/corpus", dir);
  snprintf(replay_path, sizeof(replay_path), "%s/replay", dir);

  klist_t(lms) *messages = kl_init(lms);
  const char *parts[] = {"A", "BC", "D"};
  const u32 sizes[] = {1, 2, 1};
  for (u32 i = 0; i < 3; i++) {
    message_t *m = ck_alloc(sizeof(*m));
    m->msize = (int)sizes[i];
    m->mdata = (char *)ck_memdup((void *)parts[i], sizes[i]);
    *kl_pushp(lms, messages) = m;
  }

  u32 saved_count = 0;
  assert(save_kl_message_pair(messages, (const u8 *)corpus_path,
                              (const u8 *)replay_path, KL_SAVE_FULL_CHAIN,
                              1, &saved_count) == 4);
  assert(saved_count == 3);
  FILE *f = fopen(corpus_path, "rb");
  char raw[8] = {0};
  assert(f && fread(raw, 1, sizeof(raw), f) == 4);
  assert(!memcmp(raw, "ABCD", 4) && fgetc(f) == EOF);
  fclose(f);
  f = fopen(replay_path, "rb");
  u32 frame_len = 0;
  assert(f && fread(&frame_len, sizeof(frame_len), 1, f) == 1 && frame_len == 1);
  assert(fread(raw, 1, 1, f) == 1 && raw[0] == 'A');
  assert(fread(&frame_len, sizeof(frame_len), 1, f) == 1 && frame_len == 2);
  assert(fread(raw, 1, 2, f) == 2 && !memcmp(raw, "BC", 2));
  assert(fread(&frame_len, sizeof(frame_len), 1, f) == 1 && frame_len == 1);
  assert(fread(raw, 1, 1, f) == 1 && raw[0] == 'D' && fgetc(f) == EOF);
  fclose(f);

  /* Prefix mode must save exactly the executed prefix and truncate any old
   * full-chain tail in both outputs. */
  saved_count = 0;
  assert(save_kl_message_pair(messages, (const u8 *)corpus_path,
                              (const u8 *)replay_path,
                              KL_SAVE_EXECUTED_PREFIX, 2,
                              &saved_count) == 3);
  assert(saved_count == 2);
  f = fopen(corpus_path, "rb");
  memset(raw, 0, sizeof(raw));
  assert(f && fread(raw, 1, sizeof(raw), f) == 3);
  assert(!memcmp(raw, "ABC", 3) && fgetc(f) == EOF);
  fclose(f);
  f = fopen(replay_path, "rb");
  assert(f && fread(&frame_len, sizeof(frame_len), 1, f) == 1 && frame_len == 1);
  assert(fread(raw, 1, 1, f) == 1 && raw[0] == 'A');
  assert(fread(&frame_len, sizeof(frame_len), 1, f) == 1 && frame_len == 2);
  assert(fread(raw, 1, 2, f) == 2 && !memcmp(raw, "BC", 2));
  assert(fgetc(f) == EOF);
  fclose(f);

  /* A zero executed prefix is not silently promoted to a full-chain replay. */
  saved_count = 99;
  assert(!save_kl_message_pair(messages, (const u8 *)corpus_path,
                               (const u8 *)replay_path,
                               KL_SAVE_EXECUTED_PREFIX, 0,
                               &saved_count));
  assert(saved_count == 0 && access(corpus_path, F_OK) != 0 &&
         access(replay_path, F_OK) != 0);

  delete_kl_messages(messages);
  rmdir(dir);
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
  u8 *old_out_dir = out_dir;
  u8 old_no_reflow = q1_no_reflow, old_reflow = q1_reflow;
  u8 old_event_log = event_log_enabled;
  u64 old_idle = q1_idle_total, old_saved = q1_saved_total;
  q1_no_reflow = 1; q1_reflow = 0;
  q1_idle_total = q1_saved_total = 0;
  event_log_enabled = 1;
  out_dir = (u8 *)dir;
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 5;
  root.is_provisional = 1;
  root.prov_ordinary_match = 1;
  root.prov_candidate_id = 55;
  root.prov_budget_left = 3;
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
  assert(root.prov_budget_left == 1 && root.prov_desc_execs == 2);
  assert(root.prov_desc_execs + root.prov_budget_left +
         root.prov_budget_released == 3);
  ordinary_match_close(&root, "selftest-partial-budget");
  assert(root.prov_expired && !root.is_provisional);
  assert(root.prov_budget_left == 0 && root.prov_budget_released == 1);
  assert(root.prov_desc_execs + root.prov_budget_left +
         root.prov_budget_released == 3);
  assert(q1_saved_total == 1 && q1_idle_total == 1);
  u64 closed_after_first_release = ordinary_match_closed;
  ordinary_match_close(&root, "selftest-repeat-close");
  assert(ordinary_match_closed == closed_after_first_release);
  assert(root.prov_budget_left == 0 && root.prov_budget_released == 1);
  assert(q1_saved_total == 1 && q1_idle_total == 1);
  char productivity_path[PATH_MAX], line[4096];
  snprintf(productivity_path, sizeof(productivity_path),
           "%s/productivity-events.jsonl", dir);
  FILE *productivity = fopen(productivity_path, "r");
  assert(productivity && fgets(line, sizeof(line), productivity));
  struct json_object *event = json_tokener_parse(line), *value = NULL;
  assert(event);
  assert(json_object_object_get_ex(event, "outcome", &value) &&
         !strcmp(json_object_get_string(value), "ordinary-close"));
  assert(json_object_object_get_ex(event, "descendant_invocations", &value) &&
         json_object_get_int(value) == 2);
  assert(json_object_object_get_ex(event, "budget_total", &value) &&
         json_object_get_int(value) == 3);
  assert(json_object_object_get_ex(event, "budget_left", &value) &&
         json_object_get_int(value) == 0);
  assert(json_object_object_get_ex(event, "budget_released", &value) &&
         json_object_get_int(value) == 1);
  json_object_put(event);
  assert(!fgets(line, sizeof(line), productivity));
  fclose(productivity);
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);
  assert(root.prov_expired && !root.is_provisional);
  assert(root.prov_trial_slots == NULL && !root.prov_trial_evidence_valid);
  assert(ordinary_match_closed == closed_before + 1);
  struct stat st;
  assert(stat((char *)root.fname, &st) == 0);   /* file retained, not unlinked */
  ck_free(root.fname);
  queue = queue_top = NULL;
  llm_candidate_lineage_pin = 0;
  q1_idle_total = old_idle; q1_saved_total = old_saved;
  q1_no_reflow = old_no_reflow; q1_reflow = old_reflow;
  event_log_enabled = old_event_log;
  out_dir = old_out_dir;
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

/* Salvage snapshots are independent controller probes. They remain part of
 * the campaign invocation dose while staying out of ordinary/lineage yield
 * denominators and every provisional-root quota, even when the current queue
 * item carries an expired lineage. */
static void test_salvage_probe_accounting(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 78;
  root.is_provisional = 1;
  root.prov_candidate_id = 77;
  root.prov_budget_left = 5;
  root.prov_deadline_ms = get_cur_time() + 60000;
  queue = queue_top = &root;

  const char *old_kind = execution_kind;
  u64 saved_pin = llm_candidate_lineage_pin;
  u64 saved_current = cur_fuzz_lineage_candidate_id;
  u64 saved_target = target_invocation_seq, saved_execs = total_execs;
  u64 saved_campaign_budget = campaign_call_budget;
  u64 saved_campaign_charged = campaign_charged_invocations;
  u64 saved_mutation_budget = mutation_call_budget;
  u64 saved_mutation_charged = mutation_charged_calls;
  u64 saved_controller = controller_probe_invocation_total;
  u64 saved_lineage = lineage_invocation_total, saved_ordinary = ord_invocation_total;
  u64 saved_prov_charged = prov_charged_total;
  u64 saved_idle = q1_idle_total;
  u8 saved_exhausted = campaign_budget_exhausted;
  u8 saved_reset = reset_completed_before_forkserver;
  u8 saved_log = event_log_enabled;

  campaign_call_budget = 3;
  campaign_charged_invocations = 0;
  campaign_budget_exhausted = 0;
  mutation_call_budget = 1;
  mutation_charged_calls = 1; /* already at the mutation-only limit */
  q1_idle_total = 0;
  controller_probe_invocation_total = 0;
  execution_kind = "salvage-probe";
  event_log_enabled = 0;
  llm_candidate_lineage_pin = 0;
  cur_fuzz_lineage_candidate_id = 77;
  reset_completed_before_forkserver = 1;

  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(target_invocation_seq == saved_target + 1 && total_execs == saved_execs + 1);
  assert(campaign_charged_invocations == 1);
  assert(controller_probe_invocation_total == 1);
  assert(lineage_invocation_total == saved_lineage);
  assert(ord_invocation_total == saved_ordinary);
  assert(prov_charged_total == saved_prov_charged);
  assert(root.prov_budget_left == 5 && root.prov_desc_execs == 0);
  assert(mutation_charged_calls == 1);

  /* Even a stale/empty parent lineage cannot block an independent probe. */
  root.prov_expired = 1;
  root.prov_budget_left = 0;
  root.prov_deadline_ms = 0;
  assert(run_target(NULL, 1) == FAULT_NONE);
  assert(target_invocation_seq == saved_target + 2);
  assert(campaign_charged_invocations == 2 &&
         controller_probe_invocation_total == 2);
  assert(lineage_invocation_total == saved_lineage &&
         ord_invocation_total == saved_ordinary);
  assert(prov_charged_total == saved_prov_charged && mutation_charged_calls == 1);

  /* An admitted probe is charged to the campaign cap; the next one is a
   * clean refusal and changes neither invocation nor dose counters. */
  assert(run_target(NULL, 1) == FAULT_NONE);
  u64 at_cap_invocations = target_invocation_seq;
  u64 at_cap_execs = total_execs;
  assert(campaign_charged_invocations == 3);
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);
  assert(campaign_budget_exhausted == 1);
  assert(target_invocation_seq == at_cap_invocations && total_execs == at_cap_execs);
  assert(campaign_charged_invocations == 3 && controller_probe_invocation_total == 3);

  execution_kind = old_kind;
  llm_candidate_lineage_pin = saved_pin;
  cur_fuzz_lineage_candidate_id = saved_current;
  target_invocation_seq = saved_target; total_execs = saved_execs;
  campaign_call_budget = saved_campaign_budget;
  campaign_charged_invocations = saved_campaign_charged;
  mutation_call_budget = saved_mutation_budget;
  mutation_charged_calls = saved_mutation_charged;
  controller_probe_invocation_total = saved_controller;
  lineage_invocation_total = saved_lineage; ord_invocation_total = saved_ordinary;
  prov_charged_total = saved_prov_charged;
  q1_idle_total = saved_idle;
  campaign_budget_exhausted = saved_exhausted;
  reset_completed_before_forkserver = saved_reset;
  event_log_enabled = saved_log;
  queue = queue_top = NULL;
}

/* Closing a productive root by conversion must account for its unused
 * validation quota in the Q1 parked budget and preserve the per-root identity
 * descendant calls + remaining + released = original allocation. */
static void test_conversion_releases_unused_validation_quota(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 991;
  root.is_provisional = 1;
  root.prov_candidate_id = 991;
  root.prov_desc_execs = 5;
  root.prov_budget_left = 7;
  root.prov_budget_released = 0;
  queue = queue_top = &root;

  u8 saved_no_reflow = q1_no_reflow, saved_reflow = q1_reflow;
  u64 saved_idle = q1_idle_total, saved_total = q1_saved_total;
  u64 saved_pool = q1_reflow_pool;
  u8 *saved_out_dir = out_dir;
  u8 saved_log = event_log_enabled;
  char dir[] = "/tmp/loopfuzz-quota-release-selftest-XXXXXX";
  assert(mkdtemp(dir));
  out_dir = (u8 *)dir;
  q1_no_reflow = 1;
  q1_reflow = 0;
  q1_idle_total = 0;
  q1_saved_total = 0;
  q1_reflow_pool = 0;
  event_log_enabled = 1;

  provisional_note_gain(991, 992, NULL, 0, 0, PROV_EVIDENCE_MUTATION_SAVE);
  assert(root.prov_converted && !root.is_provisional);
  assert(root.prov_desc_execs == 5 && root.prov_budget_left == 0 &&
         root.prov_budget_released == 7);
  assert(root.prov_desc_execs + root.prov_budget_left +
         root.prov_budget_released == 12);
  assert(q1_saved_total == 7 && q1_idle_total == 7);

  char flow_path[PATH_MAX];
  snprintf(flow_path, sizeof(flow_path), "%s/q1-budget-flow.jsonl", dir);
  FILE *flow = fopen(flow_path, "r");
  assert(flow);
  char line[4096];
  assert(fgets(line, sizeof(line), flow));
  struct json_object *event = json_tokener_parse(line), *value = NULL;
  assert(event);
  assert(json_object_object_get_ex(event, "kind", &value) &&
         !strcmp(json_object_get_string(value), "validation-converted-unused"));
  assert(json_object_object_get_ex(event, "destination", &value) &&
         !strcmp(json_object_get_string(value), "idle"));
  assert(json_object_object_get_ex(event, "candidate_id", &value) &&
         json_object_get_int64(value) == 991);
  assert(json_object_object_get_ex(event, "amount", &value) &&
         json_object_get_int64(value) == 7);
  json_object_put(event);
  assert(!fgets(line, sizeof(line), flow));
  fclose(flow);

  char productivity_path[PATH_MAX];
  snprintf(productivity_path, sizeof(productivity_path),
           "%s/productivity-events.jsonl", dir);
  FILE *productivity = fopen(productivity_path, "r");
  assert(productivity && fgets(line, sizeof(line), productivity));
  event = json_tokener_parse(line); assert(event);
  assert(json_object_object_get_ex(event, "outcome", &value) &&
         !strcmp(json_object_get_string(value), "convert"));
  assert(json_object_object_get_ex(event, "descendant_invocations", &value) &&
         json_object_get_int(value) == 5);
  assert(json_object_object_get_ex(event, "budget_total", &value) &&
         json_object_get_int(value) == 12);
  assert(json_object_object_get_ex(event, "budget_left", &value) &&
         json_object_get_int(value) == 0);
  assert(json_object_object_get_ex(event, "budget_released", &value) &&
         json_object_get_int(value) == 7);
  json_object_put(event);
  assert(!fgets(line, sizeof(line), productivity));
  fclose(productivity);

  /* A repeated lifecycle call cannot settle the same allocation twice. */
  provisional_release_unused_quota(&root, "selftest-repeat");
  assert(root.prov_budget_released == 7 && q1_saved_total == 7 &&
         q1_idle_total == 7);

  q1_no_reflow = saved_no_reflow; q1_reflow = saved_reflow;
  q1_idle_total = saved_idle; q1_saved_total = saved_total;
  q1_reflow_pool = saved_pool;
  event_log_enabled = saved_log;
  out_dir = saved_out_dir;
  queue = queue_top = NULL;
}

/* NO_REFLOW returns unused validation quota to the idle ledger. It reduces
 * the effective campaign cap and must preserve per-root budget conservation. */
static void test_closed_validation_quota_no_reflow(void) {
  struct queue_entry root = {0};
  u8 old_log = event_log_enabled, old_reflow = q1_reflow, old_idle_mode = q1_no_reflow;
  u8 *old_out = out_dir;
  u64 old_pool = q1_reflow_pool, old_idle = q1_idle_total, old_saved = q1_saved_total;
  u64 old_campaign_budget = campaign_call_budget;
  u64 old_provisional_live = provisional_live;
  u64 old_expired_total = provisional_expired_total;
  char dir[] = "/tmp/loopfuzz-no-reflow-quota-selftest-XXXXXX";
  assert(mkdtemp(dir));
  out_dir = (u8 *)dir;
  event_log_enabled = 1;
  q1_reflow = 0; q1_no_reflow = 1;
  q1_reflow_pool = 0; q1_idle_total = q1_saved_total = 0;
  campaign_call_budget = 100;
  root.index = 992; root.is_provisional = 1; root.prov_candidate_id = 992;
  root.prov_desc_execs = 4; root.prov_budget_left = 6;
  queue = queue_top = &root; provisional_live = 1;

  provisional_expire(&root, "no-reflow-unused-quota");
  assert(root.prov_expired && !root.is_provisional);
  assert(root.prov_desc_execs == 4 && root.prov_budget_left == 0 &&
         root.prov_budget_released == 6);
  assert(root.prov_desc_execs + root.prov_budget_left +
         root.prov_budget_released == 10);
  assert(q1_saved_total == 6 && q1_idle_total == 6 && q1_reflow_pool == 0);
  assert(campaign_effective_call_cap() == 94);
  provisional_expire(&root, "repeat-no-reflow-close");
  assert(q1_saved_total == 6 && q1_idle_total == 6 && root.prov_budget_released == 6);

  char line[4096], path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/productivity-events.jsonl", dir);
  FILE *f = fopen(path, "r"); assert(f && fgets(line, sizeof(line), f));
  struct json_object *event = json_tokener_parse(line), *value = NULL;
  assert(event);
  assert(json_object_object_get_ex(event, "budget_total", &value) &&
         json_object_get_int(value) == 10);
  assert(json_object_object_get_ex(event, "budget_left", &value) &&
         json_object_get_int(value) == 0);
  assert(json_object_object_get_ex(event, "budget_released", &value) &&
         json_object_get_int(value) == 6);
  json_object_put(event);
  assert(!fgets(line, sizeof(line), f)); fclose(f);

  snprintf(path, sizeof(path), "%s/q1-budget-flow.jsonl", dir);
  f = fopen(path, "r"); assert(f && fgets(line, sizeof(line), f));
  event = json_tokener_parse(line); assert(event);
  assert(json_object_object_get_ex(event, "kind", &value) &&
         !strcmp(json_object_get_string(value), "validation-closed-unused"));
  assert(json_object_object_get_ex(event, "destination", &value) &&
         !strcmp(json_object_get_string(value), "idle"));
  assert(json_object_object_get_ex(event, "amount", &value) &&
         json_object_get_int(value) == 6);
  assert(json_object_object_get_ex(event, "flow_id", &value) &&
         json_object_get_int64(value) == 0);
  json_object_put(event);
  assert(!fgets(line, sizeof(line), f)); fclose(f);

  q1_reflow = old_reflow; q1_no_reflow = old_idle_mode;
  q1_reflow_pool = old_pool; q1_idle_total = old_idle; q1_saved_total = old_saved;
  campaign_call_budget = old_campaign_budget;
  provisional_live = old_provisional_live; provisional_expired_total = old_expired_total;
  event_log_enabled = old_log; out_dir = old_out;
  queue = queue_top = NULL;
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
  char dir[] = "/tmp/loopfuzz-censor-quota-selftest-XXXXXX";
  assert(mkdtemp(dir));
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.is_provisional = 1;
  root.prov_candidate_id = 88;
  root.prov_budget_left = 64;
  root.prov_trial_slots = ck_alloc(HNB_SLOT_SET_BYTES);
  root.prov_trial_evidence_valid = 1;
  queue = queue_top = &root;
  u8 old_log = event_log_enabled, old_no_reflow = q1_no_reflow;
  u8 old_reflow = q1_reflow;
  u8 *old_out = out_dir;
  u64 saved_q1_total = q1_saved_total, saved_idle = q1_idle_total;
  u64 saved_pool = q1_reflow_pool, saved_budget = campaign_call_budget;
  u64 saved_live = provisional_live, saved_censored = provisional_censored;
  q1_no_reflow = 1; q1_reflow = 0;
  q1_saved_total = q1_idle_total = q1_reflow_pool = 0;
  campaign_call_budget = 100;
  provisional_live = 1;
  out_dir = (u8 *)dir;
  event_log_enabled = 1;
  u64 cap_before = campaign_effective_call_cap();
  provisional_censor_all_at_shutdown();
  assert(root.prov_expired && !root.is_provisional);
  assert(root.prov_budget_left == 64 && root.prov_budget_released == 0);
  assert(root.prov_desc_execs + root.prov_budget_left +
         root.prov_budget_released == 64);
  assert(q1_saved_total == 0 && q1_idle_total == 0); /* censor is not saved credit */
  assert(q1_reflow_pool == 0 && campaign_effective_call_cap() == cap_before);
  assert(provisional_censored == saved_censored + 1 && provisional_live == 0);
  assert(root.prov_trial_slots == NULL && !root.prov_trial_evidence_valid);

  char path[PATH_MAX], line[4096];
  snprintf(path, sizeof(path), "%s/productivity-events.jsonl", dir);
  FILE *f = fopen(path, "r"); assert(f && fgets(line, sizeof(line), f));
  struct json_object *event = json_tokener_parse(line), *value = NULL;
  assert(event);
  assert(json_object_object_get_ex(event, "outcome", &value) &&
         !strcmp(json_object_get_string(value), "censor"));
  assert(json_object_object_get_ex(event, "reason", &value) &&
         !strcmp(json_object_get_string(value), "campaign-end"));
  assert(json_object_object_get_ex(event, "censored", &value) &&
         json_object_get_boolean(value));
  assert(json_object_object_get_ex(event, "budget_total", &value) &&
         json_object_get_int(value) == 64);
  assert(json_object_object_get_ex(event, "budget_left", &value) &&
         json_object_get_int(value) == 64);
  assert(json_object_object_get_ex(event, "budget_released", &value) &&
         json_object_get_int(value) == 0);
  json_object_put(event);
  assert(!fgets(line, sizeof(line), f)); fclose(f);
  snprintf(path, sizeof(path), "%s/q1-budget-flow.jsonl", dir);
  assert(access(path, F_OK) != 0); /* censor leaves the quota unsettled */

  event_log_enabled = old_log;
  q1_no_reflow = old_no_reflow; q1_reflow = old_reflow;
  q1_saved_total = saved_q1_total; q1_idle_total = saved_idle;
  q1_reflow_pool = saved_pool; campaign_call_budget = saved_budget;
  provisional_live = saved_live; provisional_censored = saved_censored;
  out_dir = old_out;
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

/* P2 request gate: saturated window (>=2000 invocations, zero new edges)
 * skips; productive window does not; window boundary advances on eval. */
static void test_request_gate(void) {
  u8 saved_en = request_gate_enabled;
  u64 saved_seq = request_gate_window_seq, saved_g = request_gate_window_gains;
  u64 saved_skips = request_gate_skips, saved_cg = code_gain_events;
  u64 saved_inv = target_invocation_seq;
  u64 saved_states = request_gate_window_states, saved_ipsm = ipsm_new_edge_events;
  u8 saved_parked = request_gate_parked;
  u8 old_log = event_log_enabled; event_log_enabled = 0;
  request_gate_enabled = 1;
  request_gate_parked = 0;
  request_gate_window_states = ipsm_new_edge_events;

  target_invocation_seq = 1000; request_gate_window_seq = 0;
  request_gate_window_gains = code_gain_events;
  assert(request_gate_saturated() == 0);      /* window not elapsed */

  target_invocation_seq = 2500;               /* elapsed, ZERO gains */
  assert(request_gate_saturated() == 1);
  assert(request_gate_skips == saved_skips + 1);

  target_invocation_seq = 2501;
  assert(request_gate_saturated() == 1); /* next threshold=1 round stays parked */
  target_invocation_seq = 4500;
  assert(request_gate_saturated() == 0); /* bounded periodic consult */
  target_invocation_seq = 4501;
  assert(request_gate_saturated() == 1); /* periodic consult opens only one slot */
  ipsm_new_edge_events++;
  assert(request_gate_saturated() == 0); /* real state progress reopens immediately */
  assert(!request_gate_parked);

  target_invocation_seq = 5000; code_gain_events += 3;  /* productive */
  assert(request_gate_saturated() == 0);
  assert(request_gate_skips == saved_skips + 3);

  request_gate_enabled = saved_en;
  request_gate_window_seq = saved_seq; request_gate_window_gains = saved_g;
  request_gate_skips = saved_skips; code_gain_events = saved_cg;
  target_invocation_seq = saved_inv; event_log_enabled = old_log;
  request_gate_window_states = saved_states; ipsm_new_edge_events = saved_ipsm;
  request_gate_parked = saved_parked;
}

/* P3 early stop: K consecutive zero-novelty charged descendants close the
 * root; any novelty resets the streak; disabled knob is a no-op. */
static void test_pv_early_stop(void) {
  struct queue_entry root;
  memset(&root, 0, sizeof(root));
  root.index = 51; root.is_provisional = 1;
  root.prov_candidate_id = 55; root.prov_budget_left = 64;
  root.prov_deadline_ms = get_cur_time() + 60000;
  queue = queue_top = &root;
  u32 saved_k = pv_early_stop_k; u64 saved_stops = pv_early_stops;
  pv_early_stop_k = 4;

  cur_fuzz_provisional_root = &root;
  pv_early_stop_track(0); pv_early_stop_track(0);
  pv_early_stop_track(1);                  /* novelty resets */
  assert(root.prov_zero_novelty_streak == 0 && root.prov_expired == 0);
  pv_early_stop_track(0);
  root.prov_last_invocation_state_gain = 1;
  pv_early_stop_track(0);                  /* actual code-silent response novelty resets */
  assert(root.prov_zero_novelty_streak == 0 && !root.prov_expired);
  root.prov_last_invocation_state_gain = 0;
  pv_early_stop_track(0); pv_early_stop_track(0);
  pv_early_stop_track(0);
  assert(root.prov_expired == 0);           /* 3 < K */
  pv_early_stop_track(0);                   /* 4 == K -> early stop */
  assert(root.prov_expired == 1);
  assert(pv_early_stops == saved_stops + 1);

  pv_early_stop_k = 0;                      /* disabled: no-op on a fresh root */
  struct queue_entry root2;
  memset(&root2, 0, sizeof(root2));
  root2.is_provisional = 1; root2.prov_candidate_id = 56;
  root2.prov_budget_left = 64;
  root2.prov_deadline_ms = get_cur_time() + 60000;
  queue = &root2; queue_top = &root2;
  cur_fuzz_provisional_root = &root2;
  for (int i = 0; i < 10; i++) pv_early_stop_track(0);
  assert(root2.prov_expired == 0);

  pv_early_stop_k = saved_k; pv_early_stops = saved_stops;
  cur_fuzz_provisional_root = NULL;
  queue = queue_top = NULL;
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

/* Pure elapsed-time campaigns use the requested deadline rather than a
 * hidden target-call limit; unsupported quota parking fails explicitly. */
static void test_elapsed_time_campaign_without_call_cap(void) {
  u64 old_budget = campaign_call_budget, old_charged = campaign_charged_invocations;
  u64 old_mutation_budget = mutation_call_budget, old_duration = campaign_duration_sec;
  u64 old_start = run_start_time_ms, old_ord = ord_invocation_total;
  u8 old_wallclock = campaign_wallclock_mode, old_expired = campaign_wallclock_expired;
  u8 old_stop = stop_soon, old_exhausted = campaign_budget_exhausted;
  u8 old_no_reflow = q1_no_reflow, old_reflow = q1_reflow;
  u8 old_direct = q1_direct_service;
  const char *old_kind = execution_kind;

  campaign_wallclock_mode = 1;
  campaign_duration_sec = 86400;
  campaign_call_budget = mutation_call_budget = campaign_charged_invocations = 0;
  run_start_time_ms = get_cur_time();
  campaign_wallclock_expired = campaign_budget_exhausted = stop_soon = 0;
  q1_no_reflow = q1_reflow = q1_direct_service = 0;
  execution_kind = "mutation";

  assert(campaign_policy_error() == NULL);
  assert(!strcmp(campaign_resource_basis(), "elapsed-time"));
  assert(!campaign_deadline_reached());
  /* An uncapped time campaign must not silently inherit the old 5000-call
   * cutoff. This exercises the production admission point, not a formula. */
  for (u32 i = 0; i < 5001; i++) assert(execution_admit(NULL, 0));
  assert(campaign_charged_invocations == 5001);
  assert(!campaign_budget_exhausted && !campaign_wallclock_expired && !stop_soon);

  q1_reflow = 1;
  assert(campaign_policy_error() == NULL);
  q1_reflow = 0; q1_direct_service = 1;
  assert(campaign_policy_error() == NULL);
  q1_direct_service = 0; q1_no_reflow = 1;
  assert(campaign_policy_error() != NULL); /* no fictitious time parking */
  campaign_call_budget = 6000;
  assert(campaign_policy_error() == NULL);
  assert(!strcmp(campaign_resource_basis(), "elapsed-time-with-call-cap"));
  campaign_wallclock_mode = 0;
  assert(!strcmp(campaign_resource_basis(), "target-calls"));
  campaign_call_budget = 0;
  assert(campaign_policy_error() != NULL); /* old Q1 still needs a cap */
  q1_no_reflow = 0;
  campaign_wallclock_mode = 1;
  campaign_duration_sec = 0;
  assert(campaign_policy_error() != NULL);
  campaign_duration_sec = 1;
  mutation_call_budget = 1;
  assert(campaign_policy_error() != NULL);
  mutation_call_budget = 0;

  /* Simulate elapsed time; no real wait or gateway request is needed. */
  run_start_time_ms = get_cur_time() - 2000;
  u64 charged_before = campaign_charged_invocations, execs_before = total_execs;
  assert(campaign_deadline_reached());
  assert(campaign_wallclock_expired && stop_soon == 2);
  assert(!campaign_budget_exhausted);
  assert(!execution_admit(NULL, 0));
  assert(run_target(NULL, 1) == FAULT_RESOURCE_LIMIT);
  assert(campaign_charged_invocations == charged_before && total_execs == execs_before);

  campaign_call_budget = old_budget; campaign_charged_invocations = old_charged;
  mutation_call_budget = old_mutation_budget; campaign_duration_sec = old_duration;
  run_start_time_ms = old_start; ord_invocation_total = old_ord;
  campaign_wallclock_mode = old_wallclock; campaign_wallclock_expired = old_expired;
  stop_soon = old_stop; campaign_budget_exhausted = old_exhausted;
  q1_no_reflow = old_no_reflow; q1_reflow = old_reflow; q1_direct_service = old_direct;
  execution_kind = old_kind;
}

/* A late NO_REFLOW release may only park remaining campaign headroom. It
 * must never reduce the effective cap beneath target invocations already
 * charged, and the rejected excess must remain visible in the ledger. */
static void test_no_reflow_release_respects_charged_headroom(void) {
  u8 old_no_reflow = q1_no_reflow, old_reflow = q1_reflow;
  u64 old_budget = campaign_call_budget;
  u64 old_charged = campaign_charged_invocations;
  u64 old_idle = q1_idle_total, old_saved = q1_saved_total;
  u64 old_uncredited = q1_idle_uncredited_total;

  q1_no_reflow = 1; q1_reflow = 0;
  campaign_call_budget = 100;
  campaign_charged_invocations = 80;
  q1_idle_total = 0;
  q1_saved_total = 0;
  q1_idle_uncredited_total = 0;

  u64 credited = q1_release_validation_quota(995, 64, "selftest-late-release");
  assert(credited == 20);
  assert(q1_idle_total == 20 && q1_idle_uncredited_total == 44);
  assert(campaign_effective_call_cap() == 80);
  assert(campaign_charged_invocations <= campaign_effective_call_cap());
  assert(campaign_charged_invocations + q1_idle_total == campaign_call_budget);

  q1_no_reflow = old_no_reflow; q1_reflow = old_reflow;
  campaign_call_budget = old_budget;
  campaign_charged_invocations = old_charged;
  q1_idle_total = old_idle; q1_saved_total = old_saved;
  q1_idle_uncredited_total = old_uncredited;
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

static void test_closed_validation_quota_and_productivity(void) {
  struct queue_entry root = {0};
  u8 old_log = event_log_enabled, old_reflow = q1_reflow, old_idle = q1_no_reflow;
  u8 *old_out = out_dir;
  u64 old_pool = q1_reflow_pool, old_saved = q1_saved_total;
  u64 old_reflow_consumed = q1_reflow_consumed;
  u64 old_reflow_next_id = q1_reflow_next_id;
  q1_reflow_node_t *old_head = q1_reflow_head, *old_tail = q1_reflow_tail;
  char dir[] = "/tmp/loopfuzz-productivity-selftest-XXXXXX";
  assert(mkdtemp(dir)); out_dir = (u8 *)dir; event_log_enabled = 1;
  q1_reflow = 1; q1_no_reflow = 0; q1_reflow_pool = 0;
  q1_reflow_head = q1_reflow_tail = NULL;
  root.is_provisional = 1; root.prov_candidate_id = 991;
  root.prov_desc_execs = 32; root.prov_budget_left = 32;
  root.prov_baseline_saved_session = 1;
  root.prov_trial_evidence_valid = 1;
  root.prov_trial_slots = ck_alloc(HNB_SLOT_SET_BYTES);
  queue = queue_top = &root;
  provisional_expire(&root, "early-stop-no-novelty");
  assert(q1_reflow_pool == 32 && q1_saved_total == old_saved + 32);
  assert(root.prov_budget_left == 0 && root.prov_budget_released == 32);
  assert(root.prov_desc_execs + root.prov_budget_left +
         root.prov_budget_released == 64);
  assert(q1_reflow_head && q1_reflow_head->reservation.source_candidate_id == 991);
  provisional_expire(&root, "repeat-close");
  assert(q1_reflow_pool == 32 && q1_saved_total == old_saved + 32);
  char path[PATH_MAX], line[8192];
  snprintf(path, sizeof(path), "%s/productivity-events.jsonl", dir);
  FILE *f = fopen(path, "r"); assert(f && fgets(line, sizeof(line), f));
  assert(!fgets(line + strlen(line), sizeof(line) - strlen(line), f)); fclose(f);
  struct json_object *j = json_tokener_parse(line), *v;
  assert(j && json_object_object_get_ex(j, "baseline_valid", &v) && json_object_get_boolean(v));
  assert(json_object_object_get_ex(j, "descendant_invocations", &v) && json_object_get_int(v) == 32);
  assert(json_object_object_get_ex(j, "budget_total", &v) && json_object_get_int(v) == 64);
  assert(json_object_object_get_ex(j, "budget_left", &v) && json_object_get_int(v) == 0);
  assert(json_object_object_get_ex(j, "budget_released", &v) && json_object_get_int(v) == 32);
  assert(json_object_object_get_ex(j, "censored", &v) && !json_object_get_boolean(v));
  json_object_put(j);
  snprintf(path, sizeof(path), "%s/q1-budget-flow.jsonl", dir);
  f = fopen(path, "r"); assert(f && fgets(line, sizeof(line), f));
  assert(!fgets(line + strlen(line), sizeof(line) - strlen(line), f)); fclose(f);
  j = json_tokener_parse(line); assert(j);
  assert(json_object_object_get_ex(j, "kind", &v) &&
         !strcmp(json_object_get_string(v), "validation-closed-unused"));
  assert(json_object_object_get_ex(j, "destination", &v) &&
         !strcmp(json_object_get_string(v), "ordinary-pool"));
  assert(json_object_object_get_ex(j, "candidate_id", &v) &&
         json_object_get_int64(v) == 991);
  assert(json_object_object_get_ex(j, "amount", &v) &&
         json_object_get_int64(v) == 32);
  json_object_put(j);
  while (q1_reflow_head) {
    q1_reflow_node_t *next = q1_reflow_head->next; ck_free(q1_reflow_head); q1_reflow_head = next;
  }
  q1_reflow_head = old_head; q1_reflow_tail = old_tail;
  q1_reflow_pool = old_pool; q1_saved_total = old_saved;
  q1_reflow_consumed = old_reflow_consumed;
  q1_reflow_next_id = old_reflow_next_id;
  q1_reflow = old_reflow; q1_no_reflow = old_idle;
  out_dir = old_out; event_log_enabled = old_log; queue = queue_top = NULL;
}

static void test_salvage_probe_owns_baseline(void) {
  char *args[] = {"selftest", NULL};
  char **old_args = g_admission_argv;
  u8 old_log = event_log_enabled; event_log_enabled = 0;
  u8 map_before[MAP_SIZE]; memcpy(map_before, virgin_bits, MAP_SIZE);
  u64 old_cid = llm_cur_candidate_id, calls = target_invocation_seq;
  g_admission_argv = args; llm_cur_candidate_id = 993;
  salvage_snap_count = 2;
  for (u32 i = 0; i < 2; i++) {
    salvage_snap_size[i] = 6;
    salvage_snap_data[i] = ck_alloc(6);
    memcpy(salvage_snap_data[i], "NOOP\r\n", 6);
  }
  (void)salvage_probe_snapshot(); /* test transport replies to one message */
  assert(target_invocation_seq == calls + 1);
  assert(salvage_probe_evidence_valid && salvage_probe_candidate_id == 993);
  assert(salvage_probe_invocation_id == target_invocation_seq);
  assert(!memcmp(map_before, virgin_bits, MAP_SIZE)); /* no shared-map commit */
  /* Empty novelty is still a valid baseline. A later native new slot is
   * beyond that saved session rather than an unclassified conversion. */
  struct queue_entry root = {0};
  root.is_provisional = 1; root.prov_candidate_id = 993;
  root.prov_budget_left = 63; root.prov_desc_execs = 1;
  root.prov_baseline_saved_session = 1;
  root.prov_trial_evidence_valid = 1;
  root.prov_trial_candidate_id = 993;
  root.prov_trial_invocation_id = salvage_probe_invocation_id;
  root.prov_trial_slots = ck_alloc(HNB_SLOT_SET_BYTES);
  queue = queue_top = &root;
  u8 later_slots[HNB_SLOT_SET_BYTES] = {0}; test_set_map_slot(later_slots, 101);
  provisional_note_gain(993, 44, later_slots, 993,
                        salvage_probe_invocation_id + 1, PROV_EVIDENCE_MUTATION_SAVE);
  assert(root.prov_conv_class == 2 && root.prov_conv_beyond_trial_slot_count == 1);
  queue = queue_top = NULL;
  salvage_free_snapshot();
  g_admission_argv = old_args; llm_cur_candidate_id = old_cid; event_log_enabled = old_log;
}

static void test_ftp_salvage_preserves_candidate_prefix(void) {
  char *old_protocol = protocol_name;
  klist_t(lms) *old_messages = kl_messages;
  u32 old_first = candidate_message_first;
  u32 old_count = candidate_message_count;
  u32 old_clean_count = salvage_clean_count;
  u32 old_clean_idx[2] = {salvage_clean_window_idx[0],
                          salvage_clean_window_idx[1]};
  u8 old_override = full_session_m2_override;
  u8 old_prefix_protect = prov_prefix_protect;
  const char *input[] = {"USER ubuntu\r\n", "PASS ubuntu\r\n",
                         "TYPE I\r\n", "STAT\r\n", "PASV\r\n"};
  const u32 input_size[] = {13, 13, 8, 6, 6};

  salvage_free_snapshot();
  kl_messages = kl_init(lms);
  for (u32 i = 0; i < 5; i++) {
    message_t *m = ck_alloc(sizeof(*m));
    m->msize = input_size[i];
    m->mdata = (char *)ck_memdup(input[i], input_size[i]);
    *kl_pushp(lms, kl_messages) = m;
  }
  protocol_name = "FTP";
  candidate_message_first = 2;
  candidate_message_count = 3;
  salvage_clean_count = 2;
  salvage_clean_window_idx[0] = 0;
  salvage_clean_window_idx[1] = 2;

  salvage_take_snapshot();
  assert(salvage_snap_count == 4);
  assert(salvage_snap_prefix_count == 2);
  assert(salvage_snap_candidate_count == 2);
  assert(salvage_snap_size[0] == input_size[0] &&
         !memcmp(salvage_snap_data[0], input[0], input_size[0]));
  assert(salvage_snap_size[1] == input_size[1] &&
         !memcmp(salvage_snap_data[1], input[1], input_size[1]));
  assert(salvage_snap_size[2] == input_size[2] &&
         !memcmp(salvage_snap_data[2], input[2], input_size[2]));
  assert(salvage_snap_size[3] == input_size[4] &&
         !memcmp(salvage_snap_data[3], input[4], input_size[4]));

  struct queue_entry root;
  region_t regions[4];
  memset(&root, 0, sizeof(root));
  memset(regions, 0, sizeof(regions));
  root.is_provisional = 1;
  root.regions = regions;
  root.region_count = 4;
  salvage_set_candidate_window(&root);
  assert(root.prov_cand_first == 2 && root.prov_cand_count == 2);
  u32 start = 0, count = 0;
  full_session_m2_override = 1;
  prov_prefix_protect = 1;
  assert(entry_m2_range(&root, 0, &start, &count));
  assert(start == 2 && count == 2);
  salvage_snap_data[start][0] ^= 1; /* a candidate mutation cannot touch M1 */
  assert(!memcmp(salvage_snap_data[0], input[0], input_size[0]));
  assert(!memcmp(salvage_snap_data[1], input[1], input_size[1]));

  salvage_free_snapshot();
  delete_kl_messages(kl_messages);
  kl_messages = old_messages;
  protocol_name = old_protocol;
  candidate_message_first = old_first;
  candidate_message_count = old_count;
  salvage_clean_count = old_clean_count;
  salvage_clean_window_idx[0] = old_clean_idx[0];
  salvage_clean_window_idx[1] = old_clean_idx[1];
  full_session_m2_override = old_override;
  prov_prefix_protect = old_prefix_protect;
}

static void test_response_progress_without_native_save(void) {
  struct queue_entry root = {0}, other = {0};
  u32 old_k = pv_early_stop_k; u8 old_dual = pv_early_stop_dual;
  unsigned int *(*old_extract)(unsigned char *, unsigned int, unsigned int *) = extract_response_codes;
  char *old_response = response_buf; int old_size = response_buf_size;
  u64 old_response_id = response_invocation_id;
  pv_early_stop_k = 4; pv_early_stop_dual = 1;
  extract_response_codes = extract_response_codes_ftp;
  char first[] = "220 ready\r\n331 password required\r\n";
  response_buf = first; response_buf_size = sizeof(first) - 1;
  response_invocation_id = target_invocation_seq;
  u64 old_ipsm = ipsm_new_edge_events;
  assert(provisional_observe_response(&root));
  assert(!provisional_observe_response(&root)); /* same replies are no progress */
  assert(provisional_observe_response(&other)); /* separate root, no cross-root signal */
  char next[] = "220 ready\r\n230 logged in\r\n";
  response_buf = next; response_buf_size = sizeof(next) - 1;
  assert(provisional_observe_response(&root)); /* native coverage may remain silent */
  assert(ipsm_new_edge_events == old_ipsm); /* observation never writes scheduler IPSM */
  response_invocation_id--; assert(!provisional_observe_response(&root)); /* stale response rejected */
  provisional_free_trial_evidence(&root); provisional_free_trial_evidence(&other);
  assert(!root.prov_response_states && !root.prov_response_transitions);
  pv_early_stop_k = old_k; pv_early_stop_dual = old_dual;
  extract_response_codes = old_extract; response_buf = old_response; response_buf_size = old_size;
  response_invocation_id = old_response_id;
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
  char event_path[PATH_MAX], line[16384];
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
  assert(json_object_object_get_ex(j, "campaign_resource_basis", &value));
  assert(!strcmp(json_object_get_string(value), campaign_resource_basis()));
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
  test_replay_witness_extent_is_explicit();
  test_response_capture_is_frozen();
  test_decision_logs_trial_mode_snapshot();
  test_leave_one_out_counts_observed();
  test_trial_save_is_non_destructive();
  test_u_policy_semantics();
  test_ordinary_match_close_keeps_files();
  test_probe_does_not_consume_descendant_budget();
  test_salvage_probe_accounting();
  test_conversion_releases_unused_validation_quota();
  test_select_service_ordinary_fallback();
  test_ordinary_edf_expiry_keeps_files();
  test_pipelined_span_binding();
  test_prov_prefix_protect_m2();
  test_state_retain_route();
  test_channel_accounting();
  test_conversion_classification();
  test_campaign_budget_cap();
  test_elapsed_time_campaign_without_call_cap();
  test_no_reflow_release_respects_charged_headroom();
  test_witness_tomb_expiry_move();
  test_request_gate();
  test_pv_early_stop();
  test_q1_reflow_consumption();
  test_closed_validation_quota_and_productivity();
  test_closed_validation_quota_no_reflow();
  test_ftp_salvage_preserves_candidate_prefix();
  test_salvage_probe_owns_baseline();
  test_response_progress_without_native_save();
  test_q1_direct_service_route();
  test_censor_frees_trial_evidence();
  test_opportunity_gate();
  test_code_durable_policy_and_witness_transaction();
  test_initial_seed_replay_survives_interrupted_dry_run();
  test_provisional_replay_is_published_before_discovery();
  puts("gating contract selftest: PASS");
  return 0;
}
