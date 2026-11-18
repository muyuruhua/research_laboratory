/* Real scheduler/state/M2 code, with unused fuzzer paths removed by section GC. */
#define AFL_LIB 1
#ifndef BIN_PATH
#define BIN_PATH "/usr/local/bin"
#endif
#include "afl-fuzz.c"
#include "evidence-cal.c"
#include <assert.h>

/* Protocol classification is outside this test's state-identity contract. */
u8 classify_state_error_hint(unsigned int state_id, const char *protocol) {
  (void)protocol;
  return state_id >= 400;
}

static void test_cumulative_weights(void) {
  u64 sums[] = {2, 5, 10};
  u32 counts[3] = {0};
  for (u64 draw = 0; draw < 10; draw++) counts[index_search(sums, 3, draw)]++;
  assert(counts[0] == 2 && counts[1] == 3 && counts[2] == 5);
  u64 leading_zero[] = {0, 3, 8}, internal_zero[] = {2, 2, 7};
  for (u64 draw = 0; draw < 8; draw++) assert(index_search(leading_zero, 3, draw) > 0);
  for (u64 draw = 0; draw < 7; draw++) assert(index_search(internal_zero, 3, draw) != 1);
  u64 large[] = {0xffffffffULL, 0x1fffffffeULL};
  assert(index_search(large, 2, 0xffffffffULL) == 1);
  assert(index_search(large, 2, 0x1fffffffdULL) == 1);
  assert(index_search(sums, 3, 10) == 3);
  assert(index_search(NULL, 0, 0) == 0);
}

/* P0-10 completion: joint statistical test of the production pipeline
 * scheduler_draw_below(total) -> index_search(cum, n, draw), i.e. exactly
 * what the weighted-selection path executes per selection.  3,000,000
 * draws over weights {2,3,5}: expected proportions 0.2/0.3/0.5; at this n
 * the 4-sigma binomial band is ~0.5% of each expectation, so a 1.5%
 * relative tolerance rejects the bias the old >= boundary produced
 * ((2,3,5)->(3,3,4)) while tolerating healthy randomness. */
static void test_joint_weighted_sampling(void) {
  u64 sums[] = {2, 5, 10};
  u64 total = 10;
  double expect[3] = {0.2, 0.3, 0.5};
  u64 counts[3] = {0, 0, 0};
  const u32 N = 3000000;
  ec_rng_seed(0xD15EA5EEDULL);
  for (u32 i = 0; i < N; i++) {
    u64 draw = scheduler_draw_below(total);
    assert(draw < total);
    u32 idx = index_search(sums, 3, draw);
    assert(idx < 3);
    counts[idx]++;
  }
  for (u32 b = 0; b < 3; b++) {
    double rel = (double)counts[b] / ((double)N * expect[b]) - 1.0;
    if (rel < 0) rel = -rel;
    assert(rel < 0.015);
  }
  /* Zero-weight buckets stay structurally unreachable through the same
   * pipeline, and the surviving buckets keep their 4:6 ratio. */
  u64 zw[] = {0, 4, 4, 10};
  u64 zw_counts[4] = {0, 0, 0, 0};
  for (u32 i = 0; i < 200000; i++) {
    u64 draw = scheduler_draw_below(10);
    u32 idx = index_search(zw, 4, draw);
    assert(idx == 1 || idx == 3);
    zw_counts[idx]++;
  }
  assert(zw_counts[0] == 0 && zw_counts[2] == 0);
  assert(zw_counts[1] > 70000 && zw_counts[1] < 90000);
}

static void test_bounded_rng(void) {
  uint64_t out = 7;
  assert(!ec_rng_below(0, &out) && out == 7);
  assert(!ec_rng_below(10, NULL));
  for (int i = 0; i < 20; i++) assert(ec_rng_below(1, &out) && out == 0);
  uint64_t bound = (1ULL << 63) + 1, seed, raw = 0, expected = 0;
  unsigned rejected = 0;
  for (seed = 1; seed < 100; seed++) {
    ec_rng_seed(seed);
    rejected = 0;
    do { raw = ec_rng_next(); if (raw < (uint64_t)(-bound) % bound) rejected++; }
    while (raw < (uint64_t)(-bound) % bound);
    if (rejected) { expected = raw % bound; break; }
  }
  assert(rejected && seed < 100);
  ec_rng_seed(seed);
  assert(ec_rng_below(bound, &out) && out == expected && out < bound);
  ec_rng_seed(123);
  u32 buckets[10] = {0};
  for (u32 i = 0; i < 100000; i++) {
    assert(ec_rng_below(10, &out) && out < 10);
    buckets[out]++;
  }
  for (u32 i = 0; i < 10; i++) assert(buckets[i] > 9500 && buckets[i] < 10500);
  u8 high_bits_seen = 0;
  for (u32 i = 0; i < 100; i++) {
    assert(ec_rng_below(UINT64_MAX, &out) && out < UINT64_MAX);
    high_bits_seen |= out > 0xffffffffULL;
  }
  assert(high_bits_seen);
}

static void test_m2_and_queue_contract(void) {
  u32 a = 220, b = 230;
  region_t regions[3] = {{.state_count=1,.state_sequence=&a},
                         {.state_count=1,.state_sequence=&b},
                         {.state_count=1,.state_sequence=&b}};
  struct queue_entry q = {.regions=regions,.region_count=2};
  u32 start = 99, count = 99;
  assert(!entry_can_fuzz_state(&q, b));
  assert(entry_m2_range(&q, a, &start, &count) && start == 1 && count == 1);
  assert(entry_last_annotated_state(&q) == a);
  assert(!entry_can_fuzz_state(&q, 999));
  q.region_count = 3;
  assert(entry_m2_range(&q, b, &start, &count) && start == 2 && count == 1);
  assert(entry_last_annotated_state(&q) == b);
  regions[1].state_count = 0;
  assert(entry_m2_range(&q, a, &start, &count) && start == 1 && count == 1);
  q.region_count = 1;
  assert(!entry_can_fuzz_state(&q, a));
  assert(entry_last_annotated_state(&q) == 0);
  assert(entry_m2_range(&q, 0, &start, &count) && start == 0 && count == 1);
  struct queue_entry expired = {.regions=regions,.region_count=1,.prov_expired=1};
  struct queue_entry empty = {.region_count=0};
  expired.next = &empty; empty.next = &q; queue = &expired;
  assert(next_executable_entry(&q) == &q);
  assert(next_executable_entry(&expired) == &q);
  assert(next_executable_entry(NULL) == &q);
  q.prov_expired = 1;
  assert(!next_executable_entry(NULL) && !next_executable_entry(&q));
  assert(entry_last_annotated_state(&q) == SCHEDULER_NO_STATE);
  assert(!entry_can_fuzz_state(NULL, 0));
  assert(!entry_can_fuzz_state(&empty, 0));
  queue = NULL;
}

/* Exercise the production episode accounting and posterior update.  A
 * trial between two ordinary mutations must not discard the first
 * mutation's reward; full-session candidate validation must never train a
 * prefix-state posterior.  Nested execution labels require an explicit
 * ordinary parent and are not accepted merely because their kind matches. */
static void test_episode_attribution(state_info_t *st, u32 sid) {
  u8 old_log = event_log_enabled;
  event_log_enabled = 0;
  target_state_id = sid;
  full_session_m2_override = 0;
  scheduler_selection_reason = "weighted-eligible";
  double alpha = st->cal_alpha, beta = st->cal_beta;
  u32 episodes = st->cal_episodes;
  u64 pooled = cal_run_episode_updates;
  cal_episode_begin(sid);
  cal_episode_note_invocation("mutation");
  cal_episode_note_code_gain();
  cal_episode_note_state_gain();
  cal_nested_mutation_context = 1;
  cal_episode_note_invocation("calibration");
  cal_episode_note_invocation("hang-retry");
  cal_nested_mutation_context = 0;
  cal_episode_note_invocation("candidate");
  cal_episode_note_code_gain();
  cal_episode_note_state_gain();
  admission_trial_mode = 1;
  cal_episode_note_invocation("shadow");
  cal_episode_note_invocation("mutation"); /* trial cannot spoof ordinary work */
  admission_trial_mode = 0;
  cal_episode_note_invocation("prov-annotate");
  cal_episode_note_invocation("salvage-probe");
  cal_episode_note_invocation("calibration"); /* no ordinary parent */
  cal_episode_note_invocation("hang-retry");
  cal_episode_note_invocation("mutation");
  assert(cal_episode_total_invocations == 11);
  assert(cal_episode_training_invocations == 4);
  assert(cal_episode_mutation_invocations == 2 && cal_episode_nested_invocations == 2);
  assert(cal_episode_code_gains == 1 && cal_episode_state_gains == 1);
  assert(cal_episode_all_code_gains == 2 && cal_episode_all_state_gains == 2);
  cal_episode_finalize(0);
  assert(st->cal_episodes == episodes + 1 && cal_run_episode_updates == pooled + 1);
  assert(fabs(st->cal_alpha - (1.0 + cal_gamma * (alpha - 1.0) + 1.0)) < 1e-12);
  assert(fabs(st->cal_beta - (1.0 + cal_gamma * (beta - 1.0))) < 1e-12);

  alpha = st->cal_alpha; beta = st->cal_beta; episodes = st->cal_episodes;
  pooled = cal_run_episode_updates;
  /* Each exclusion is independently sufficient: a future change to one
   * guard must not be hidden by the other guard in the same test. */
  full_session_m2_override = 1;
  scheduler_selection_reason = "weighted-eligible";
  cal_episode_begin(sid);
  cal_episode_note_invocation("mutation");
  cal_episode_note_code_gain();
  cal_nested_mutation_context = 1;
  cal_episode_note_invocation("calibration");
  cal_nested_mutation_context = 0;
  assert(!cal_episode_train_eligible && cal_episode_total_invocations == 2);
  assert(!cal_episode_training_invocations && !cal_episode_code_gains);
  cal_episode_finalize(0);
  assert(st->cal_alpha == alpha && st->cal_beta == beta);
  assert(st->cal_episodes == episodes && cal_run_episode_updates == pooled);

  full_session_m2_override = 0;
  scheduler_selection_reason = "forced-provisional-candidate";
  cal_episode_begin(sid);
  cal_episode_note_invocation("mutation");
  cal_episode_note_code_gain();
  assert(!cal_episode_train_eligible && cal_episode_total_invocations == 1);
  assert(!cal_episode_training_invocations && !cal_episode_code_gains);
  cal_episode_finalize(0);
  assert(st->cal_alpha == alpha && st->cal_beta == beta);
  assert(st->cal_episodes == episodes && cal_run_episode_updates == pooled);

  /* Interrupted or state-redirected episodes cannot fabricate a reward. */
  full_session_m2_override = 0;
  scheduler_selection_reason = "warmup-eligible";
  cal_episode_begin(sid);
  cal_episode_note_invocation("mutation");
  cal_episode_note_code_gain();
  cal_episode_finalize(1);
  assert(st->cal_episodes == episodes && st->cal_alpha == alpha && st->cal_beta == beta);
  cal_episode_begin(sid);
  target_state_id = sid + 1;
  cal_episode_note_invocation("mutation");
  cal_episode_note_code_gain();
  assert(cal_episode_total_invocations == 1 && !cal_episode_training_invocations);
  cal_episode_finalize(0);
  assert(st->cal_episodes == episodes && cal_run_episode_updates == pooled);
  target_state_id = sid;
  event_log_enabled = old_log;
}

/* Exercise the same real-map observation used by calibrate_case.  A
 * repeated input may first expose a code edge during inline calibration:
 * the map consumes it exactly once and its ordinary parent earns reward.
 * A new hit-count bucket alone, or controller-only calibration, cannot
 * create a positive training example. */
static void test_fixed_dose_calibration(state_info_t *st, u32 sid) {
  u8 old_log = event_log_enabled;
  u32 old_window = cal_reward_window_invocations;
  state_info_t saved = *st;
  event_log_enabled = 0;
  cal_reward_window_invocations = 4;
  target_state_id = sid;
  full_session_m2_override = admission_trial_mode = 0;
  scheduler_selection_reason = "weighted-eligible";
  st->cal_alpha = st->cal_beta = 1.0;
  st->cal_ewma = 0.5;
  st->cal_episodes = st->cal_episode_rewards = 0;
  u64 windows = cal_training_windows, rewarded = cal_training_windows_rewarded;
  u64 censored = cal_training_censored_invocations;

  cal_episode_begin(sid);
  cal_episode_note_invocation("mutation");
  cal_nested_mutation_context = 1;
  cal_episode_note_invocation("calibration");
  cal_nested_mutation_context = 0;
  /* Controller gains cannot contaminate this otherwise unproductive
   * fixed-dose window, even when their code executes between mutations. */
  cal_episode_note_invocation("candidate"); cal_episode_note_code_gain();
  cal_episode_note_invocation("shadow"); cal_episode_note_code_gain();
  admission_trial_mode = 1;
  cal_episode_note_invocation("mutation"); cal_episode_note_code_gain();
  admission_trial_mode = 0;
  cal_episode_note_invocation("mutation");
  cal_episode_note_invocation("mutation");
  assert(st->cal_episodes == 0); /* fourth gain observation not closed yet */
  cal_episode_note_invocation("mutation"); /* closes the four real calls */
  assert(st->cal_episodes == 1 && st->cal_episode_rewards == 0);
  assert(st->cal_alpha == 1.0 && st->cal_beta == 2.0);
  /* Three more eligible calls complete a second window.  A gain exactly
   * on its last invocation belongs to this window, not the next one. */
  for (u32 i = 0; i < 3; i++) cal_episode_note_invocation("mutation");
  cal_episode_note_code_gain();
  cal_episode_finalize(0);
  assert(st->cal_episodes == 2 && st->cal_episode_rewards == 1);
  assert(fabs(st->cal_alpha - 2.0) < 1e-12);
  assert(fabs(st->cal_beta - (1.0 + cal_gamma)) < 1e-12);
  assert(cal_training_windows == windows + 2 &&
         cal_training_windows_rewarded == rewarded + 1);
  assert(cal_training_censored_invocations == censored);
  assert(cal_training_window.completed_windows == 2 &&
         cal_training_window.rewarded_windows == 1);
  assert(fabs(st->cal_ewma - ec_ewma_step(ec_ewma_step(0.5, cal_ewma_alpha, 0),
                                      cal_ewma_alpha, 1)) < 1e-12);

  double alpha = st->cal_alpha, beta = st->cal_beta;
  cal_episode_begin(sid);
  for (u32 i = 0; i < 3; i++) cal_episode_note_invocation("mutation");
  cal_episode_note_code_gain();
  cal_episode_finalize(0);
  assert(st->cal_episodes == 2 && st->cal_alpha == alpha && st->cal_beta == beta);
  assert(cal_training_censored_invocations == censored + 3);
  /* Full-session PV service cannot train a response-state posterior. */
  full_session_m2_override = 1;
  cal_episode_begin(sid);
  for (u32 i = 0; i < 8; i++) {
    cal_episode_note_invocation("mutation"); cal_episode_note_code_gain();
  }
  cal_episode_finalize(0);
  assert(st->cal_episodes == 2 && st->cal_alpha == alpha && st->cal_beta == beta);
  full_session_m2_override = 0;
  cal_episode_begin(sid);
  for (u32 i = 0; i < 4; i++) cal_episode_note_invocation("mutation");
  cal_episode_finalize(1);
  assert(st->cal_episodes == 2 && st->cal_alpha == alpha && st->cal_beta == beta);
  assert(cal_training_censored_invocations == censored + 7);
  *st = saved;
  cal_reward_window_invocations = old_window;
  event_log_enabled = old_log;
}

static void test_inline_calibration_reward(state_info_t *st, u32 sid) {
  u8 old_log = event_log_enabled;
  u8 *old_trace = trace_bits;
  u8 saved_virgin[MAP_SIZE];
  memcpy(saved_virgin, virgin_bits, MAP_SIZE);
  trace_bits = ck_alloc(MAP_SIZE);
  memset(virgin_bits, 0xff, MAP_SIZE);
  event_log_enabled = 0;
  full_session_m2_override = 0;
  scheduler_selection_reason = "weighted-eligible";
  target_state_id = sid;
  u32 episodes = st->cal_episodes;
  u64 rewarded = st->cal_episode_rewards;

  cal_episode_begin(sid);
  cal_episode_note_invocation("mutation");
  /* A previously seen edge with a fresh hit-count bucket is hnb==1. */
  virgin_bits[0] = 0xfe;
  trace_bits[0] = 2;
  cal_nested_mutation_context = 1;
  cal_episode_note_invocation("calibration");
  assert(calibration_consume_new_bits(0) == 1);
  assert(!cal_episode_code_gains);
  /* The next stability iteration discovers an actually unseen edge. */
  trace_bits[1] = 1;
  cal_episode_note_invocation("calibration");
  assert(calibration_consume_new_bits(0) == 2);
  assert(cal_episode_code_gains == 1 && cal_episode_all_code_gains == 1);
  assert(calibration_consume_new_bits(0) == 0);
  assert(cal_episode_code_gains == 1);
  cal_nested_mutation_context = 0;
  cal_episode_finalize(0);
  assert(st->cal_episodes == episodes + 1 && st->cal_episode_rewards == rewarded + 1);

  episodes = st->cal_episodes;
  rewarded = st->cal_episode_rewards;
  cal_episode_begin(sid);
  cal_episode_note_invocation("candidate");
  cal_episode_note_invocation("calibration"); /* no ordinary parent */
  trace_bits[2] = 1;
  assert(calibration_consume_new_bits(0) == 2);
  assert(!cal_episode_training_invocations && !cal_episode_code_gains);
  assert(cal_episode_all_code_gains == 1);
  cal_episode_finalize(0);
  assert(st->cal_episodes == episodes && st->cal_episode_rewards == rewarded);

  ck_free(trace_bits);
  trace_bits = old_trace;
  memcpy(virgin_bits, saved_virgin, MAP_SIZE);
  event_log_enabled = old_log;
}

/* All Q3 scorers must see exactly the same Frontier(s), including fixed
 * error and low-productivity penalties.  This detects a hidden policy
 * replacement when calibration_enabled is toggled. */
static void test_q3_shared_frontier(state_info_t *a, state_info_t *b) {
  state_info_t saved_a = *a, saved_b = *b;
  u8 old_frontier = ablation_no_frontier;
  ablation_no_frontier = 0;
  calibration_enabled = 0;
  a->fuzzs = b->fuzzs = 0;
  a->paths_discovered = b->paths_discovered = 0;
  a->selected_times = b->selected_times = 30;
  a->productivity = b->productivity = 0;
  a->error_hint = b->error_hint = 2;
  update_scores_and_select_next_state(FAVOR);
  double unpenalized_a = a->last_frontier_score;
  double unpenalized_b = b->last_frontier_score;
  a->error_hint = 1;
  b->error_hint = 0;
  update_scores_and_select_next_state(FAVOR);
  double fixed_a = a->last_frontier_score;
  double fixed_b = b->last_frontier_score;
  assert(fabs(fixed_a - 0.5 * unpenalized_a) < 1e-9);
  assert(fabs(fixed_b - 0.7 * unpenalized_b) < 1e-9);
  calibration_enabled = 1;
  for (u8 estimator = 0; estimator < 4; estimator++) {
    cal_estimator = estimator;
    update_scores_and_select_next_state(FAVOR);
    assert(a->last_frontier_score == fixed_a);
    assert(b->last_frontier_score == fixed_b);
  }
  *a = saved_a;
  *b = saved_b;
  ablation_no_frontier = old_frontier;
  calibration_enabled = 0;
  cal_estimator = 0;
}

static void test_registration_and_scheduler(void) {
  setup_ipsm();
  expand_was_fuzzed_map(1, 1);
  state_info_t *initial = register_state(0);
  assert(state_ids_count == 1 && fuzzed_map_states == 1);
  state_info_t *state = register_state(431);
  struct queue_entry historical_seed = {0};
  state->seeds = ck_alloc(sizeof(void *)); state->seeds[0] = &historical_seed;
  state->seeds_count = 1; state->cal_alpha = 1.995; state->cal_beta = 2.990025;
  state->selected_times = 3; state->cal_episodes = 3;
  assert(!agnode(ipsm, "431", FALSE));
  agnode(ipsm, "431", TRUE);
  assert(register_state(431) == state);
  assert(state_ids_count == 2 && fuzzed_map_states == 2);
  assert(state->cal_alpha == 1.995 && state->cal_beta == 2.990025);
  assert(state->selected_times == 3 && state->cal_episodes == 3);
  assert(state->seeds_count == 1 && state->seeds[0] == &historical_seed);
  assert(register_state(0) == initial && state_ids_count == 2);

  u32 a = 220, b = 230;
  region_t regions[2] = {{.state_count=1,.state_sequence=&a},
                         {.state_count=1,.state_sequence=&b}};
  struct queue_entry valid = {.regions=regions,.region_count=2,.generating_state_id=220};
  struct queue_entry terminal = {.regions=regions,.region_count=1};
  struct queue_entry expired = {.regions=regions,.region_count=2,.prov_expired=1};
  state_info_t *reachable = register_state(a), *dead_end = register_state(b);
  void *pool[] = {&expired, &terminal, &valid};
  initial->seeds = ck_alloc(sizeof(void *)); initial->seeds[0] = &valid; initial->seeds_count = 1;
  reachable->seeds = ck_alloc(sizeof(pool)); memcpy(reachable->seeds, pool, sizeof(pool));
  reachable->seeds_count = 3;
  dead_end->seeds = ck_alloc(sizeof(void *)); dead_end->seeds[0] = &valid; dead_end->seeds_count = 1;
  for (u8 mode = RANDOM_SELECTION; mode <= FAVOR; mode++) {
    reachable->selected_seed_index = 0;
    for (u32 i = 0; i < 50; i++) assert(choose_seed(a, mode) == &valid);
    assert(!choose_seed(b, mode));
  }
  ck_free(reachable->seeds);
  reachable->seeds = ck_alloc(12 * sizeof(void *));
  reachable->seeds_count = 12;
  for (u32 i = 0; i < 11; i++) reachable->seeds[i] = i % 2 ? &expired : &terminal;
  reachable->seeds[11] = &valid;
  for (u8 mode = RANDOM_SELECTION; mode <= FAVOR; mode++)
    for (u32 i = 0; i < 50; i++) assert(choose_seed(a, mode) == &valid);
  for (u8 mode = RANDOM_SELECTION; mode <= FAVOR; mode++) {
    for (u32 i = 0; i < 50; i++) {
      u32 selected = choose_target_state(mode);
      assert(selected == 0 || selected == a);
      assert(scheduler_eligible_states == 2);
      if (strcmp(scheduler_selection_reason, "weighted-eligible")) {
        khint_t k = kh_get(hms, khms_states, selected);
        assert(kh_val(khms_states, k)->last_sampled_theta == -1.0);
        assert(kh_val(khms_states, k)->last_selection_score == 0.0);
      }
    }
  }
  /* Warmup must count cursor wraps, not every eligible state encountered
   * while building the eligibility set. With two executable states at
   * indices 0 and 2, the first two selections do not complete a sweep; the
   * third wraps from index 3 to index 0 exactly once. */
  state_cycles = selected_state_index = 0;
  scheduler_warmup_selections = 0;
  scheduler_warmup_max_selections = 0;
  assert(choose_target_state(FAVOR) == 0);
  assert(state_cycles == 0);
  assert(choose_target_state(FAVOR) == a);
  assert(state_cycles == 0);
  assert(choose_target_state(FAVOR) == 0);
  assert(state_cycles == 1);

  /* Growing state spaces cannot defer weighted scheduling indefinitely:
   * after the configured count of unweighted FAVOR selections, the next
   * choice must enter the production weighted path. */
  state_cycles = selected_state_index = 0;
  scheduler_warmup_selections = 0;
  scheduler_warmup_max_selections = 2;
  assert(choose_target_state(FAVOR) == 0);
  assert(!strcmp(scheduler_selection_reason, "warmup-eligible"));
  assert(scheduler_warmup_selections == 1);
  assert(choose_target_state(FAVOR) == a);
  assert(!strcmp(scheduler_selection_reason, "warmup-eligible"));
  assert(scheduler_warmup_selections == 2);
  choose_target_state(FAVOR);
  assert(!strcmp(scheduler_selection_reason, "weighted-eligible"));
  assert(!strcmp(scheduler_warmup_exit_reason, "selection-cap"));
  assert(scheduler_warmup_selections == 2);

  test_q3_shared_frontier(initial, reachable);

  /* The calibration audit reuses the same normalized draw against
   * frontier-only weights. Choose EWMA values that materially reorder two
   * otherwise equal frontier states, then find a deterministic quantile
   * in the interval where the calibrated and counterfactual choices differ. */
  calibration_enabled = 1;
  cal_estimator = 1;
  cal_estimator_name = "ewma";
  cal_epsilon = 0.1;
  initial->fuzzs = reachable->fuzzs = 0;
  initial->selected_times = reachable->selected_times = 0;
  initial->paths_discovered = reachable->paths_discovered = 0;
  initial->cal_ewma = 0.95;
  reachable->cal_ewma = 0.05;
  u8 calibration_changed = 0;
  for (u64 seed = 1; seed <= 256 && !calibration_changed; seed++) {
    ec_rng_seed(seed);
    update_scores_and_select_next_state(FAVOR);
    calibration_changed = scheduler_calibration_changed_selection;
  }
  assert(calibration_changed);
  assert(scheduler_calibration_applied);
  assert(scheduler_calibration_counterfactual_state == 0 ||
         scheduler_calibration_counterfactual_state == a);
  assert(scheduler_calibration_counterfactual_state != SCHEDULER_NO_STATE);
  calibration_enabled = 0;
  cal_estimator = 0;
  cal_estimator_name = "thompson";
  cal_epsilon = EC_DEFAULT_EPSILON;

  initial->seeds[0] = &expired;
  state_cycles = selected_state_index = 0;
  scheduler_warmup_selections = 0;
  scheduler_warmup_max_selections = 64;
  for (u32 i = 0; i < 10; i++) assert(choose_target_state(FAVOR) == a);
  assert(state_cycles >= 5);
  initial->seeds[0] = &valid;
  initial->score = 0; reachable->score = 3; dead_end->score = (u32)-1;
  for (u32 i = 0; i < 50; i++) assert(update_scores_and_select_next_state(INVALID_SELECTION) == a);
  initial->score = reachable->score = 0;
  u8 selected_zero = 0, selected_a = 0;
  for (u32 i = 0; i < 50; i++) {
    u32 selected = update_scores_and_select_next_state(INVALID_SELECTION);
    assert(selected == 0 || selected == a);
    selected_zero |= selected == 0; selected_a |= selected == a;
    assert(!strcmp(scheduler_selection_reason, "zero-weight-eligible-uniform"));
  }
  assert(selected_zero && selected_a);
  initial->score = reachable->score = (u32)-1;
  update_scores_and_select_next_state(INVALID_SELECTION);
  assert(scheduler_weight_total == 0x1fffffffeULL);
  valid.prov_expired = 1;
  for (u8 mode = RANDOM_SELECTION; mode <= FAVOR; mode++)
    assert(choose_target_state(mode) == SCHEDULER_NO_STATE);
  assert(update_scores_and_select_next_state(INVALID_SELECTION) == SCHEDULER_NO_STATE);
  assert(!strcmp(scheduler_selection_reason, "no-executable-state"));
  assert(choose_target_state(INVALID_SELECTION) == SCHEDULER_NO_STATE);

  test_episode_attribution(reachable, a);
  test_fixed_dose_calibration(reachable, a);
  test_inline_calibration_reward(reachable, a);

  destroy_ipsm();
  state_ids = NULL; state_ids_count = 0;
  for (u32 i = 0; i < fuzzed_map_states; i++) ck_free(was_fuzzed_map[i]);
  ck_free(was_fuzzed_map); was_fuzzed_map = NULL;
  fuzzed_map_states = fuzzed_map_qentries = 0;
}

int main(void) {
  rand_cnt = 100000; srandom(123);
  test_cumulative_weights();
  test_joint_weighted_sampling();
  test_bounded_rng();
  test_m2_and_queue_contract();
  test_registration_and_scheduler();
  puts("scheduler_contract_selftest: exact sampling, joint weighted uniformity, RNG rejection, M2 eligibility, queue bounds, warmup bound/cycles, shared Q3 frontier, calibration counterfactual, state persistence, episode attribution, inline calibration reward passed");
  return 0;
}
