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
  initial->seeds[0] = &expired;
  state_cycles = selected_state_index = 0;
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

  destroy_ipsm();
  state_ids = NULL; state_ids_count = 0;
  for (u32 i = 0; i < fuzzed_map_states; i++) ck_free(was_fuzzed_map[i]);
  ck_free(was_fuzzed_map); was_fuzzed_map = NULL;
  fuzzed_map_states = fuzzed_map_qentries = 0;
}

int main(void) {
  rand_cnt = 100000; srandom(123);
  test_cumulative_weights();
  test_bounded_rng();
  test_m2_and_queue_contract();
  test_registration_and_scheduler();
  puts("scheduler_contract_selftest: exact sampling, RNG rejection, M2 eligibility, queue bounds, state persistence passed");
  return 0;
}
