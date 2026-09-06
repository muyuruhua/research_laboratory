/*
 * evidence_selftest.c — standalone unit checks for evidence-cal.c
 *
 * Build & run:
 *   gcc -O2 -Wall -o evidence_selftest evidence_selftest.c evidence-cal.c -lm
 *   ./evidence_selftest
 *
 * Exit code 0 = all checks green.
 */

#include "evidence-cal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...)                                        \
  do {                                                          \
    if (!(cond)) {                                              \
      failures++;                                               \
      printf("FAIL %s:%d: ", __FILE__, __LINE__);               \
      printf(__VA_ARGS__);                                      \
      printf("\n");                                             \
    }                                                           \
  } while (0)

static int approx(double a, double b, double tol) {
  return fabs(a - b) <= tol;
}

static void test_posterior_update(void) {
  ec_posterior_t p;
  ec_posterior_init_default(&p);
  CHECK(approx(p.alpha, 1.0, 1e-12), "alpha init");
  CHECK(approx(p.beta, 1.0, 1e-12), "beta init");
  CHECK(approx(ec_posterior_mean(&p), 0.5, 1e-12), "uniform mean");

  /* reward=1: α ← 1 + γ(α−1) + 1 = 2, β stays 1 */
  ec_posterior_update(&p, 1);
  CHECK(approx(p.alpha, 2.0, 1e-12), "alpha after one success (gamma ignored at α=1)");
  CHECK(approx(p.beta, 1.0, 1e-12), "beta after one success");
  CHECK(approx(ec_posterior_mean(&p), 2.0 / 3.0, 1e-12), "mean 2/3");

  /* reward=0: α ← 1 + 0.995·(2−1) + 0 = 1.995, β ← 1 + 0.995·0 + 1 = 2 */
  ec_posterior_update(&p, 0);
  CHECK(approx(p.alpha, 1.0 + 0.995 * 1.0, 1e-12), "discounted alpha");
  CHECK(approx(p.beta, 2.0, 1e-12), "beta after failure");

  /* Long-run discounting keeps α,β ≥ 1 and decays stale evidence:
   * 100 consecutive failures must pull the mean near the floor. */
  ec_posterior_t q2;
  ec_posterior_init_default(&q2);
  for (int i = 0; i < 100; i++) ec_posterior_update(&q2, 0);
  double m = ec_posterior_mean(&q2);
  CHECK(m > 0.0 && m < 0.05, "100 failures pull mean near 0, got %f", m);
  CHECK(q2.alpha >= 1.0 && q2.beta >= 1.0, "posteriors stay >= 1");

  /* Non-stationarity: after early success streak, later failures decay it. */
  ec_posterior_t q3;
  ec_posterior_init_default(&q3);
  for (int i = 0; i < 30; i++) ec_posterior_update(&q3, 1);
  double m_early = ec_posterior_mean(&q3);
  for (int i = 0; i < 300; i++) ec_posterior_update(&q3, 0);
  double m_late = ec_posterior_mean(&q3);
  CHECK(m_early > 0.95, "early streak mean, got %f", m_early);
  CHECK(m_late < m_early, "discounted failures reduce stale mean (%f -> %f)",
        m_early, m_late);
}

static void test_disposition(void) {
  ec_predicates_t pr;

  /* Case A: P ∧ U ∧ R ∧ G_code → durable, even with G_state also set */
  memset(&pr, 1, sizeof(pr));
  CHECK(ec_decide_disposition(&pr) == EC_DURABLE, "case A durable");
  CHECK(strcmp(ec_disposition_name(EC_DURABLE), "durable") == 0, "name");

  /* Case B: P ∧ U ∧ R ∧ ¬G_code ∧ G_state → provisional */
  memset(&pr, 1, sizeof(pr));
  pr.g_code_pass = 0;
  CHECK(ec_decide_disposition(&pr) == EC_PROVISIONAL, "case B provisional");

  /* Case C variants */
  memset(&pr, 1, sizeof(pr)); pr.p_pass = 0;
  CHECK(ec_decide_disposition(&pr) == EC_REJECT, "P fail");
  CHECK(strcmp(ec_reject_reason(&pr), "p_fail:invalid-schema") == 0, "P reason");

  memset(&pr, 1, sizeof(pr)); pr.u_pass = 0; pr.g_code_pass = 0; pr.g_state_pass = 1;
  CHECK(ec_decide_disposition(&pr) == EC_REJECT, "U fail beats G_state");
  CHECK(strcmp(ec_reject_reason(&pr), "u_fail:unacceptable-response") == 0, "U reason");

  memset(&pr, 1, sizeof(pr)); pr.r_pass = 0; pr.g_code_pass = 0; pr.g_state_pass = 1;
  CHECK(ec_decide_disposition(&pr) == EC_REJECT, "R fail beats G_state");

  memset(&pr, 1, sizeof(pr)); pr.g_code_pass = 0; pr.g_state_pass = 0;
  CHECK(ec_decide_disposition(&pr) == EC_REJECT, "no gain → reject");
  CHECK(strcmp(ec_reject_reason(&pr),
               "no-gain:no-code-or-state-evidence") == 0, "no-gain reason");

  CHECK(ec_decide_disposition(NULL) == EC_REJECT, "NULL predicates");
}

static void test_thompson_statistics(void) {
  ec_rng_seed(0xC0FFEE123456789ULL);

  /* Thompson sample of Beta(1,1) must be ~Uniform(0,1) */
  double sum = 0, sum2 = 0;
  const int N = 20000;
  for (int i = 0; i < N; i++) {
    double t = ec_thompson_sample(1.0, 1.0);
    CHECK(t >= 0.0 && t <= 1.0, "sample in [0,1]");
    sum += t; sum2 += t * t;
  }
  double mean = sum / N, var = sum2 / N - mean * mean;
  CHECK(approx(mean, 0.5, 0.02), "Beta(1,1) sample mean ~ 0.5, got %f", mean);
  CHECK(approx(var, 1.0 / 12.0, 0.005), "Beta(1,1) sample var ~ 1/12, got %f", var);

  /* Beta(9,1): mean 0.9, var = 9*1/(100*11*... ) = ab/(s²(s+1)) = 9/(100*11) */
  sum = 0;
  for (int i = 0; i < N; i++) sum += ec_thompson_sample(9.0, 1.0);
  double mean91 = sum / N;
  CHECK(approx(mean91, 0.9, 0.01), "Beta(9,1) sample mean ~ 0.9, got %f", mean91);

  /* Score composition: frontier 100, θ̃=0.5, ε=0.1 → 100·(0.1+0.9·0.5)=55 */
  CHECK(approx(ec_selection_score(100.0, 0.5, 0.1), 55.0, 1e-9), "score compose");
  /* θ̃=0 must not zero the score (exploration floor) */
  CHECK(approx(ec_selection_score(100.0, 0.0, 0.1), 10.0, 1e-9), "epsilon floor");

  /* Reproducibility: same seed → same stream */
  ec_rng_seed(42);
  double a1 = ec_thompson_sample(3.0, 2.0);
  double a2 = ec_thompson_sample(3.0, 2.0);
  ec_rng_seed(42);
  double b1 = ec_thompson_sample(3.0, 2.0);
  double b2 = ec_thompson_sample(3.0, 2.0);
  CHECK(a1 == b1 && a2 == b2, "deterministic replay of sampling stream");
}

static void test_gamma_extremes(void) {
  ec_rng_seed(7);
  /* shape ≥ 1 guaranteed by clamp; extreme shapes must not hang or NaN */
  for (int i = 0; i < 1000; i++) {
    double g = ec_gamma_sample(1.0 + 5000.0 * ec_uniform01());
    CHECK(g > 0.0 && g == g, "gamma sample finite positive");
  }
  /* Gamma clamp for shape < 1 */
  double g = ec_gamma_sample(0.3);
  CHECK(g > 0.0, "clamped gamma(0.3) positive");
}

int main(void) {
  test_posterior_update();
  test_disposition();
  test_thompson_statistics();
  test_gamma_extremes();

  if (failures) {
    printf("evidence_selftest: %d FAILURE(S)\n", failures);
    return 1;
  }
  printf("evidence_selftest: all checks passed\n");
  return 0;
}
