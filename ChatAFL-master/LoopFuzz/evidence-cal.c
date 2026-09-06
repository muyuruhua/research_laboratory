/*
 * evidence-cal.c — pure math for LoopFuzz's evidence controller.
 * See evidence-cal.h for the design rationale and paper mapping.
 */

#include "evidence-cal.h"

#include <math.h>
#include <string.h>

/* ── Discounted Beta-Bernoulli posterior ─────────────────────────── */

void ec_posterior_init_default(ec_posterior_t *p) {
  if (!p) return;
  p->alpha = 1.0;
  p->beta  = 1.0;
  p->gamma = EC_DEFAULT_GAMMA;
}

void ec_posterior_update(ec_posterior_t *p, int reward) {
  if (!p) return;
  double r = reward ? 1.0 : 0.0;
  p->alpha = 1.0 + p->gamma * (p->alpha - 1.0) + r;
  p->beta  = 1.0 + p->gamma * (p->beta  - 1.0) + (1.0 - r);
}

double ec_posterior_mean(const ec_posterior_t *p) {
  if (!p || (p->alpha + p->beta) <= 0.0) return 0.0;
  return p->alpha / (p->alpha + p->beta);
}

double ec_posterior_var(const ec_posterior_t *p) {
  if (!p) return 0.0;
  double a = p->alpha, b = p->beta, s = a + b;
  if (s <= 0.0 || s + 1.0 <= 0.0) return 0.0;
  return (a * b) / (s * s * (s + 1.0));
}

/* ── Deterministic RNG (xoshiro256**) ────────────────────────────── */

static uint64_t ec_rng_s[4] = {0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL,
                               0x94D049BB133111EBULL, 0x2545F4914F6CDD1DULL};

static inline uint64_t ec_rotl(uint64_t x, int k) {
  return (x << k) | (x >> (64 - k));
}

void ec_rng_seed(uint64_t seed) {
  /* splitmix64 expansion of the seed into the four state words */
  uint64_t z = seed + 0x9E3779B97F4A7C15ULL;
  for (int i = 0; i < 4; i++) {
    z += 0x9E3779B97F4A7C15ULL;
    uint64_t x = z;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    x = x ^ (x >> 31);
    ec_rng_s[i] = x;
  }
  /* avoid the all-zero fixed point */
  if (!ec_rng_s[0] && !ec_rng_s[1] && !ec_rng_s[2] && !ec_rng_s[3])
    ec_rng_s[0] = 0x9E3779B97F4A7C15ULL;
}

static inline uint64_t ec_rng_next(void) {
  uint64_t result = ec_rotl(ec_rng_s[1] * 5, 7) * 9;
  uint64_t t = ec_rng_s[1] << 17;
  ec_rng_s[2] ^= ec_rng_s[0];
  ec_rng_s[3] ^= ec_rng_s[1];
  ec_rng_s[1] ^= ec_rng_s[2];
  ec_rng_s[0] ^= ec_rng_s[3];
  ec_rng_s[2] ^= t;
  ec_rng_s[3] = ec_rotl(ec_rng_s[3], 45);
  return result;
}

double ec_uniform01(void) {
  /* 53-bit uniform in [0,1) */
  return (double)(ec_rng_next() >> 11) * (1.0 / 9007199254740992.0);
}

double ec_gamma_sample(double shape) {
  /* Marsaglia–Tsang squeeze method, valid for shape ≥ 1.  All posteriors in
   * this controller start at (1,1) and the discounted update keeps
   * α, β ≥ 1, so no boost trick is needed. */
  if (shape < 1.0) shape = 1.0;

  double d = shape - 1.0 / 3.0;
  double c = 1.0 / sqrt(9.0 * d);

  for (;;) {
    double x, v, u;
    /* Box–Muller standard normal */
    double u1 = ec_uniform01();
    double u2 = ec_uniform01();
    if (u1 <= 0.0) u1 = 1e-300;
    x = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);

    v = 1.0 + c * x;
    if (v <= 0.0) continue;
    v = v * v * v;

    u = ec_uniform01();
    if (u < 1.0 - 0.0331 * x * x * x * x) return d * v;
    if (log(u) < 0.5 * x * x + d * (1.0 - v + log(v))) return d * v;
  }
}

double ec_thompson_sample(double alpha, double beta) {
  double ga = ec_gamma_sample(alpha);
  double gb = ec_gamma_sample(beta);
  double denom = ga + gb;
  if (denom <= 0.0 || !(denom == denom)) return 0.5; /* NaN guard */
  double t = ga / denom;
  if (t < 0.0) t = 0.0;
  if (t > 1.0) t = 1.0;
  return t;
}

/* ── Calibrated scheduling score ─────────────────────────────────── */

double ec_calibrated_factor(double theta_sample, double epsilon) {
  if (epsilon < 0.0) epsilon = 0.0;
  if (epsilon > 1.0) epsilon = 1.0;
  return epsilon + (1.0 - epsilon) * theta_sample;
}

double ec_selection_score(double frontier_score, double theta_sample,
                          double epsilon) {
  return frontier_score * ec_calibrated_factor(theta_sample, epsilon);
}

/* ── Two-tier admission disposition ──────────────────────────────── */

int ec_decide_disposition(const ec_predicates_t *pr) {
  if (!pr) return EC_REJECT;
  if (!pr->p_pass) return EC_REJECT;
  if (!pr->u_pass) return EC_REJECT;
  if (!pr->r_pass) return EC_REJECT;
  if (pr->g_code_pass) return EC_DURABLE;
  if (pr->g_state_pass) return EC_PROVISIONAL;
  return EC_REJECT;
}

const char *ec_disposition_name(int d) {
  switch (d) {
    case EC_DURABLE:     return "durable";
    case EC_PROVISIONAL: return "provisional";
    default:             return "reject";
  }
}

const char *ec_reject_reason(const ec_predicates_t *pr) {
  if (!pr) return "invalid";
  if (!pr->p_pass) return "p_fail:invalid-schema";
  if (!pr->u_pass) return "u_fail:unacceptable-response";
  if (!pr->r_pass) return "r_fail:no-reachability";
  if (pr->g_code_pass || pr->g_state_pass) return "unreachable";
  return "no-gain:no-code-or-state-evidence";
}
