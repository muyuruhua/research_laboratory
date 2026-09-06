#ifndef __EVIDENCE_CAL_H
#define __EVIDENCE_CAL_H

/*
 * LoopFuzz evidence controller — pure calibration & admission math.
 *
 * This module implements the paper-aligned logic with NO fuzzer state and
 * NO I/O, so it can be unit-tested standalone (evidence_selftest.c):
 *
 *  1. Online calibration of response-derived state utility (paper §五):
 *     per-state Beta-Bernoulli productivity posterior θ_s ~ Beta(α_s, β_s)
 *     with discounted (non-stationary) updates
 *         α ← 1 + γ(α−1) + r
 *         β ← 1 + γ(β−1) + (1−r)
 *     and Thompson sampling for scheduling
 *         Score(s) = Frontier(s) · [ε + (1−ε)·θ̃_s]
 *
 *  2. The two-tier admission disposition table (paper §四):
 *         P ∧ U ∧ R ∧ G_code                → DURABLE
 *         P ∧ U ∧ R ∧ ¬G_code ∧ G_state     → PROVISIONAL (bounded budget)
 *         otherwise                         → REJECT
 *     where G_code is *code* coverage evidence (code edge/favored entry) and
 *     G_state is IPSM state-machine novelty only.  The two are deliberately
 *     NOT interchangeable: IPSM edge growth is not program progress.
 *
 * Terminology note (paper §三): "code edge/branch" = program coverage
 * feedback; "IPSM/state edge" = response state machine transition.  Never
 * write plain "edge" in logs or docs.
 */

#include <stdint.h>

/* Event-log schema version (bump on any field change). */
#define EC_SCHEMA_VERSION 2

/* Candidate dispositions after the bounded trial (paper §四). */
#define EC_REJECT       0
#define EC_PROVISIONAL  1
#define EC_DURABLE      2

/* Frozen calibration defaults (paper §五: freeze after pilot, sensitivity
 * analysis only over γ ∈ {0.99, 0.995, 1.0} — do not widen). */
#define EC_DEFAULT_GAMMA   0.995
#define EC_DEFAULT_EPSILON 0.1

typedef struct {
  double alpha;   /* posterior α, initialized to 1.0 */
  double beta;    /* posterior β, initialized to 1.0 */
  double gamma;   /* discount factor ∈ (0, 1], EC_DEFAULT_GAMMA */
} ec_posterior_t;

void     ec_posterior_init_default(ec_posterior_t *p);
void     ec_posterior_update(ec_posterior_t *p, int reward);
double   ec_posterior_mean(const ec_posterior_t *p);
double   ec_posterior_var(const ec_posterior_t *p);

/* Deterministic RNG stream (xoshiro256**), separate from AFL's RNG so
 * Thompson sampling never disturbs existing fuzzing trajectories. */
void     ec_rng_seed(uint64_t seed);
double   ec_uniform01(void);
double   ec_gamma_sample(double shape);       /* Marsaglia–Tsang, shape ≥ 1 */
double   ec_thompson_sample(double alpha, double beta);

/* Calibrated exploration floor: ε + (1−ε)·θ̃ (ε = min exploration weight,
 * keeps low-sample states from starving forever). */
double   ec_calibrated_factor(double theta_sample, double epsilon);

/* Combined scheduling score (paper §五.4). */
double   ec_selection_score(double frontier_score, double theta_sample,
                            double epsilon);

/* Admission predicates evaluated on live-trial evidence. */
typedef struct {
  unsigned char p_pass;        /* schema/parse validity of the LLM candidate */
  unsigned char u_pass;        /* acceptable server response (no 4xx/5xx/fault) */
  unsigned char r_pass;        /* reached target state / any state transition */
  unsigned char g_code_pass;   /* code edge/branch gain or favored entry */
  unsigned char g_state_pass;  /* IPSM node/edge novelty only */
} ec_predicates_t;

int          ec_decide_disposition(const ec_predicates_t *pr);
const char  *ec_disposition_name(int d);
/* Most specific failing predicate, for reject reason codes. */
const char  *ec_reject_reason(const ec_predicates_t *pr);

#endif /* __EVIDENCE_CAL_H */
