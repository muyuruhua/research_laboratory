/* knowledge-level.h — unified knowledge-level gate for LoopFuzz
 * (de-injection, 2026-10-10).
 *
 * LoopFuzz historically carried five CVE-knowledge channels (attack seed
 * catalog, CVE-named deep-state templates, plateau prompt CVE patterns,
 * payload-guard byte anchors, CVE-annotated mutation scheduling), each
 * with its own env gate and its own default.  For information-controlled
 * evaluation those channels must be OFF by default and physically absent
 * from paper builds (compile-time strip via CHATAFL_EMBED_CVE_CATALOG).
 *
 * This header is the single replacement control surface:
 *
 *   CHATAFL_KNOWLEDGE_LEVEL = 0  (default) all knowledge channels off;
 *                                    bug-class mutation operators off.
 *                                 1  bug-class channels on: class-generic
 *                                    mutation operators, RFC-derived
 *                                    generic deep-state templates
 *                                    (deepstate_*.raw), and the CWE-cited
 *                                    bug-class plateau prompt primitives.
 *                                    This is the paper main arm (L1).
 *                                 2  reserved: LOTO-transferred protocol
 *                                    patterns produced by the knowledge
 *                                    compiler (no-op until that lands).
 *                                 3  full legacy CVE knowledge: attack
 *                                    seed catalog, CVE-named deep-state
 *                                    templates, CVE prompt patterns, and
 *                                    the CVE-anchor payload guard.  Only
 *                                    available in builds compiled with
 *                                    CHATAFL_EMBED_CATALOG=1 (make L3=1);
 *                                    intended solely for the leakage
 *                                    upper-bound ablation arm.
 *
 * Legacy env overrides (deprecated, still honored so historical ablation
 * scripts and oracle_selftest keep working): when set explicitly they
 * win over the level default for their channel.  afl-fuzz.c prints a
 * deprecation warning at startup when any is present.
 *
 * Header-only on purpose: every translation unit gets its own lazy
 * getenv cache (env is stable for the process lifetime), which keeps
 * the Makefile and the standalone test harnesses link-clean.
 */
#ifndef __KNOWLEDGE_LEVEL_H__
#define __KNOWLEDGE_LEVEL_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* 1 if the binary was built with the CVE catalog data compiled in. */
#ifdef CHATAFL_EMBED_CVE_CATALOG
#define KL_CVE_CATALOG_COMPILED 1
#else
#define KL_CVE_CATALOG_COMPILED 0
#endif

static int kl_level_cached = -1;

static inline int kl_level(void) {
  if (kl_level_cached < 0) {
    const char *env = getenv("CHATAFL_KNOWLEDGE_LEVEL");
    int v = env ? atoi(env) : 0;
    if (v < 0) v = 0;
    if (v > 3) v = 3;
    if (v == 3 && !KL_CVE_CATALOG_COMPILED) {
      /* Requested the legacy arm on a clean build: cap at L1 so the
       * channels degrade gracefully instead of silently promising
       * knowledge that is not in the binary. */
      fprintf(stderr,
              "[!] KNOWLEDGE-LEVEL: 3 requested but this build has no "
              "CVE catalog compiled in (make L3=1); capping at 1\n");
      v = 1;
    }
    kl_level_cached = v;
  }
  return kl_level_cached;
}

/* L1+: class-generic operators / templates / prompt primitives. */
static inline int kl_bugclass_enabled(void) { return kl_level() >= 1; }

/* L3: legacy per-target CVE knowledge (needs the catalog build). */
static inline int kl_cve_knowledge_enabled(void) {
  return kl_level() == 3 && KL_CVE_CATALOG_COMPILED;
}

/* ── Legacy overrides ───────────────────────────────────────────────
 * Returns 1 when the env var is explicitly set to an enabling value,
 * 0 when explicitly disabled, -1 when unset (caller applies the
 * level-derived default). */
static inline int kl_env_tri(const char *name) {
  const char *env = getenv(name);
  if (!env || !*env) return -1;
  if (atoi(env) == 1 || strcasecmp(env, "on") == 0 ||
      strcasecmp(env, "yes") == 0 || strcasecmp(env, "true") == 0)
    return 1;
  return 0;
}

/* Stage 2: CVE-pattern attack seed files (attack_<id>_vN.raw). */
static inline int kl_attack_seeds_on(void) {
  int e = kl_env_tri("CHATAFL_ATTACK_SEEDS");
  if (e >= 0) return e && KL_CVE_CATALOG_COMPILED;
  return kl_cve_knowledge_enabled();
}

/* CVE-named deep-state templates (attack_deep_*.raw, catalog subset). */
static inline int kl_cve_deep_seeds_on(void) {
  return kl_cve_knowledge_enabled();
}

/* Generic deep-state templates (deepstate_<id>_v0.raw, RFC-derived).
 * Legacy CHATAFL_DEEP_STATE_EXPLORE used to default ON; it now follows
 * the level (>=1) unless explicitly set. */
static inline int kl_generic_deep_seeds_on(void) {
  int e = kl_env_tri("CHATAFL_DEEP_STATE_EXPLORE");
  if (e >= 0) return e;
  return kl_bugclass_enabled();
}

/* Stage 3: plateau CVE-pattern prompt bias (chat-llm.c). */
static inline int kl_attack_prompt_on(void) {
  int e = kl_env_tri("CHATAFL_ATTACK_PROMPT");
  if (e >= 0) return e && KL_CVE_CATALOG_COMPILED;
  return kl_cve_knowledge_enabled();
}

/* Stage 1: attack oracle rules R1-R10 (protocol-oracle-precise.c). */
static inline int kl_attack_oracle_on(void) {
  int e = kl_env_tri("CHATAFL_ATTACK_ORACLE");
  if (e >= 0) return e;
  return kl_cve_knowledge_enabled();
}

/* P0-2 payload guard: CVE-derived byte anchors, only meaningful for
 * attack_* seed files (the L3 catalog).  Default now follows the level;
 * explicit CHATAFL_PAYLOAD_GUARD still wins. */
static inline int kl_payload_guard_on(void) {
  int e = kl_env_tri("CHATAFL_PAYLOAD_GUARD");
  if (e >= 0) return e;
  return kl_cve_knowledge_enabled();
}

/* Bug-class mutation engine (cve_targeted_mutate): the operators are
 * class-generic (escape amplification, boundary saturation, lexer
 * poison, nesting imbalance) and are the method contribution — active
 * at L1+ and off at L0 so the pure baseline arm stays pure. */
static inline int kl_bugclass_mutate_on(void) { return kl_bugclass_enabled(); }

#endif /* __KNOWLEDGE_LEVEL_H__ */
