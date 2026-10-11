#ifndef __ATTACK_CATALOG_H__
#define __ATTACK_CATALOG_H__

/* attack-catalog.h — CVE-pattern attack seed catalog (Stage 2) and the
 * generic deep-state template set.
 *
 * DE-INJECTION (2026-10-10), see knowledge-level.h for the level model:
 *   - Generic deep-state templates (RFC-derivable state shapes) are
 *     always compiled, written as deepstate_<id>_v0.raw, active at
 *     CHATAFL_KNOWLEDGE_LEVEL>=1 (legacy CHATAFL_DEEP_STATE_EXPLORE
 *     still overrides; its old default-ON is GONE).
 *   - CVE-pattern knowledge (Stage-2 catalog incl. MQTT projections,
 *     CVE-named deep templates, payload-guard anchors) is compiled ONLY
 *     under CHATAFL_EMBED_CVE_CATALOG (make L3=1), written as
 *     attack_<id>_v<N>.raw, active only at CHATAFL_KNOWLEDGE_LEVEL=3
 *     (legacy CHATAFL_ATTACK_SEEDS still overrides).
 *   - Paper builds must use the default (catalog-free) build; the
 *     binary is then auditable: strings(1) finds no catalog ids/CVE
 *     refs/payload literals (see audit_infoleak.py).
 *
 * Seeds flow through the EXISTING admission channel: written into
 * in_dir before read_testcases(), queued, coverage-accounted and
 * auto-deprioritized when they add no new edges.  Nothing here touches
 * the forkserver, the scheduler, or the mutation core.
 */

/* One message in an attack sequence.  Text protocols use line_fmt with a
 * printf-style single %s argument (the payload, e.g. a long path or a
 * malformed token); binary protocols use raw bytes. */
typedef struct {
  const char *line_fmt;   /* NULL for raw messages */
  const char *payload;    /* %s argument for line_fmt; NULL for none */
  const unsigned char *raw; /* raw bytes when line_fmt == NULL */
  unsigned int raw_len;
  unsigned int repeat;      /* append this message repeat times */
} attack_msg_step_t;

typedef struct {
  const char *id;           /* file-stem fragment: attack_<id>_v<N>.raw */
  const char *protocol;     /* "RTSP" | "FTP" | "SIP" | "SMTP" | "MQTT" */
  const char *cve_ref;      /* reference from 漏洞发现经验, or "pattern" */
  const attack_msg_step_t *steps;
  unsigned int n_steps;
  unsigned int n_variants;  /* deterministic variants (>1 vary payloads) */
} attack_pattern_t;

/* Write attack_<id>_v<N>.raw files for the given protocol into seed_dir.
 * Returns the number of files written (0 when the gate is off, the
 * protocol has no patterns, or seed_dir is NULL — and always 0 in
 * catalog-free builds).  Never exceeds the CHATAFL_ATTACK_SEED_MAX cap. */
unsigned int attack_enrich_seeds(const char *seed_dir, const char *protocol);

/* Generic deep-state sequence templates (pause/play toggles, teardown
 * reuse, file lifecycles, ...) as deepstate_<id>_v0.raw through the same
 * admission channel.  Active at CHATAFL_KNOWLEDGE_LEVEL>=1 (legacy
 * CHATAFL_DEEP_STATE_EXPLORE overrides), cap CHATAFL_DEEP_STATE_SEED_MAX
 * (default 6).  CVE-named templates join at level 3 in catalog builds.
 * DAAP maps to the HTTP template. */
unsigned int deep_state_enrich_seeds(const char *seed_dir, const char *protocol);

/* Byte anchors of attack-seed payloads that must survive havoc.
 * Fills up to 4 pointers into patterns_out and returns the count
 * (0 when the protocol has no registered patterns, the guard is off,
 * or the catalog is not compiled in). */
unsigned int attack_payload_patterns(const char *protocol,
                                     const char *patterns_out[4]);

#endif /* __ATTACK_CATALOG_H__ */
