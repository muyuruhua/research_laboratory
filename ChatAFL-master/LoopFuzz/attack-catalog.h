#ifndef __ATTACK_CATALOG_H__
#define __ATTACK_CATALOG_H__

/* attack-catalog.h — CVE-pattern attack seed catalog (Stage 2).
 *
 * Deterministic seed-file generation encoding the bug-trigger patterns
 * distilled in papers/漏洞发现经验 (11 CVEs across RTSP/FTP/SIP/SMTP/MQTT;
 * see papers/ChatAFLBugDetect.txt / MBFuzzerBugDetect.txt /
 * vulnerabilities.txt).  The seeds flow through the EXISTING admission
 * channel: written into in_dir before read_testcases(), they are queued,
 * coverage-accounted and auto-deprioritized when they add no new edges —
 * the exact mechanism the MQTT binary enrichment already uses and that
 * has been verified not to perturb b_abs/edges metrics.
 *
 * Gated by CHATAFL_ATTACK_SEEDS (default OFF).  Per-protocol file cap via
 * CHATAFL_ATTACK_SEED_MAX (default 16).  Nothing here touches the
 * forkserver, the scheduler, or the mutation core.
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
 * protocol has no patterns, or seed_dir is NULL).  Never exceeds the
 * CHATAFL_ATTACK_SEED_MAX cap. */
unsigned int attack_enrich_seeds(const char *seed_dir, const char *protocol);

#endif /* __ATTACK_CATALOG_H__ */
