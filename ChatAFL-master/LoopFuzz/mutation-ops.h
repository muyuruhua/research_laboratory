/* mutation-ops.h — Protocol-Aware Mutation Engine (extracted 2026-09-07)
 *
 * Extracted from afl-fuzz.c so unit tests link against the REAL
 * implementation instead of a drifting replica. afl-fuzz.c overrides
 * mut_ur() with its UR() (random()); test binaries provide their own
 * deterministic strong definition.
 *
 * Strategies in cve_targeted_mutate() — version-filtered (only CVEs
 * whose affected range covers our mirror snapshots):
 *   S1  Content-Length overflow        (SIP/HTTP/DAAP: kamailio CVE-2026-39863)
 *   S2a RNTO trailing backslash/quote  (FTP: proftpd CVE-2023-51713)
 *   S2b MLSD/MLST argument extension   (FTP: pure-ftpd CVE-2024-48208)
 *   S3  AUTH base64 length boundary    (SMTP: exim CVE-2018-6789/2023-42115)
 *   S4  Session token replacement      (RTSP: live555 CVE-2026-41470)
 *   S5  AUTH SPA/NTLM malformed blob   (SMTP: exim CVE-2023-42114)
 *   S6  RCPT TO address extension      (SMTP: exim CVE-2023-42116)
 *   S7  AUTH base64 NUL-field absence  (SMTP: exim CVE-2023-42115)
 *   S8  line-end/quote structure       (FTP: proftpd CVE-2023-51713)
 *   S9  consecutive-separator path     (HTTP/DAAP: owntone CVE-2026-26828)
 *   S10 query parameter omission       (HTTP/DAAP: owntone CVE-2026-26829)
 *
 * Deliberately NOT implemented (CVE agent 2026-09-07: mirrors outside
 * affected range): lighttpd trailer smuggling CVE-2025-12642 (needs
 * 1.4.80+, mirror is 1.4.72-dev), owntone expression nesting
 * CVE-2025-44560 (not triggerable on 27.2), owntone SQLi CVE-2026-41457
 * (needs 28.4-29.0). */

#ifndef MUTATION_OPS_H
#define MUTATION_OPS_H

#include <stdint.h>

/* Telemetry counters (defined in mutation-ops.c, read by write_stats_file) */
extern uint64_t auth_prefix_restores_havoc;
extern uint64_t auth_prefix_calls;
extern uint64_t auth_prefix_found;
extern uint32_t cve_mutations_applied;

/* RNG hook. Weak default uses rand(); afl-fuzz.c provides a strong
 * override bound to UR(). Tests provide deterministic sequences. */
uint32_t mut_ur(uint32_t bound);

uint32_t count_auth_prefixes(const uint8_t *buf, uint32_t len,
                             const char *proto);

/* Restore authentication command lines (USER/PASS, EHLO/AUTH, ...)
 * from orig into mutated at their original offsets after havoc.
 * Returns number of bytes restored. */
uint32_t auth_prefix_protect(uint8_t *mutated_buf, const uint8_t *orig_buf,
                             uint32_t mutated_len, uint32_t orig_len,
                             const char *proto);

/* Cheap precondition scan: does this buffer contain a marker that any
 * CVE strategy for this protocol could fire on? The havoc hook uses it
 * to boost the trigger probability on pattern-bearing buffers (2026-09-08
 * fix for the queue-dilution lottery: proftpd replicas hit 0 triggers
 * because ~1 pattern entry × ~30 cycles × 1/32 ≈ 0.93 expected fires). */
int mut_marker_scan(const uint8_t *buf, uint32_t len, const char *proto);

/* Apply one protocol-aware CVE-targeted mutation in place.
 * Returns 1 if applied (buffer/length possibly changed), 0 otherwise. */
uint8_t cve_targeted_mutate(uint8_t *buf, uint32_t *len_ref,
                            uint32_t buf_cap, const char *proto);

#endif /* MUTATION_OPS_H */
