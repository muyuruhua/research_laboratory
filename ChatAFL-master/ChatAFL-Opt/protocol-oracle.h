/*
 * ChatAFL-Opt: Protocol-Specific Semantic Oracle Framework
 * =========================================================
 *
 * Extends vulnerability detection beyond crash-only (memory bugs) to
 * semantic/logic vulnerability detection based on RFC security invariants.
 *
 * Security properties checked:
 *   - Authentication bypass (accessing protected resources without auth)
 *   - State machine violations (illegal state transitions)
 *   - Information leakage (sensitive data in responses)
 *   - Authorization bypass (privilege escalation)
 *   - Resource exhaustion / DoS patterns
 *   - Path traversal
 *   - Injection indicators
 *
 * Inspired by real CVEs:
 *   CVE-2024-3935 (lightftp), CVE-2024-42644..42655 (bftpd),
 *   CVE-2023-34488 (mqtt), etc.
 */

#ifndef __PROTOCOL_ORACLE_H
#define __PROTOCOL_ORACLE_H

#include <stdint.h>
#include <stddef.h>

/* ============================================
 * Oracle Violation Severity Levels
 * ============================================ */

#define ORACLE_SEV_NONE     0   /* No violation */
#define ORACLE_SEV_INFO     1   /* Informational (potential info leak) */
#define ORACLE_SEV_LOW      2   /* Low severity (unusual behavior) */
#define ORACLE_SEV_MEDIUM   3   /* Medium (state machine violation) */
#define ORACLE_SEV_HIGH     4   /* High (auth bypass, path traversal) */
#define ORACLE_SEV_CRITICAL 5   /* Critical (RCE indicator, full bypass) */

/* ============================================
 * Oracle Violation Categories
 * Maps to security properties from FindVulnerability.txt
 * ============================================ */

#define ORACLE_CAT_NONE             0x0000
#define ORACLE_CAT_AUTH_BYPASS      0x0001  /* Authentication */
#define ORACLE_CAT_AUTHZ_BYPASS     0x0002  /* Authorization */
#define ORACLE_CAT_STATE_VIOLATION  0x0004  /* State Consistency */
#define ORACLE_CAT_INFO_LEAK        0x0008  /* Confidentiality */
#define ORACLE_CAT_PATH_TRAVERSAL   0x0010  /* Integrity */
#define ORACLE_CAT_INJECTION        0x0020  /* Integrity */
#define ORACLE_CAT_DOS              0x0040  /* Availability */
#define ORACLE_CAT_RESOURCE_EXHAUST 0x0080  /* Availability */
#define ORACLE_CAT_ISOLATION        0x0100  /* Isolation */
#define ORACLE_CAT_REPLAY           0x0200  /* State Consistency - double spend */
#define ORACLE_CAT_SMUGGLING        0x0400  /* Integrity - request smuggling */

/* Maximum violations per check */
#define ORACLE_MAX_VIOLATIONS 16

/* ============================================
 * Violation Report Structure
 * ============================================ */

typedef struct {
    uint8_t  severity;           /* ORACLE_SEV_* */
    uint16_t category;           /* ORACLE_CAT_* bitmask */
    uint32_t pattern_hash;       /* For deduplication */
    char     description[256];   /* Human-readable description */
    char     cve_reference[64];  /* Related CVE pattern if known */
    int      request_index;      /* Which request triggered this */
} oracle_violation_t;

typedef struct {
    oracle_violation_t violations[ORACLE_MAX_VIOLATIONS];
    int violation_count;
    uint8_t max_severity;        /* Highest severity found */
    uint16_t categories_hit;     /* OR of all categories */
} oracle_result_t;

/* ============================================
 * Protocol State Tracking
 * ============================================ */

typedef struct {
    uint8_t authenticated;       /* Has client authenticated? */
    uint8_t connected;           /* Is connection established? */
    uint8_t tls_active;          /* Is TLS/encryption active? */
    uint8_t admin_mode;          /* Is client in admin/privileged mode? */
    int     auth_attempts;       /* Number of auth attempts */
    int     commands_sent;       /* Total commands sent before auth */
    int     commands_after_auth; /* Total commands sent after auth */
    int     current_state;       /* Protocol-specific state enum */
    char    last_command[64];    /* Last command sent */
    int     last_response_code;  /* Last response code received */
} protocol_state_t;

/* FTP state machine states */
#define FTP_STATE_INIT       0
#define FTP_STATE_USER_SENT  1
#define FTP_STATE_LOGGED_IN  2
#define FTP_STATE_PASSIVE    3
#define FTP_STATE_TRANSFER   4

/* SMTP state machine states */
#define SMTP_STATE_INIT      0
#define SMTP_STATE_EHLO      1
#define SMTP_STATE_AUTH      2
#define SMTP_STATE_MAIL      3
#define SMTP_STATE_RCPT      4
#define SMTP_STATE_DATA      5

/* RTSP state machine states */
#define RTSP_STATE_INIT      0
#define RTSP_STATE_DESCRIBED 1
#define RTSP_STATE_SETUP     2
#define RTSP_STATE_PLAYING   3

/* SIP state machine states */
#define SIP_STATE_INIT       0
#define SIP_STATE_REGISTER   1
#define SIP_STATE_INVITED    2
#define SIP_STATE_CONFIRMED  3

/* MQTT state machine states */
#define MQTT_STATE_INIT      0
#define MQTT_STATE_CONNECTED 1
#define MQTT_STATE_SUBSCRIBED 2
#define MQTT_STATE_PUBLISHING 3

/* HTTP state machine states */
#define HTTP_STATE_INIT      0
#define HTTP_STATE_AUTHED    1

/* ============================================
 * Main Oracle API
 * ============================================ */

/*
 * Initialize oracle for a specific protocol.
 * Call once at fuzzer startup.
 */
void oracle_init(const char *protocol_name);

/*
 * Check a request-response pair for security violations.
 *
 * @param protocol_name  Protocol identifier (e.g., "FTP", "MQTT")
 * @param requests       Array of request buffers sent
 * @param req_lens       Array of request lengths
 * @param req_count      Number of requests
 * @param response       Server response buffer
 * @param resp_len       Response length
 * @param result         Output: violation results
 *
 * @return Number of violations found
 */
int oracle_check(
    const char *protocol_name,
    const unsigned char **requests,
    const unsigned int *req_lens,
    int req_count,
    const unsigned char *response,
    unsigned int resp_len,
    oracle_result_t *result
);

/*
 * Check if a violation pattern is new (not seen before).
 * Uses a dedup bitmap internally.
 */
int oracle_is_new_violation(uint32_t pattern_hash);

/*
 * Save a violation report to the output directory.
 */
void oracle_save_violation(
    const char *out_dir,
    const oracle_result_t *result,
    const unsigned char *request_data,
    unsigned int request_len,
    const unsigned char *response_data,
    unsigned int response_len
);

/*
 * Get oracle statistics string for status display.
 */
const char* oracle_stats_string(void);

/* ============================================
 * Protocol-Specific Oracle Functions
 * ============================================ */

int oracle_check_ftp(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result);

int oracle_check_smtp(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result);

int oracle_check_rtsp(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result);

int oracle_check_sip(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result);

int oracle_check_daap(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result);

int oracle_check_http(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result);

int oracle_check_mqtt(
    const unsigned char **requests, const unsigned int *req_lens,
    int req_count, const unsigned char *response, unsigned int resp_len,
    oracle_result_t *result);

/* ============================================
 * Telemetry counters (extern, defined in protocol-oracle.c)
 * ============================================ */

extern uint64_t oracle_total_checks;
extern uint64_t oracle_total_violations;
extern uint64_t oracle_unique_violations;
extern uint64_t oracle_auth_bypass_count;
extern uint64_t oracle_state_violation_count;
extern uint64_t oracle_info_leak_count;
extern uint64_t oracle_path_traversal_count;
extern uint64_t oracle_dos_count;

#endif /* __PROTOCOL_ORACLE_H */
