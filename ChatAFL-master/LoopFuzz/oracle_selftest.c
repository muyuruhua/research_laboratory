/* oracle_selftest.c — self-test driver for the indexed precise oracle.
 *
 * Compiles protocol-oracle-precise.c with -DORACLE_SELF_TEST, which makes the
 * fast indexed paths cross-check against the slow reference implementations and
 * abort() on any mismatch.  This driver feeds representative request/response
 * pairs for every protocol so the fast paths actually run.
 *
 * Build (from LoopFuzz/):
 *   cc -O1 -DORACLE_SELF_TEST -I. -I.. -c protocol-oracle-precise.c -o /tmp/po.o
 *   cc -O1 -o /tmp/oracle_selftest oracle_selftest.c /tmp/po.o -ljson-c
 *   /tmp/oracle_selftest
 *
 * Exit 0 = all fast paths match their slow references; any mismatch prints a
 * message and aborts.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "protocol-oracle.h"

static int g_checks = 0;
static int g_expect_failures = 0;

static void run_check(const char *proto,
                      const unsigned char **reqs, const unsigned int *lens, int n,
                      const unsigned char *resp, unsigned int resp_len) {
    oracle_result_t r;
    memset(&r, 0, sizeof(r));
    int v = oracle_check(proto, reqs, lens, n, resp, resp_len, &r);
    g_checks++;
    printf("  %-6s reqs=%d resp=%u -> %d violations (sev=%d cat=0x%04x)\n",
           proto, n, resp_len, v, r.max_severity, r.categories_hit);
    /* A MEDIUM+ violation without an associated request index is suspicious,
     * but we only care here about fast/slow equivalence, so just count. */
}

/* Attack-rule assertion helper: expect MIN_V..MAX_V violations whose
 * category bitmask intersects WANT_CAT (0 = no category requirement).
 * Prints PASS/FAIL per fixture and counts failures. */
static void run_expect(const char *label,
                       const char *proto,
                       const unsigned char **reqs, const unsigned int *lens, int n,
                       const unsigned char *resp, unsigned int resp_len,
                       int min_v, int max_v, unsigned int want_cat) {
    oracle_result_t r;
    memset(&r, 0, sizeof(r));
    int v = oracle_check(proto, reqs, lens, n, resp, resp_len, &r);
    g_checks++;
    int ok = (v >= min_v && v <= max_v);
    if (ok && want_cat) ok = ((r.categories_hit & want_cat) != 0);
    printf("  %-42s -> %d violations (sev=%d cat=0x%04x) %s\n",
           label, v, r.max_severity, r.categories_hit,
           ok ? "PASS" : "FAIL");
    if (!ok) g_expect_failures++;
}

#define REGION_1 "USER anonymous\r\nPASS x\r\nLIST\r\nQUIT\r\n"
#define REGION_2 "USER u\r\nPASS p\r\nRETR /etc/passwd\r\nQUIT\r\n"
#define REGION_3 "CWD ..\\..\\\r\nLIST\r\n"
#define FTP_RESP \
    "220 Welcome\r\n" \
    "331 Password required\r\n" \
    "230 User logged in\r\n" \
    "150 Opening data connection\r\n" \
    "226 Transfer complete\r\n" \
    "221 Goodbye\r\n"

#define SMTP_REGION_1 "EHLO localhost\r\nMAIL FROM:<a@b.com>\r\nRCPT TO:<x@y.net>\r\nDATA\r\n.\r\nQUIT\r\n"
#define SMTP_REGION_2 "EHLO x\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<z@w.z>\r\nDATA\r\n.\r\n"
#define SMTP_RESP \
    "220 mail.example ESMTP\r\n" \
    "250-localhost Hello\r\n" \
    "250 Sender ok\r\n" \
    "250 Recipient ok\r\n" \
    "354 End data with <CR><LF>.<CR><LF>\r\n" \
    "250 OK id=abc\r\n" \
    "221 Bye\r\n"

#define RTSP_REGION_1 "PLAY rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\n\r\n"
#define RTSP_REGION_2 "SETUP rtsp://h/s RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP;unicast;client_port=0\r\n\r\n"
#define RTSP_REGION_3 "PLAY rtsp://h/s RTSP/1.0\r\nCSeq: 3\r\n\r\n"
#define RTSP_RESP_1 \
    "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 123\r\nRange: npt=0-\r\n\r\n"
#define RTSP_RESP_2 \
    "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 123\r\nTransport: RTP/AVP;unicast;client_port=0;server_port=8000\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 123\r\nRange: npt=0-\r\n\r\n"

#define HTTP_REGION_1 "GET /../etc/passwd HTTP/1.1\r\nHost: a\r\n\r\n"
#define HTTP_REGION_2 "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n"
#define HTTP_REGION_3 "GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\n"
#define HTTP_RESP \
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" \
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nroot:x:0:0:"

#define MQTT_CONNECT "\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"
#define MQTT_PUBLISH "\x30\x0c\x00\x03a/bhello"
#define MQTT_SUBSCRIBE "\x82\x06\x00\x01\x00\x03a/b\x00"
#define MQTT_RESP "\x20\x02\x00\x00\x40\x02\x00\x01\x90\x04\x00\x01\x00"

/* ── Attack-rule fixtures (CHATAFL_ATTACK_ORACLE, 2026-08-20) ──
 * One positive + two negatives per rule R1-R10. */

/* R1: FTP filesystem command accepted without prior 230. */
#define R1_POS_REGION "USER anon\r\nMKD /tmp/x\r\nQUIT\r\n"
#define R1_POS_RESP \
    "220 Welcome\r\n"      /* banner        */ \
    "331 Password required\r\n" /* USER     */ \
    "257 Created\r\n"      /* MKD — no 230  */ \
    "221 Bye\r\n"
/* Negative A: proper login precedes MKD. */
#define R1_NEGA_REGION "USER u\r\nPASS p\r\nMKD /tmp/x\r\nQUIT\r\n"
#define R1_NEGA_RESP \
    "220 Welcome\r\n" \
    "331 Password required\r\n" \
    "230 Logged in\r\n" \
    "257 Created\r\n" \
    "221 Bye\r\n"
/* Negative B: MKD rejected with 550. */
#define R1_NEGB_REGION "USER anon\r\nMKD /tmp/x\r\nQUIT\r\n"
#define R1_NEGB_RESP \
    "220 Welcome\r\n" \
    "331 Password required\r\n" \
    "550 Permission denied\r\n" \
    "221 Bye\r\n"

/* R2: RNTO with deep traversal accepted with 250. */
#define R2_POS_REGION "RNFR /tmp/a\r\nRNTO ../../../../tmp/b\r\nQUIT\r\n"
#define R2_POS_RESP \
    "220 Welcome\r\n" \
    "350 Ready for RNTO\r\n" \
    "250 Rename successful\r\n" \
    "221 Bye\r\n"
/* Negative A: shallow traversal (depth 1) — still caught by the pre-existing
 * LOW traversal-accept rule, but NOT by R2 (needs depth >= 2 + 250). */
#define R2_NEGA_REGION "RNFR /tmp/a\r\nRNTO ../b\r\nQUIT\r\n"
#define R2_NEGA_RESP \
    "220 Welcome\r\n" \
    "350 Ready for RNTO\r\n" \
    "250 Rename successful\r\n" \
    "221 Bye\r\n"
/* Negative B: deep traversal rejected. */
#define R2_NEGB_REGION "RNFR /tmp/a\r\nRNTO ../../../../tmp/b\r\nQUIT\r\n"
#define R2_NEGB_RESP \
    "220 Welcome\r\n" \
    "350 Ready for RNTO\r\n" \
    "550 Permission denied\r\n" \
    "221 Bye\r\n"

/* R3: PLAY accepted before any SETUP (existing HIGH/STRONG rule).
 * The PLAY request must NOT carry a Session header — the rule deliberately
 * skips session-bearing PLAY (hijack hypothesis, not "before SETUP" proof). */
#define R3_POS_REGION_1 "DESCRIBE rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\n\r\n"
#define R3_POS_REGION_2 "PLAY rtsp://h/s RTSP/1.0\r\nCSeq: 2\r\n\r\n"
#define R3_POS_RESP \
    "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 9\r\nRange: npt=0-\r\n\r\n"
/* Negative A: SETUP precedes PLAY with matching session. */
#define R3_NEGA_REGION_2 "SETUP rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast\r\nSession: 9\r\n\r\nPLAY rtsp://h/s RTSP/1.0\r\nCSeq: 2\r\nSession: 9\r\n\r\n"
#define R3_NEGA_RESP \
    "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 9\r\nTransport: RTP/AVP;unicast\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 9\r\nRange: npt=0-\r\n\r\n"
/* Negative B: PLAY rejected with 454 (session not found). */
#define R3_NEGB_RESP \
    "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n" \
    "RTSP/1.0 454 Session Not Found\r\nCSeq: 2\r\n\r\n"

/* R4: forged Session accepted (two setup-issued sessions observed). */
#define R4_POS_REGION_1 \
    "SETUP rtsp://h/a RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP\r\n\r\n" \
    "SETUP rtsp://h/b RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP\r\n\r\n"
#define R4_POS_REGION_2 "PLAY rtsp://h/a RTSP/1.0\r\nCSeq: 3\r\nSession: 7777\r\n\r\n"
#define R4_POS_RESP \
    "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 111\r\nTransport: RTP/AVP\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 222\r\nTransport: RTP/AVP\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 7777\r\nRange: npt=0-\r\n\r\n"
/* Negative A: only one setup-issued session (differential guard unmet). */
#define R4_NEGA_REGION_1 "SETUP rtsp://h/a RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP\r\n\r\n"
#define R4_NEGA_RESP \
    "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 111\r\nTransport: RTP/AVP\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 7777\r\nRange: npt=0-\r\n\r\n"
/* Negative B: PLAY uses an actually-issued session (111). */
#define R4_NEGB_REGION_2 "PLAY rtsp://h/a RTSP/1.0\r\nCSeq: 3\r\nSession: 111\r\n\r\n"
#define R4_NEGB_RESP \
    "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 111\r\nTransport: RTP/AVP\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 222\r\nTransport: RTP/AVP\r\n\r\n" \
    "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 111\r\nRange: npt=0-\r\n\r\n"

/* R5: traversal syntax in DESCRIBE URL accepted with 2xx (telemetry). */
#define R5_POS_REGION "DESCRIBE rtsp://h/../../etc RTSP/1.0\r\nCSeq: 1\r\n\r\n"
#define R5_POS_RESP "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n"
/* Negative A: plain URL. */
#define R5_NEGA_REGION "DESCRIBE rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\n\r\n"
/* Negative B: traversal rejected. */
#define R5_NEGB_RESP "RTSP/1.0 404 Not Found\r\nCSeq: 1\r\n\r\n"

/* R6: SIP 401 challenge, then credential-less INVITE gets 200. */
#define R6_POS_REGION_1 "INVITE sip:a@h SIP/2.0\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h:5060\r\n\r\n"
#define R6_POS_REGION_2 "INVITE sip:b@h SIP/2.0\r\nCSeq: 2 INVITE\r\nVia: SIP/2.0/UDP h:5060\r\n\r\n"
#define R6_POS_RESP \
    "SIP/2.0 401 Unauthorized\r\nCSeq: 1 INVITE\r\nWWW-Authenticate: Digest\r\n\r\n" \
    "SIP/2.0 200 OK\r\nCSeq: 2 INVITE\r\n\r\n"
/* Negative A: INVITE carries credentials. */
#define R6_NEGA_REGION_2 "INVITE sip:b@h SIP/2.0\r\nCSeq: 2 INVITE\r\nAuthorization: Digest x\r\nVia: SIP/2.0/UDP h:5060\r\n\r\n"
/* Negative B: no 401/407 challenge anywhere. */
#define R6_NEGB_RESP \
    "SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\n\r\n" \
    "SIP/2.0 200 OK\r\nCSeq: 2 INVITE\r\n\r\n"

/* R7: malformed Via accepted with 200. */
#define R7_POS_REGION "INVITE sip:a@h SIP/2.0\r\nCSeq: 1 INVITE\r\nVia: xx\r\n\r\n"
#define R7_POS_RESP "SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\n\r\n"
/* Negative A: well-formed Via. */
#define R7_NEGA_REGION "INVITE sip:a@h SIP/2.0\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h:5060\r\n\r\n"
/* Negative B: malformed Via but server rejects with 400. */
#define R7_NEGB_RESP "SIP/2.0 400 Bad Via\r\nCSeq: 1 INVITE\r\n\r\n"

/* R8: SMTP 530 auth-required challenge, then MAIL FROM 250 without AUTH. */
#define R8_POS_REGION "EHLO x\r\nMAIL FROM:<a@b.c>\r\nQUIT\r\n"
#define R8_POS_RESP \
    "220 mail ESMTP\r\n" \
    "530 authentication required\r\n" \
    "250 OK\r\n" \
    "221 Bye\r\n"
/* Negative A: AUTH 235 precedes MAIL. */
#define R8_NEGA_REGION "EHLO x\r\nAUTH PLAIN d\r\nMAIL FROM:<a@b.c>\r\nQUIT\r\n"
#define R8_NEGA_RESP \
    "220 mail ESMTP\r\n" \
    "250 x\r\n" \
    "235 ok\r\n" \
    "250 OK\r\n" \
    "221 Bye\r\n"
/* Negative B: no auth-required challenge. */
#define R8_NEGB_RESP \
    "220 mail ESMTP\r\n" \
    "250 x\r\n" \
    "250 OK\r\n" \
    "221 Bye\r\n"

/* R9: broker delivers a $SYS-topic PUBLISH. */
#define R9_POS_RESP \
    "\x20\x02\x00\x00"              /* CONNACK accept            */ \
    "\x30\x11\x00\x0a$SYS/broker"   /* PUBLISH $SYS/broker       */ \
    "hello"
/* Negative A: ordinary topic delivered. */
#define R9_NEGA_RESP \
    "\x20\x02\x00\x00" \
    "\x30\x0c\x00\x03a/bhello"
/* Negative B: $SYS in a CONNECT payload only — no delivery. */
#define R9_NEGB_REGION_2 "\x82\x08\x00\x01\x00\x05$SYS/\x00"

/* R10: broker delivers the same QoS 2 pid twice.
 * Remaining-length must count EVERYTHING after the RL varint:
 * topic-len(2) + topic(5) + pid(2) + payload(7) = 16 = 0x10. */
#define R10_POS_RESP \
    "\x20\x02\x00\x00"              /* CONNACK accept                 */ \
    "\x34\x10\x00\x05topic\x00\x07payload" /* QoS2 PUBLISH pid=7       */ \
    "\x34\x10\x00\x05topic\x00\x07payload" /* duplicate QoS2 pid=7     */
/* Negative A: two different QoS 2 pids. */
#define R10_NEGA_RESP \
    "\x20\x02\x00\x00" \
    "\x34\x10\x00\x05topic\x00\x07payload" \
    "\x34\x10\x00\x05topic\x00\x08payload"
/* Negative B: same topic repeated but QoS 0 (no pid semantics). */
#define R10_NEGB_RESP \
    "\x20\x02\x00\x00" \
    "\x30\x0c\x00\x05topicpayload" \
    "\x30\x0c\x00\x05topicpayload"

/* CL-conflict tightening fixtures (forked-daapd EFF-batch FP audit).
 * Positive: two CLs with genuinely different values, accepted with 2xx. */
#define CL_POS_REGION \
    "GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 999\r\n\r\n"
#define CL_POS_RESP \
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
/* Negative A: the audited FP shape — "0" + binary junk + embedded GET inside
 * the first CL value (splicing artifact), second CL clean "0".  All numeric
 * values agree; server 200s the valid prefix.  Must NOT fire. */
#define CL_NEGA_REGION \
    "GET /server-info HTTP/1.1\r\nHost: a\r\nContent-Length: 0\x00\x01\x00\x00GET /api/search HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
#define CL_NEGA_RESP \
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
/* Negative B: mangled value ("Content-Length:set=0 HTTP/1.1" carries no
 * digits) plus a clean CL 0 — and the response window contains a 400 for the
 * malformed tail, so even the numeric path must be rejected.  Must NOT fire. */
#define CL_NEGB_REGION \
    "GET / HTTP/1.1\r\nHost: a\r\nContent-Length:set=0 HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
#define CL_NEGB_RESP \
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi" \
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

int main(void) {
    const unsigned char *reqs[8];
    unsigned int lens[8];

    /* Attack rules are env-gated in the oracle; enable for this driver. */
    setenv("CHATAFL_ATTACK_ORACLE", "1", 1);

    oracle_init("FTP");

    printf("== FTP ==\n");
    reqs[0] = (const unsigned char *)REGION_1; lens[0] = sizeof(REGION_1)-1;
    reqs[1] = (const unsigned char *)REGION_3; lens[1] = sizeof(REGION_3)-1;
    run_check("FTP", reqs, lens, 2, (const unsigned char *)FTP_RESP, sizeof(FTP_RESP)-1);

    reqs[0] = (const unsigned char *)REGION_2; lens[0] = sizeof(REGION_2)-1;
    run_check("FTP", reqs, lens, 1, (const unsigned char *)FTP_RESP, sizeof(FTP_RESP)-1);

    printf("== SMTP ==\n");
    reqs[0] = (const unsigned char *)SMTP_REGION_1; lens[0] = sizeof(SMTP_REGION_1)-1;
    run_check("SMTP", reqs, lens, 1, (const unsigned char *)SMTP_RESP, sizeof(SMTP_RESP)-1);

    reqs[0] = (const unsigned char *)SMTP_REGION_2; lens[0] = sizeof(SMTP_REGION_2)-1;
    run_check("SMTP", reqs, lens, 1, (const unsigned char *)SMTP_RESP, sizeof(SMTP_RESP)-1);

    printf("== RTSP ==\n");
    reqs[0] = (const unsigned char *)RTSP_REGION_1; lens[0] = sizeof(RTSP_REGION_1)-1;
    reqs[1] = (const unsigned char *)RTSP_REGION_2; lens[1] = sizeof(RTSP_REGION_2)-1;
    reqs[2] = (const unsigned char *)RTSP_REGION_3; lens[2] = sizeof(RTSP_REGION_3)-1;
    run_check("RTSP", reqs, lens, 3, (const unsigned char *)RTSP_RESP_2, sizeof(RTSP_RESP_2)-1);

    printf("== HTTP ==\n");
    reqs[0] = (const unsigned char *)HTTP_REGION_1; lens[0] = sizeof(HTTP_REGION_1)-1;
    reqs[1] = (const unsigned char *)HTTP_REGION_2; lens[1] = sizeof(HTTP_REGION_2)-1;
    reqs[2] = (const unsigned char *)HTTP_REGION_3; lens[2] = sizeof(HTTP_REGION_3)-1;
    run_check("HTTP", reqs, lens, 3, (const unsigned char *)HTTP_RESP, sizeof(HTTP_RESP)-1);

    printf("== MQTT ==\n");
    reqs[0] = (const unsigned char *)MQTT_CONNECT;   lens[0] = sizeof(MQTT_CONNECT)-1;
    reqs[1] = (const unsigned char *)MQTT_SUBSCRIBE; lens[1] = sizeof(MQTT_SUBSCRIBE)-1;
    run_check("MQTT", reqs, lens, 2, (const unsigned char *)MQTT_RESP, sizeof(MQTT_RESP)-1);

    reqs[0] = (const unsigned char *)MQTT_PUBLISH; lens[0] = sizeof(MQTT_PUBLISH)-1;
    run_check("MQTT", reqs, lens, 1, (const unsigned char *)MQTT_RESP, sizeof(MQTT_RESP)-1);

    printf("== SIP (stub) ==\n");
    run_check("SIP", reqs, lens, 1, (const unsigned char *)MQTT_RESP, sizeof(MQTT_RESP)-1);

    printf("== DAAP ==\n");
    reqs[0] = (const unsigned char *)HTTP_REGION_1; lens[0] = sizeof(HTTP_REGION_1)-1;
    run_check("DAAP", reqs, lens, 1, (const unsigned char *)HTTP_RESP, sizeof(HTTP_RESP)-1);

    /* ── Attack-rule fixtures: R1-R10, one positive + two negatives each ── */
    printf("== ATTACK RULES (CHATAFL_ATTACK_ORACLE=1) ==\n");

    printf("  -- R1 FTP unauth filesystem command --\n");
    reqs[0] = (const unsigned char *)R1_POS_REGION; lens[0] = sizeof(R1_POS_REGION)-1;
    run_expect("R1 pos: MKD 257 no 230", "FTP", reqs, lens, 1,
               (const unsigned char *)R1_POS_RESP, sizeof(R1_POS_RESP)-1,
               1, 16, ORACLE_CAT_AUTH_BYPASS);
    reqs[0] = (const unsigned char *)R1_NEGA_REGION; lens[0] = sizeof(R1_NEGA_REGION)-1;
    run_expect("R1 negA: login precedes MKD", "FTP", reqs, lens, 1,
               (const unsigned char *)R1_NEGA_RESP, sizeof(R1_NEGA_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R1_NEGB_REGION; lens[0] = sizeof(R1_NEGB_REGION)-1;
    run_expect("R1 negB: MKD 550", "FTP", reqs, lens, 1,
               (const unsigned char *)R1_NEGB_RESP, sizeof(R1_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R2 FTP RNTO deep traversal --\n");
    reqs[0] = (const unsigned char *)R2_POS_REGION; lens[0] = sizeof(R2_POS_REGION)-1;
    run_expect("R2 pos: RNTO depth4 250", "FTP", reqs, lens, 1,
               (const unsigned char *)R2_POS_RESP, sizeof(R2_POS_RESP)-1,
               1, 16, ORACLE_CAT_PATH_TRAVERSAL);
    reqs[0] = (const unsigned char *)R2_NEGA_REGION; lens[0] = sizeof(R2_NEGA_REGION)-1;
    run_expect("R2 negA: depth1", "FTP", reqs, lens, 1,
               (const unsigned char *)R2_NEGA_RESP, sizeof(R2_NEGA_RESP)-1,
               1, 16, ORACLE_CAT_PATH_TRAVERSAL);
    reqs[0] = (const unsigned char *)R2_NEGB_REGION; lens[0] = sizeof(R2_NEGB_REGION)-1;
    run_expect("R2 negB: 550", "FTP", reqs, lens, 1,
               (const unsigned char *)R2_NEGB_RESP, sizeof(R2_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R3 RTSP PLAY before SETUP (existing rule) --\n");
    reqs[0] = (const unsigned char *)R3_POS_REGION_1; lens[0] = sizeof(R3_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R3_POS_REGION_2; lens[1] = sizeof(R3_POS_REGION_2)-1;
    run_expect("R3 pos: PLAY no SETUP 200", "RTSP", reqs, lens, 2,
               (const unsigned char *)R3_POS_RESP, sizeof(R3_POS_RESP)-1,
               1, 16, ORACLE_CAT_STATE_VIOLATION);
    reqs[0] = (const unsigned char *)R3_POS_REGION_1; lens[0] = sizeof(R3_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R3_NEGA_REGION_2; lens[1] = sizeof(R3_NEGA_REGION_2)-1;
    run_expect("R3 negA: SETUP precedes PLAY", "RTSP", reqs, lens, 2,
               (const unsigned char *)R3_NEGA_RESP, sizeof(R3_NEGA_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R3_POS_REGION_1; lens[0] = sizeof(R3_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R3_POS_REGION_2; lens[1] = sizeof(R3_POS_REGION_2)-1;
    run_expect("R3 negB: PLAY 454", "RTSP", reqs, lens, 2,
               (const unsigned char *)R3_NEGB_RESP, sizeof(R3_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R4 RTSP forged Session --\n");
    reqs[0] = (const unsigned char *)R4_POS_REGION_1; lens[0] = sizeof(R4_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R4_POS_REGION_2; lens[1] = sizeof(R4_POS_REGION_2)-1;
    run_expect("R4 pos: forged Session 200", "RTSP", reqs, lens, 2,
               (const unsigned char *)R4_POS_RESP, sizeof(R4_POS_RESP)-1,
               1, 16, ORACLE_CAT_AUTH_BYPASS);
    reqs[0] = (const unsigned char *)R4_NEGA_REGION_1; lens[0] = sizeof(R4_NEGA_REGION_1)-1;
    reqs[1] = (const unsigned char *)R4_POS_REGION_2; lens[1] = sizeof(R4_POS_REGION_2)-1;
    run_expect("R4 negA: one issued session", "RTSP", reqs, lens, 2,
               (const unsigned char *)R4_NEGA_RESP, sizeof(R4_NEGA_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R4_POS_REGION_1; lens[0] = sizeof(R4_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R4_NEGB_REGION_2; lens[1] = sizeof(R4_NEGB_REGION_2)-1;
    run_expect("R4 negB: issued Session 111", "RTSP", reqs, lens, 2,
               (const unsigned char *)R4_NEGB_RESP, sizeof(R4_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R5 RTSP URL traversal telemetry --\n");
    reqs[0] = (const unsigned char *)R5_POS_REGION; lens[0] = sizeof(R5_POS_REGION)-1;
    run_expect("R5 pos: ../.. accepted", "RTSP", reqs, lens, 1,
               (const unsigned char *)R5_POS_RESP, sizeof(R5_POS_RESP)-1,
               1, 16, ORACLE_CAT_PATH_TRAVERSAL);
    reqs[0] = (const unsigned char *)R5_NEGA_REGION; lens[0] = sizeof(R5_NEGA_REGION)-1;
    run_expect("R5 negA: plain URL", "RTSP", reqs, lens, 1,
               (const unsigned char *)R5_POS_RESP, sizeof(R5_POS_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R5_POS_REGION; lens[0] = sizeof(R5_POS_REGION)-1;
    run_expect("R5 negB: 404", "RTSP", reqs, lens, 1,
               (const unsigned char *)R5_NEGB_RESP, sizeof(R5_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R6 SIP auth challenge then unauth INVITE 200 --\n");
    reqs[0] = (const unsigned char *)R6_POS_REGION_1; lens[0] = sizeof(R6_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R6_POS_REGION_2; lens[1] = sizeof(R6_POS_REGION_2)-1;
    run_expect("R6 pos: 401 then 200", "SIP", reqs, lens, 2,
               (const unsigned char *)R6_POS_RESP, sizeof(R6_POS_RESP)-1,
               1, 16, ORACLE_CAT_AUTH_BYPASS);
    reqs[0] = (const unsigned char *)R6_POS_REGION_1; lens[0] = sizeof(R6_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R6_NEGA_REGION_2; lens[1] = sizeof(R6_NEGA_REGION_2)-1;
    run_expect("R6 negA: INVITE has creds", "SIP", reqs, lens, 2,
               (const unsigned char *)R6_POS_RESP, sizeof(R6_POS_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R6_POS_REGION_1; lens[0] = sizeof(R6_POS_REGION_1)-1;
    reqs[1] = (const unsigned char *)R6_POS_REGION_2; lens[1] = sizeof(R6_POS_REGION_2)-1;
    run_expect("R6 negB: no challenge", "SIP", reqs, lens, 2,
               (const unsigned char *)R6_NEGB_RESP, sizeof(R6_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R7 SIP malformed Via --\n");
    reqs[0] = (const unsigned char *)R7_POS_REGION; lens[0] = sizeof(R7_POS_REGION)-1;
    run_expect("R7 pos: Via:xx 200", "SIP", reqs, lens, 1,
               (const unsigned char *)R7_POS_RESP, sizeof(R7_POS_RESP)-1,
               1, 16, 0);
    reqs[0] = (const unsigned char *)R7_NEGA_REGION; lens[0] = sizeof(R7_NEGA_REGION)-1;
    run_expect("R7 negA: valid Via", "SIP", reqs, lens, 1,
               (const unsigned char *)R7_POS_RESP, sizeof(R7_POS_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R7_POS_REGION; lens[0] = sizeof(R7_POS_REGION)-1;
    run_expect("R7 negB: 400", "SIP", reqs, lens, 1,
               (const unsigned char *)R7_NEGB_RESP, sizeof(R7_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R8 SMTP MAIL despite 530 --\n");
    reqs[0] = (const unsigned char *)R8_POS_REGION; lens[0] = sizeof(R8_POS_REGION)-1;
    run_expect("R8 pos: 530 then 250", "SMTP", reqs, lens, 1,
               (const unsigned char *)R8_POS_RESP, sizeof(R8_POS_RESP)-1,
               1, 16, ORACLE_CAT_AUTH_BYPASS);
    reqs[0] = (const unsigned char *)R8_NEGA_REGION; lens[0] = sizeof(R8_NEGA_REGION)-1;
    run_expect("R8 negA: AUTH 235 first", "SMTP", reqs, lens, 1,
               (const unsigned char *)R8_NEGA_RESP, sizeof(R8_NEGA_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R8_POS_REGION; lens[0] = sizeof(R8_POS_REGION)-1;
    run_expect("R8 negB: no challenge", "SMTP", reqs, lens, 1,
               (const unsigned char *)R8_NEGB_RESP, sizeof(R8_NEGB_RESP)-1,
               0, 0, 0);

    printf("  -- R9 MQTT $SYS delivery --\n");
    reqs[0] = (const unsigned char *)MQTT_CONNECT; lens[0] = sizeof(MQTT_CONNECT)-1;
    run_expect("R9 pos: $SYS delivered", "MQTT", reqs, lens, 1,
               (const unsigned char *)R9_POS_RESP, sizeof(R9_POS_RESP)-1,
               1, 16, ORACLE_CAT_ISOLATION);
    run_expect("R9 negA: ordinary topic", "MQTT", reqs, lens, 1,
               (const unsigned char *)R9_NEGA_RESP, sizeof(R9_NEGA_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)R9_NEGB_REGION_2; lens[0] = sizeof(R9_NEGB_REGION_2)-1;
    run_expect("R9 negB: $SYS only in request", "MQTT", reqs, lens, 1,
               (const unsigned char *)R9_NEGA_RESP, sizeof(R9_NEGA_RESP)-1,
               0, 0, 0);

    printf("  -- R10 MQTT duplicate QoS2 pid --\n");
    reqs[0] = (const unsigned char *)MQTT_CONNECT; lens[0] = sizeof(MQTT_CONNECT)-1;
    run_expect("R10 pos: pid 7 twice", "MQTT", reqs, lens, 1,
               (const unsigned char *)R10_POS_RESP, sizeof(R10_POS_RESP)-1,
               1, 16, ORACLE_CAT_REPLAY);
    run_expect("R10 negA: distinct pids", "MQTT", reqs, lens, 1,
               (const unsigned char *)R10_NEGA_RESP, sizeof(R10_NEGA_RESP)-1,
               0, 0, 0);
    run_expect("R10 negB: QoS0 repeats", "MQTT", reqs, lens, 1,
               (const unsigned char *)R10_NEGB_RESP, sizeof(R10_NEGB_RESP)-1,
               0, 0, 0);

    /* CL-conflict rule tightening (forked-daapd EFF-batch FP audit): the
     * malformed-CL path must not fire when the trailing junk embeds a request
     * line (mutation artifact) or when the whole value is mangled — and the
     * 400-rejection check must scan ALL response blocks, not just the nth. */
    printf("  -- CL-conflict tightening (daapd FP audit) --\n");
    reqs[0] = (const unsigned char *)CL_POS_REGION; lens[0] = sizeof(CL_POS_REGION)-1;
    run_expect("CL pos: 5 vs 999 accepted", "HTTP", reqs, lens, 1,
               (const unsigned char *)CL_POS_RESP, sizeof(CL_POS_RESP)-1,
               1, 16, ORACLE_CAT_SMUGGLING);
    reqs[0] = (const unsigned char *)CL_NEGA_REGION; lens[0] = sizeof(CL_NEGA_REGION)-1;
    run_expect("CL negA: artifact GET in value", "HTTP", reqs, lens, 1,
               (const unsigned char *)CL_NEGA_RESP, sizeof(CL_NEGA_RESP)-1,
               0, 0, 0);
    reqs[0] = (const unsigned char *)CL_NEGB_REGION; lens[0] = sizeof(CL_NEGB_REGION)-1;
    run_expect("CL negB: mangled value + 400", "HTTP", reqs, lens, 1,
               (const unsigned char *)CL_NEGB_RESP, sizeof(CL_NEGB_RESP)-1,
               0, 0, 0);

    /* ── Binding-hardening regression (Aug-25 batch FPs, 2026-08-25) ──
     * Three live-batch false positives, minimized.  Each reproduces the
     * exact root cause fixed by the framing-integrity gate (CRLF defects,
     * AUTH-continuation ambiguity) and the RTSP first-line binding guard. */

    /* FP1 bftpd: unterminated binary message merges with RNTO at the
     * server; XCUP's 250 shifts onto the RNTO slot.  Must NOT fire. */
    {
        static const unsigned char fp1_m1[] = "USER ubuntu\r\n";
        static const unsigned char fp1_m2[] = { 'X', 0x80, 0x00, 0x00, 0x00, 0x14 };
        static const unsigned char fp1_m3[] = "RNTO renamed_test\r\n";
        static const unsigned char fp1_m4[] = "XCUP\r\n";
        static const unsigned char fp1_resp[] =
            "220 bftpd ready\r\n331 Password please\r\n500 Unknown\r\n"
            "250 OK\r\n257 /\" is cwd\r\n";
        reqs[0] = fp1_m1; lens[0] = sizeof(fp1_m1) - 1;
        reqs[1] = fp1_m2; lens[1] = sizeof(fp1_m2);
        reqs[2] = fp1_m3; lens[2] = sizeof(fp1_m3) - 1;
        reqs[3] = fp1_m4; lens[3] = sizeof(fp1_m4) - 1;
        run_expect("BH1: unterminated msg merge (bftpd FP)", "FTP",
                   reqs, lens, 4, fp1_resp, sizeof(fp1_resp) - 1, 0, 0, 0);
    }

    /* FP2a exim: AUTH line followed by another line in the same message —
     * server consumed it as SASL continuation, one reply for two slots;
     * MAIL bound to 354, queue-250 onto RCPT.  Must NOT fire. */
    {
        static const unsigned char fp2_m1[] = "EHLO x\r\n";
        static const unsigned char fp2_m2[] =
            "AUTH PLAIN abcdefgh\r\nGHJUNKLINE\r\n";
        static const unsigned char fp2_m3[] = "MAIL FROM:<a@b.c>\r\n";
        static const unsigned char fp2_m4[] = "RCPT TO:<c@d.e>\r\n";
        static const unsigned char fp2_m5[] = "QUIT\r\n";
        static const unsigned char fp2_resp[] =
            "220 mail ESMTP\r\n250-x\r\n250 HELP\r\n"
            "503 AUTH command used when not advertised\r\n"
            "250 OK\r\n251 Accepted\r\n221 Bye\r\n";
        reqs[0] = fp2_m1; lens[0] = sizeof(fp2_m1) - 1;
        reqs[1] = fp2_m2; lens[1] = sizeof(fp2_m2) - 1;
        reqs[2] = fp2_m3; lens[2] = sizeof(fp2_m3) - 1;
        reqs[3] = fp2_m4; lens[3] = sizeof(fp2_m4) - 1;
        reqs[4] = fp2_m5; lens[4] = sizeof(fp2_m5) - 1;
        run_expect("BH2: AUTH continuation shift (exim FP)", "SMTP",
                   reqs, lens, 5, fp2_resp, sizeof(fp2_resp) - 1, 0, 0, 0);
    }

    /* FP2b exim (bare-LF variant): embedded bare \n creates a phantom
     * slot the server never saw.  Must NOT fire. */
    {
        static const unsigned char fp2b_m1[] = "EHLO x\r\n";
        static const unsigned char fp2b_m2[] = "AUTH PLAIN abc\nDEF\r\n";
        static const unsigned char fp2b_m3[] = "MAIL FROM:<a@b.c>\r\n";
        static const unsigned char fp2b_m4[] = "RCPT TO:<c@d.e>\r\n";
        static const unsigned char fp2b_resp[] =
            "220 m\r\n250 h\r\n503 no auth\r\n250 OK\r\n251 ok\r\n";
        reqs[0] = fp2b_m1; lens[0] = sizeof(fp2b_m1) - 1;
        reqs[1] = fp2b_m2; lens[1] = sizeof(fp2b_m2) - 1;
        reqs[2] = fp2b_m3; lens[2] = sizeof(fp2b_m3) - 1;
        reqs[3] = fp2b_m4; lens[3] = sizeof(fp2b_m4) - 1;
        run_expect("BH3: bare-LF phantom slot (exim FP)", "SMTP",
                   reqs, lens, 4, fp2b_resp, sizeof(fp2b_resp) - 1, 0, 0, 0);
    }

    /* FP3 live555: mutation merged SETUP (corrupted CSeq header) and a
     * second embedded PLAY line into one message; the PLAY's CSeq
     * uniquely matched the SETUP's 201 Created + Session + RTP-Info
     * block, and its Session header was corrupted so the session-reuse
     * guard could not see it.  Embedded methods must not bind. */
    {
        static const unsigned char fp3_m1[] =
            "SETUP rtsp://127.0.0.1:8554/a/track1 RTSP/1.0\r\n"
            "CSmq: 3\r\nTransport: RTP/AVP;unicast\r\n\r\n"
            "PLAY rtsp://127.0.0.1:8554/b/ RTSP/1.0\r\nCSeq: 5\r\n"
            "Ses\xbfion: 000022B8\r\nRange: npt=0-\r\n\r\n";
        static const unsigned char fp3_resp[] =
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"
            "RTSP/1.0 201 OK\r\nCSeq: 5\r\nSession: 000022B8\r\n"
            "RTP-Info: url=rtsp://127.0.0.1:8554/b/\r\n\r\n";
        reqs[0] = fp3_m1; lens[0] = sizeof(fp3_m1) - 1;
        run_expect("BH4: embedded 2nd method (live555 FP)", "RTSP",
                   reqs, lens, 1, fp3_resp, sizeof(fp3_resp) - 1, 0, 0, 0);
    }

    /* BH5 (FN recovery): a GENUINE R2 hit in the trusted prefix of a
     * sequence whose LATER message carries a framing defect.  The old
     * whole-sequence gate suppressed this; the per-slot trust limit must
     * keep the early RNTO binding live and the rule firing. */
    {
        static const unsigned char fp5_m1[] = "USER u\r\n";
        static const unsigned char fp5_m2[] = "RNTO ../../evil\r\n";
        static const unsigned char fp5_m3[] = { 'J', 'U', 'N', 'K', 0x01, 0x02 };
        static const unsigned char fp5_resp[] =
            "220 bftpd ready\r\n331 pw\r\n250 OK renamed\r\n500 junk\r\n";
        reqs[0] = fp5_m1; lens[0] = sizeof(fp5_m1) - 1;
        reqs[1] = fp5_m2; lens[1] = sizeof(fp5_m2) - 1;
        reqs[2] = fp5_m3; lens[2] = sizeof(fp5_m3);
        run_expect("BH5: FN recovery, trusted prefix fires", "FTP",
                   reqs, lens, 3, fp5_resp, sizeof(fp5_resp) - 1,
                   1, 16, ORACLE_CAT_PATH_TRAVERSAL);
    }

    printf("\nORACLE SELF-TEST PASSED: %d oracle_check() executions, "
           "fast==slow on every path.\n", g_checks);
    if (g_expect_failures) {
        printf("ORACLE SELF-TEST FAILED: %d attack-rule expectation(s) "
               "not met.\n", g_expect_failures);
        return 1;
    }
    printf("All %d attack-rule fixtures met their expectations.\n",
           38);
    return 0;
}
