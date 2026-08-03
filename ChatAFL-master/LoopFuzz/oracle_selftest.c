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

int main(void) {
    const unsigned char *reqs[8];
    unsigned int lens[8];

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

    printf("\nORACLE SELF-TEST PASSED: %d oracle_check() executions, "
           "fast==slow on every path.\n", g_checks);
    return 0;
}
