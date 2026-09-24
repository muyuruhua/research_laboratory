/* S2c unit test: deterministic mut_ur override, verify the amplification
 * shape on a stock in-ftp-like buffer. Not shipped into any image. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mutation-ops.h"

/* deterministic: middle-of-bound */
uint32_t mut_ur(uint32_t bound) { return bound ? bound / 2 : 0; }

int main(void) {
    /* stock seed shape: USER/PASS (excluded from S2c) + short verbs */
    const char *seed = "USER ubuntu\r\nPASS ubuntu\r\nSYST\r\nQUIT\r\n";
    uint8_t buf[1024 * 1024];
    uint32_t len = strlen(seed);
    memcpy(buf, seed, len);

    uint8_t r = cve_targeted_mutate(buf, &len, sizeof(buf), "FTP");
    printf("applied=%u new_len=%u escape_amp_applied=%llu\n",
           r, len, (unsigned long long)escape_amp_applied);

    /* verify: USER/PASS lines intact, one line is a quoted escape flood */
    int user_ok = memcmp(buf, "USER ubuntu\r\nPASS ubuntu\r\n", 26) == 0;
    printf("auth prefix intact: %s\n", user_ok ? "YES" : "NO");

    /* find the flood line: first '"' in the buffer */
    uint32_t flood_start = 0;
    while (flood_start < len && buf[flood_start] != '"') flood_start++;
    uint32_t flood_len = 0;
    while (flood_start + flood_len < len &&
           buf[flood_start + flood_len] != '\n') flood_len++;
    printf("flood line len=%u starts-with-quote=%c ends=%02x %02x %02x\n",
           flood_len, buf[flood_start],
           buf[flood_start + flood_len - 3], buf[flood_start + flood_len - 2],
           buf[flood_start + flood_len - 1]);
    printf("first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           buf[flood_start], buf[flood_start+1], buf[flood_start+2],
           buf[flood_start+3], buf[flood_start+4], buf[flood_start+5],
           buf[flood_start+6], buf[flood_start+7]);

    int pass = (r == 1) && user_ok && flood_len >= 30720 &&
               buf[flood_start] == '"' &&
               buf[flood_start+1] == '\\' &&
               buf[flood_start + flood_len - 4] == 0x22 &&
               buf[flood_start + flood_len - 3] == 0x20;
    printf("VERDICT: %s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
