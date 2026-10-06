#ifndef __LOOPFUZZ_SHA256_H
#define __LOOPFUZZ_SHA256_H

/* Minimal self-contained SHA-256 (FIPS 180-4) for run-config identity
 * hardening (P0-2): fuzzer binary, target binary, seed corpus and config
 * hashes.  No external crypto dependency — verified against sha256sum by
 * the standalone check in sha256.c (SHA256_SELFTEST main) and by the
 * build-time smoke `make sha256_selftest && ./sha256_selftest`. */

#include <stddef.h>
typedef unsigned char sha256_byte;

/* Hash a buffer; out receives 32 bytes. */
void sha256_buf(const void *data, size_t len, sha256_byte out[32]);

/* Hash a whole file (0 on success, -1 on open/read failure). */
int sha256_file(const char *path, sha256_byte out[32]);

/* Lowercase hex encoding of a 32-byte digest into out[65]. */
void sha256_hex(const sha256_byte digest[32], char out[65]);

#endif /* __LOOPFUZZ_SHA256_H */
