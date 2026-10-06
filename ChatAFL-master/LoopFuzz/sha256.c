/* SHA-256 (FIPS 180-4), self-contained, public-domain style implementation
 * for LoopFuzz run-config identity hardening (P0-2). */

#include "sha256.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t  buffer[64];
  size_t   buflen;
} sha256_ctx;

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
  0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
  0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
  0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
  0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
  0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64]) {
  uint32_t m[64], a, b, c, d, e, f, g, h, t1, t2;
  for (int i = 0; i < 16; i++)
    m[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) |
           ((uint32_t)data[i*4+2] << 8) | (uint32_t)data[i*4+3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROTR(m[i-15],7) ^ ROTR(m[i-15],18) ^ (m[i-15] >> 3);
    uint32_t s1 = ROTR(m[i-2],17) ^ ROTR(m[i-2],19) ^ (m[i-2] >> 10);
    m[i] = m[i-16] + s0 + m[i-7] + s1;
  }
  a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
  e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
    uint32_t ch = (e & f) ^ (~e & g);
    t1 = h + S1 + ch + K[i] + m[i];
    uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
  ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
  ctx->bitlen = 0; ctx->buflen = 0;
  ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
  ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
  ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
  ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    ctx->buffer[ctx->buflen++] = data[i];
    if (ctx->buflen == 64) {
      sha256_transform(ctx, ctx->buffer);
      ctx->bitlen += 512;
      ctx->buflen = 0;
    }
  }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
  uint64_t bitlen = ctx->bitlen + (uint64_t)ctx->buflen * 8; /* total msg bits */
  size_t i = ctx->buflen;
  ctx->buffer[i++] = 0x80;
  if (i > 56) {                     /* need a second block for the length */
    while (i < 64) ctx->buffer[i++] = 0;
    sha256_transform(ctx, ctx->buffer);
    i = 0;
  }
  while (i < 56) ctx->buffer[i++] = 0;
  for (int j = 0; j < 8; j++)
    ctx->buffer[63 - j] = (uint8_t)(bitlen >> (8 * j));
  sha256_transform(ctx, ctx->buffer);
  for (int j = 0; j < 8; j++) {
    out[j*4]   = (uint8_t)(ctx->state[j] >> 24);
    out[j*4+1] = (uint8_t)(ctx->state[j] >> 16);
    out[j*4+2] = (uint8_t)(ctx->state[j] >> 8);
    out[j*4+3] = (uint8_t)(ctx->state[j]);
  }
}

void sha256_buf(const void *data, size_t len, sha256_byte out[32]) {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, (const uint8_t *)data, len);
  sha256_final(&ctx, out);
}

int sha256_file(const char *path, sha256_byte out[32]) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  sha256_ctx ctx;
  sha256_init(&ctx);
  uint8_t buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    sha256_update(&ctx, buf, n);
  int err = ferror(f);
  fclose(f);
  if (err) return -1;
  sha256_final(&ctx, out);
  return 0;
}

void sha256_hex(const sha256_byte digest[32], char out[65]) {
  static const char hexd[] = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    out[i*2]   = hexd[digest[i] >> 4];
    out[i*2+1] = hexd[digest[i] & 0xf];
  }
  out[64] = 0;
}

#ifdef SHA256_SELFTEST
#include <stdlib.h>
int main(int argc, char **argv) {
  /* With a file argument: print its sha256 (compare with sha256sum).
   * Without: verify the FIPS test vectors. */
  if (argc > 1) {
    sha256_byte d[32]; char h[65];
    if (sha256_file(argv[1], d) != 0) { perror("sha256_file"); return 1; }
    sha256_hex(d, h); printf("%s  %s\n", h, argv[1]); return 0;
  }
  struct { const char *msg; const char *want; } tv[] = {
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
  };
  for (unsigned i = 0; i < sizeof(tv)/sizeof(tv[0]); i++) {
    sha256_byte d[32]; char h[65];
    sha256_buf(tv[i].msg, strlen(tv[i].msg), d);
    sha256_hex(d, h);
    if (strcmp(h, tv[i].want) != 0) {
      fprintf(stderr, "FAIL vec %u: got %s want %s\n", i, h, tv[i].want);
      return 1;
    }
  }
  printf("sha256 selftest: all vectors pass\n");
  return 0;
}
#endif
