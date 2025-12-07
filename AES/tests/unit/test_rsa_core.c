// tests/unit/test_rsa_core.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "bigint/bigint.h"
#include "rsa/rsa_core.h"

/*
gcc -Wall -Wextra -O2 \
  -Iinclude \
  src/bigint/bigint.c \
  src/rsa/rsa_core.c \
  tests/unit/test_rsa_core.c \
  -o build/unit/test_rsa_core

1. 교재예제키 Round trip
2. 같은 키 평문 0 블록 암복호
3. m >= n 평문 블록 암호화시 에러
4. rsa_decrypt_block block length 불일치 에러
5. rsa_ctx_init null 인자 처리 및 zero initialization
6. rsa_encrypt_block 출력버퍼가 너무 잦은 경우, 즉, out_len < modulus_bytes 에러
*/

/* 공통으로 쓰는 작은 RSA 키 (p=61, q=53) */
static void make_sample_key(BigInt *n, BigInt *e, BigInt *d) {
    /* p = 61, q = 53
     * n   = 3233
     * phi = 3120
     * e   = 17
     * d   = 2753
     */
    bi_from_u64(n, 3233u);
    bi_from_u64(e, 17u);
    bi_from_u64(d, 2753u);
}

/* [TC1] 기본 교재 예제: 65 ("A") 한 블록 encrypt/decrypt round-trip */
static void test_rsa_small_sample(void)
{
    BigInt n, e, d;
    make_sample_key(&n, &e, &d);

    RSAContext ctx_enc;
    RSAContext ctx_dec;
    rsa_ctx_init(&ctx_enc, &n, &e);
    rsa_ctx_init(&ctx_dec, &n, &d);

    /* 3233 = 0x0CA1 → 2 byte modulus */
    assert(ctx_enc.modulus_bytes == 2);
    assert(ctx_dec.modulus_bytes == 2);

    /* 평문: 65 = 0x0041 (big-endian 2바이트) */
    uint8_t m[2]  = { 0x00, 0x41 };
    uint8_t c[2]  = { 0, 0 };
    uint8_t m2[2] = { 0, 0 };

    int ret;

    ret = rsa_encrypt_block(&ctx_enc, m, sizeof(m), c, sizeof(c));
    assert(ret == 0);

    /* 2790 = 0x0AE6 */
    assert(c[0] == 0x0A);
    assert(c[1] == 0x0E6 % 0x100); /* 안전하게 써도 되지만, 그대로 하자 */
    assert(c[0] == 0x0A);
    assert(c[1] == 0xE6);

    ret = rsa_decrypt_block(&ctx_dec, c, sizeof(c), m2, sizeof(m2));
    assert(ret == 0);

    assert(m2[0] == m[0]);
    assert(m2[1] == m[1]);
}

/* [TC2] 평문이 0 (0x0000) 인 블록도 정상적으로 왕복 되는지 확인 */
static void test_rsa_zero_plain_block(void)
{
    BigInt n, e, d;
    make_sample_key(&n, &e, &d);

    RSAContext ctx_enc;
    RSAContext ctx_dec;
    rsa_ctx_init(&ctx_enc, &n, &e);
    rsa_ctx_init(&ctx_dec, &n, &d);

    assert(ctx_enc.modulus_bytes == 2);

    uint8_t m[2]  = { 0x00, 0x00 };
    uint8_t c[2]  = { 0, 0 };
    uint8_t m2[2] = { 0xFF, 0xFF }; /* 초기값 일부러 쓰레기 값 */

    int ret = rsa_encrypt_block(&ctx_enc, m, sizeof(m), c, sizeof(c));
    assert(ret == 0);

    ret = rsa_decrypt_block(&ctx_dec, c, sizeof(c), m2, sizeof(m2));
    assert(ret == 0);

    assert(m2[0] == 0x00);
    assert(m2[1] == 0x00);
}

/* [TC3] 평문 m >= n 인 경우 (RSA 전제 위반) → rsa_core_pow 가 -1 리턴하는지 */
static void test_rsa_m_ge_n_fail(void)
{
    BigInt n, e, d;
    make_sample_key(&n, &e, &d);

    RSAContext ctx_enc;
    rsa_ctx_init(&ctx_enc, &n, &e);
    assert(ctx_enc.modulus_bytes == 2);

    /* 4000 (0x0FA0) > 3233 (0x0CA1) */
    uint8_t bad_m[2] = { 0x0F, 0xA0 };
    uint8_t out_bad[2] = { 0, 0 };

    int ret = rsa_encrypt_block(&ctx_enc,
                                bad_m, sizeof(bad_m),
                                out_bad, sizeof(out_bad));
    assert(ret != 0);
}

/* [TC4] rsa_decrypt_block: in_len != modulus_bytes 인 경우 에러 리턴 */
static void test_rsa_decrypt_block_size_mismatch(void)
{
    BigInt n, e, d;
    make_sample_key(&n, &e, &d);

    RSAContext ctx_enc;
    RSAContext ctx_dec;
    rsa_ctx_init(&ctx_enc, &n, &e);
    rsa_ctx_init(&ctx_dec, &n, &d);

    uint8_t m[2]  = { 0x00, 0x41 };
    uint8_t c[2]  = { 0, 0 };
    uint8_t m2[2] = { 0, 0 };

    int ret = rsa_encrypt_block(&ctx_enc, m, sizeof(m), c, sizeof(c));
    assert(ret == 0);

    /* 암호문 제대로 된 길이(2바이트)로는 성공해야 함 */
    ret = rsa_decrypt_block(&ctx_dec, c, sizeof(c), m2, sizeof(m2));
    assert(ret == 0);

    /* 길이를 1로 줄이면 rsa_decrypt_block 에서 바로 실패해야 함 */
    uint8_t short_ct[1] = { c[0] };
    ret = rsa_decrypt_block(&ctx_dec, short_ct, sizeof(short_ct), m2, sizeof(m2));
    assert(ret != 0);
}

/* [TC5] rsa_ctx_init: NULL 인자 처리 + zero-initialization 동작 확인 */
static void test_rsa_ctx_init_null_params(void)
{
    BigInt n, e, d;
    make_sample_key(&n, &e, &d);

    /* ctx == NULL 이더라도 크래시 나지 않고 그냥 리턴해야 함 */
    rsa_ctx_init(NULL, &n, &e);

    /* n 또는 exp 가 NULL 이면 ctx 내용은 모두 0 으로 남아야 함 */
    RSAContext ctx;
    rsa_ctx_init(&ctx, &n, &e);
    assert(ctx.modulus_bytes == 2);

    /* 이제 n=NULL 로 넣어서 다시 초기화 → 전부 0 이 되어야 함 */
    rsa_ctx_init(&ctx, NULL, &e);
    assert(ctx.modulus_bytes == 0);
    assert(bi_is_zero(&ctx.n));
    assert(bi_is_zero(&ctx.exp));

    /* exp=NULL 로 넣는 경우도 동일하게 0 유지 */
    rsa_ctx_init(&ctx, &n, NULL);
    assert(ctx.modulus_bytes == 0);
    assert(bi_is_zero(&ctx.n));
    assert(bi_is_zero(&ctx.exp));
}

/* [TC6] out_len < modulus_bytes 인 경우 rsa_encrypt_block 이 실패하는지 */
static void test_rsa_out_buffer_too_small(void)
{
    BigInt n, e, d;
    make_sample_key(&n, &e, &d);

    RSAContext ctx_enc;
    rsa_ctx_init(&ctx_enc, &n, &e);
    assert(ctx_enc.modulus_bytes == 2);

    uint8_t m[2] = { 0x00, 0x41 };
    uint8_t small_out[1] = { 0 };

    /* out_len 이 1 < modulus_bytes(2) 이므로 -1 이어야 한다. */
    int ret = rsa_encrypt_block(&ctx_enc,
                                m, sizeof(m),
                                small_out, sizeof(small_out));
    assert(ret != 0);
}

int main(void)
{
    test_rsa_small_sample();
    test_rsa_zero_plain_block();
    test_rsa_m_ge_n_fail();
    test_rsa_decrypt_block_size_mismatch();
    test_rsa_ctx_init_null_params();
    test_rsa_out_buffer_too_small();

    printf("RSA core extended tests: OK\n");
    return 0;
}
