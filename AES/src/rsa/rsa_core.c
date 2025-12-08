#include "rsa/rsa_core.h"
#include <string.h> // memset

/* - RSAContext 초기화: n/exp 세팅, 없으면 zero 상태 유지 */
void rsa_ctx_init(RSAContext* ctx, const BigInt* n, const BigInt* exp) {
    if (!ctx) return;

    bi_zero(&ctx->n);
    bi_zero(&ctx->exp);
    ctx->modulus_bytes = 0;

    if (!n || !exp) {
        return;
    }

    ctx->n   = *n;
    ctx->exp = *exp;

    // n 을 big-endian 바이트로 표현했을 때 필요한 길이
    ctx->modulus_bytes = bi_to_be_bytes(&ctx->n, NULL, 0);
}

/* - 공통 pow 헬퍼: m^exp mod n 수행 후 modulus_bytes 길이로 right-pad */
static int rsa_core_pow(const RSAContext* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    if (!ctx || !out) return -1;
    if (ctx->modulus_bytes == 0) return -1;
    if (out_len < ctx->modulus_bytes) return -1;

    if (!in && in_len > 0) return -1;

    BigInt m;
    BigInt c;

    bi_zero(&m);
    bi_zero(&c);

    // in (big-endian) -> BigInt
    bi_from_be_bytes(&m, in, in_len);

    // m < n 확인 (RSA 기본 전제)
    if (bi_cmp(&m, &ctx->n) >= 0) {
        return -1;
    }

    // c = m^exp mod n
    bi_modexp(&c, &m, &ctx->exp, &ctx->n);

    // 출력 버퍼를 0으로 채우고, 하위 쪽에 결과를 right-align
    memset(out, 0, out_len);

    size_t needed = bi_to_be_bytes(&c, NULL, 0);
    if (needed > ctx->modulus_bytes) {
        // 이론상 나오면 안 되는 상황
        return -1;
    }

    if (needed > 0) {
        size_t offset = ctx->modulus_bytes - needed;
        (void)bi_to_be_bytes(&c, out + offset, needed);
    }

    return 0;
}

/* - 한 블록 암호화: pow 헬퍼 그대로 사용 */
int rsa_encrypt_block(const RSAContext* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    // encrypt/decrypt 모두 동일 pow 연산
    return rsa_core_pow(ctx, in, in_len, out, out_len);
}

/* - 한 블록 복호화: 입력 길이 검증 후 pow 헬퍼 */
int rsa_decrypt_block(const RSAContext* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    if (!ctx) return -1;

    // 암호문 블록은 항상 modulus_bytes 길이라고 가정
    if (in_len != ctx->modulus_bytes) {
        return -1;
    }

    return rsa_core_pow(ctx, in, in_len, out, out_len);
}
