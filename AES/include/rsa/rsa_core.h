#ifndef RSA_CORE_H
#define RSA_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "bigint/bigint.h"

/*
 * RSA Core Context
 *  - n   : modulus
 *  - exp : exponent (e or d)
 *  - modulus_bytes : n 을 big-endian 바이트로 표현했을 때 길이
 */
typedef struct {
    BigInt n;
    BigInt exp;
    size_t modulus_bytes;
} RSAContext;

/*
 * rsa_ctx_init
 *  - ctx  : 초기화할 컨텍스트
 *  - n    : modulus
 *  - exp  : exponent (e 또는 d)
 *
 *  효과:
 *  - ctx->n, ctx->exp 에 값을 복사
 *  - ctx->modulus_bytes 를 n 의 바이트 길이로 설정
 */
void rsa_ctx_init(RSAContext* ctx,
                  const BigInt* n,
                  const BigInt* exp);

/*
 * rsa_encrypt_block
 *
 *  입력:
 *   - ctx      : RSAContext (n, e/d, modulus_bytes)
 *   - in       : 평문 블록 (big-endian)
 *   - in_len   : 평문 길이 (바이트)
 *   - out      : 암호문을 저장할 버퍼
 *   - out_len  : out 버퍼 크기 (modulus_bytes 이상이어야 함)
 *
 *  제약:
 *   - 0 <= in < n 이어야 함 (그렇지 않으면 -1 리턴)
 *
 *  출력:
 *   - 성공 시 0, 실패 시 -1
 *   - out[0..modulus_bytes-1] 에 항상 modulus_bytes 바이트 암호문 기록
 *     (필요하다면 상위 바이트 쪽에 0-padding)
 */
int rsa_encrypt_block(const RSAContext* ctx,
                      const uint8_t* in, size_t in_len,
                      uint8_t* out, size_t out_len);

/*
 * rsa_decrypt_block
 *
 *  입력:
 *   - ctx      : RSAContext (n, e/d, modulus_bytes)
 *   - in       : 암호문 블록 (항상 modulus_bytes 바이트)
 *   - in_len   : 암호문 길이 (ctx->modulus_bytes 이어야 함)
 *   - out      : 평문을 저장할 버퍼
 *   - out_len  : out 버퍼 크기 (modulus_bytes 이상)
 *
 *  출력:
 *   - 성공 시 0, 실패 시 -1
 *   - out[0..modulus_bytes-1] 에 항상 modulus_bytes 바이트 평문 기록
 *     (필요하다면 상위 바이트 쪽에 0-padding)
 *   - ZeroPadding strip 은 여기서 하지 않음 (위 레이어에서 처리)
 */
int rsa_decrypt_block(const RSAContext* ctx,
                      const uint8_t* in, size_t in_len,
                      uint8_t* out, size_t out_len);

#endif /* RSA_CORE_H */
