#ifndef RSA_CORE_H
#define RSA_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "bigint/bigint.h"

/*
- RSA Core Context
- n   : modulus
- exp : exponent (e or d)
- modulus_bytes : n 을 big-endian 바이트로 표현했을 때 길이
*/
typedef struct {
    BigInt n;
    BigInt exp;
    size_t modulus_bytes;
} RSAContext;

/*
- rsa_ctx_init
- ctx  : 초기화할 컨텍스트
- n    : modulus
- exp  : exponent (e 또는 d)
- 효과: ctx->n, ctx->exp 복사 + modulus_bytes 설정
*/
void rsa_ctx_init(RSAContext* ctx, const BigInt* n, const BigInt* exp);

/*
- rsa_encrypt_block
- 입력: ctx, 평문 블록(in/in_len), out/out_len(>= modulus_bytes)
- 제약: 0 <= in < n
- 출력: 성공 0 / 실패 -1, out에 modulus_bytes 길이 암호문
*/
int rsa_encrypt_block(const RSAContext* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len);

/*
- rsa_decrypt_block
- 입력: ctx, 암호문 블록(in_len == modulus_bytes), out/out_len(>= modulus_bytes)
- 출력: 성공 0 / 실패 -1, out에 modulus_bytes 길이 평문 (strip은 상위에서 처리)
*/
int rsa_decrypt_block(const RSAContext* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len);

#endif /* RSA_CORE_H */
