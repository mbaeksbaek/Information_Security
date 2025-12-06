#ifndef RSA_OPS_H
#define RSA_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_ops.h"

/*
 * RSA_OPS
 * - CryptoOps vtable 구현체
 * - RSA-ECB + ZeroPadding 모드
 *
 * Key format (key_hex -> bytes):
 *   [  N  |  EXP  ]
 *     ^      ^
 *     |      +-- e (encrypt 시) 또는 d (decrypt 시)
 *     +--------- modulus n (big-endian)
 *
 * - key_len 은 반드시 짝수 바이트
 * - key_len/2 바이트를 modulus, 나머지 key_len/2 바이트를 exponent 로 사용
 * - enc 시에는 (N || e), dec 시에는 (N || d)를 CLI 에서 넣어주면 됨.
 */
extern const CryptoOps RSA_OPS;

#endif /* RSA_OPS_H */
