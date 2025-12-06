#ifndef BIGINT_H
#define BIGINT_H
/*
12.06 2048 연산을 위한 Big Int Module
[TODO] 모듈러 최적화는 시간이 되면 진행

*/
#include <stdint.h>
#include <stddef.h>

#define BI_WORD_BITS 64
#define BI_MAX_BITS 2048
#define BI_MAX_WORDS (BI_MAX_BITS / BI_WORD_BITS)

typedef struct {
    uint64_t limb[BI_MAX_WORDS];    // little endian: limb 0 = least significant
    size_t nlimbs;  // size of limb, occupied limb count
} BigInt;

// basic utils
void bi_zero(BigInt* r);    // r = 0
void bi_from_u64(BigInt* r, uint64_t v);    // r = v ( 0 <= v < 2^64)
int bi_is_zero(const BigInt* a);    // 0 : 1, else 0
int bi_cmp(const BigInt* a, const BigInt* b);   // a ? b (-1: a<b, 0: a==b, 1: a>b)

// arith - suppose that result is under BI_MAX_BITS
void bi_add(BigInt* r, const BigInt* a, const BigInt* b);
void bi_sub(BigInt* r, const BigInt* a, const BigInt* b);   // only a>=b
void bi_mul(BigInt* r, const BigInt* a, const BigInt* b);

// shift
void bi_shl_bits(BigInt* r, const BigInt* a, unsigned kbits);

void bi_print_hex(const BigInt*a);

// 이거 너무 느려서 추후에 Montgomery Mult 모듈로 교체 : 시간되면
void bi_mod(BigInt* r, const BigInt* a, const BigInt *m);
void bi_mulmod(BigInt* r, const BigInt* a, const BigInt* b, const BigInt* m);

int bi_from_hex(BigInt* b, const char *hex_str);
int bi_to_hex(const BigInt* b, char *buf, size_t buf_size);

// [12.06] added functions

// 바이트 배열 <-> BigInt (Big-Endian)
void   bi_from_be_bytes(BigInt* r, const uint8_t* buf, size_t len);
/* 
 * BigInt a 를 big-endian 바이트 배열로 변환
 * - out: 결과를 쓸 버퍼
 * - max_len: out 버퍼 최대 길이
 * - return: 실제로 필요한 바이트 수 (성공 시), 
 *           max_len 이 부족하면 0 리턴 (아무것도 안 씀)
 */
size_t bi_to_be_bytes(const BigInt* a, uint8_t* out, size_t max_len);

// 나눗셈/모듈러 (양의 정수 전제)
void   bi_div_mod(BigInt* q, BigInt* r, const BigInt* a, const BigInt* m);
void   bi_mod(BigInt* r, const BigInt* a, const BigInt* m);

// 모듈러 곱: r = (a * b) mod m
void   bi_modmul(BigInt* r, const BigInt* a, const BigInt* b, const BigInt* m);

// 모듈러 거듭제곱: r = (base^exp) mod mod
void   bi_modexp(BigInt* r, const BigInt* base, const BigInt* exp, const BigInt* mod);
#endif  // big_int.h