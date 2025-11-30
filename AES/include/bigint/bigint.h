#ifndef BIGINT_H
#define BIGINT_H

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
#endif  // big_int.h