#include "big_int.h"
#include <stdio.h>

static void bi_normalize(BigInt* a) {
    while (a->nlimbs > 0 && a->limb[a->nlimbs - 1] == 0)
        a->nlimbs--;
}

void bi_zero(BigInt* r) {
    for (size_t i = 0; i < BI_MAX_WORDS; i++)
        r->limb[i] = 0;
    r->nlimbs = 0;
}

void bi_from_u64(BigInt* r, uint64_t v) {
    bi_zero(r);
    if (v == 0) return;
    r->limb[0] = v;
    r->nlimbs = 1;
}

int bi_is_zero(const BigInt* a) {
    return a->nlimbs == 0;
}

int bi_cmp(const BigInt* a, const BigInt* b) {
    if (a->nlimbs < b->nlimbs) return -1;
    if (a->nlimbs > b->nlimbs) return 1;

    for (size_t i = a->nlimbs; i-- > 0;) {
        if (a->limb[i] < b->limb[i]) return -1;
        if (a->limb[i] > b->limb[i]) return 1;
    }
    return 0;
}

void bi_add(BigInt *r, const BigInt *a, const BigInt *b) {
    const BigInt *x = a;
    const BigInt *y = b;
    if (b->nlimbs > a->nlimbs) {
        x = b;
        y = a;
    }

    uint64_t carry = 0;
    size_t i = 0;
    for (; i < y->nlimbs; i++) {
        __uint128_t sum = (__uint128_t)x->limb[i]
                        + (__uint128_t)y->limb[i]
                        + carry;
        r->limb[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    // x 나머지
    for (; i < x->nlimbs; i++) {
        __uint128_t sum = (__uint128_t)x->limb[i] + carry;
        r->limb[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    if (carry != 0) {
        r->limb[i++] = carry;
    }
    r->nlimbs = i;

    // 상한 체크는 여기선 생략 (과제용이면 assert 넣어도 됨)
}

void bi_sub(BigInt *r, const BigInt *a, const BigInt *b) {
    uint64_t borrow = 0;
    size_t i = 0;
    for (; i < b->nlimbs; i++) {
        uint64_t av = a->limb[i];
        uint64_t bv = b->limb[i];
        uint64_t sub = av - bv - borrow;
        r->limb[i] = sub;
        // borrow 계산: av < bv + 이전 borrow 이면 새 borrow = 1
        uint64_t need = bv + borrow;
        borrow = (av < need) ? 1 : 0;
    }
    for (; i < a->nlimbs; i++) {
        uint64_t av = a->limb[i];
        uint64_t sub = av - borrow;
        r->limb[i] = sub;
        borrow = (av < borrow) ? 1 : 0;
    }
    r->nlimbs = a->nlimbs;
    bi_normalize(r);
}

// O(N^2) : [TODO] OPT
void bi_mul(BigInt *r, const BigInt *a, const BigInt *b) {
    // 임시 결과 버퍼 0으로 클리어
    BigInt tmp;
    bi_zero(&tmp);

    if (a->nlimbs == 0 || b->nlimbs == 0) {
        bi_zero(r);
        return;
    }

    // 기본 곱셈: tmp.limb[i+j] += a[i] * b[j]
    for (size_t i = 0; i < a->nlimbs; i++) {
        __uint128_t carry = 0;
        for (size_t j = 0; j < b->nlimbs; j++) {
            size_t k = i + j;
            __uint128_t cur = (__uint128_t)a->limb[i] * (__uint128_t)b->limb[j]
                            + (__uint128_t)tmp.limb[k]
                            + carry;
            tmp.limb[k] = (uint64_t)cur;
            carry = cur >> 64;
        }
        tmp.limb[i + b->nlimbs] = (uint64_t)carry;
    }

    tmp.nlimbs = a->nlimbs + b->nlimbs;
    if (tmp.nlimbs > BI_MAX_WORDS) {
        // overflow: 과제용이면 assert 터뜨리거나 truncate
        // 여기서는 그냥 잘라두고 넘어간다고 가정
        tmp.nlimbs = BI_MAX_WORDS;
    }

    bi_normalize(&tmp);
    *r = tmp;
}


void bi_shl_bits(BigInt *r, const BigInt *a, unsigned kbits) {
    if (bi_is_zero(a) || kbits == 0) {
        *r = *a;
        return;
    }

    unsigned word_shift = kbits / BI_WORD_BITS;
    unsigned bit_shift  = kbits % BI_WORD_BITS;

    BigInt tmp;
    bi_zero(&tmp);

    uint64_t carry = 0;
    for (size_t i = 0; i < a->nlimbs; i++) {
        uint64_t v = a->limb[i];
        uint64_t low  = v << bit_shift;
        uint64_t high = (bit_shift == 0) ? 0 : (v >> (BI_WORD_BITS - bit_shift));

        size_t idx = i + word_shift;
        if (idx < BI_MAX_WORDS) {
            uint64_t prev = tmp.limb[idx];
            __uint128_t sum = (__uint128_t)prev + low + carry;
            tmp.limb[idx] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }

        if (high != 0) {
            size_t idx2 = i + word_shift + 1;
            if (idx2 < BI_MAX_WORDS) {
                __uint128_t sum2 = (__uint128_t)tmp.limb[idx2] + high + carry;
                tmp.limb[idx2] = (uint64_t)sum2;
                carry = (uint64_t)(sum2 >> 64);
            }
        }
    }

    tmp.nlimbs = a->nlimbs + word_shift + 2;
    if (tmp.nlimbs > BI_MAX_WORDS) tmp.nlimbs = BI_MAX_WORDS;
    bi_normalize(&tmp);
    *r = tmp;
}

void bi_print_hex(const BigInt *a) {
    if (a->nlimbs == 0) {
        printf("0x0\n");
        return;
    }
    printf("0x");
    // 가장 상위 limb부터 출력
    for (size_t i = a->nlimbs; i-- > 0; ) {
        if (i == a->nlimbs - 1)
            printf("%lx", a->limb[i]);        // 맨 앞에는 0 안 채우고
        else
            printf("%016lx", a->limb[i]);     // 그 다음부터는 항상 16자리
    }
    printf("\n");
}
