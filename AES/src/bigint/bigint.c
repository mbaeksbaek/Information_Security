#include "bigint/bigint.h"
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

// ===== 내부 헬퍼: 비트 관련 함수들 =====

static size_t bi_bit_length(const BigInt* a) {
    if (a->nlimbs == 0) return 0;

    size_t hi = a->nlimbs - 1;
    uint64_t v = a->limb[hi];
    // v != 0 이라고 가정 (normalize 된 상태)
    unsigned bits = 0;
    while (v) {
        bits++;
        v >>= 1;
    }
    return hi * BI_WORD_BITS + bits;
}

static int bi_get_bit(const BigInt* a, size_t idx) {
    size_t word = idx / BI_WORD_BITS;
    unsigned bit = (unsigned)(idx % BI_WORD_BITS);
    if (word >= a->nlimbs) return 0;
    return (int)((a->limb[word] >> bit) & 1u);
}

static void bi_set_bit(BigInt* a, size_t idx) {
    size_t word = idx / BI_WORD_BITS;
    unsigned bit = (unsigned)(idx % BI_WORD_BITS);
    if (word >= BI_MAX_WORDS) {
        // 상위 비트는 잘라버림 (과제용)
        return;
    }
    if (a->nlimbs <= word) {
        // 중간 비트까지 0으로 채워줌
        for (size_t i = a->nlimbs; i <= word; i++) {
            a->limb[i] = 0;
        }
        a->nlimbs = word + 1;
    }
    a->limb[word] |= ((uint64_t)1u << bit);
}

// ===== Big-Endian 바이트 <-> BigInt =====

void bi_from_be_bytes(BigInt* r, const uint8_t* buf, size_t len) {
    bi_zero(r);
    if (!buf || len == 0) return;

    // leading zero 스킵
    size_t start = 0;
    while (start < len && buf[start] == 0) {
        start++;
    }
    if (start == len) {
        // 모두 0
        return;
    }

    size_t out_idx = 0;
    size_t i = len;

    // 뒤에서부터 8바이트씩 잘라서 limb 하나씩 채움 (little-endian limb)
    while (i > start && out_idx < BI_MAX_WORDS) {
        uint64_t limb = 0;
        unsigned shift = 0;
        // limb 하나 만들기
        for (unsigned b = 0; b < 8 && i > start; b++) {
            i--;
            limb |= ((uint64_t)buf[i]) << shift;
            shift += 8;
        }
        r->limb[out_idx++] = limb;
    }
    r->nlimbs = out_idx;
    bi_normalize(r);
}

size_t bi_to_be_bytes(const BigInt* a, uint8_t* out, size_t max_len) {
    if (a->nlimbs == 0) {
        // 0은 길이 0 으로 반환 (RSA 관점에서는 modulus 0은 말이 안 되지만,
        // 여기서는 "필요 없음"으로 처리)
        return 0;
    }

    size_t hi = a->nlimbs - 1;
    uint64_t v = a->limb[hi];

    // 최상위 limb에 실제로 필요한 바이트 수
    unsigned hi_bytes = 0;
    while (v) {
        hi_bytes++;
        v >>= 8;
    }
    if (hi_bytes == 0) hi_bytes = 1; // 이론상 안 들어오긴 함

    size_t needed = hi * 8 + hi_bytes;
    if (!out) {
        // 버퍼만 계산하고 싶을 때
        return needed;
    }
    if (max_len < needed) {
        // 버퍼가 부족 -> 아무것도 안 씀, 0 리턴
        return 0;
    }

    size_t pos = needed;
    for (size_t i = 0; i < a->nlimbs; i++) {
        uint64_t limb = a->limb[i];
        for (unsigned b = 0; b < 8 && pos > 0; b++) {
            out[--pos] = (uint8_t)(limb & 0xFFu);
            limb >>= 8;
        }
    }
    // pos == 0 이 되어야 정상
    return needed;
}

// ===== 나눗셈 / 모듈러 =====

void bi_div_mod(BigInt* q, BigInt* r,
                const BigInt* a, const BigInt* m) {
    bi_zero(q);
    bi_zero(r);

    if (bi_is_zero(m)) {
        // 0으로 나누기: 여기서는 q=r=0 그대로 두고 리턴
        // 필요하면 assert 추가 가능
        return;
    }
    if (bi_is_zero(a)) {
        return; // 0 / m = 0 ... 0
    }

    size_t nbits = bi_bit_length(a);
    // 복원 나눗셈 알고리즘: bit 단위
    for (size_t i = nbits; i > 0; i--) {
        size_t bit = i - 1;

        // r <<= 1
        BigInt tmp;
        bi_shl_bits(&tmp, r, 1);
        *r = tmp;

        // r += a의 bit
        if (bi_get_bit(a, bit)) {
            if (r->nlimbs == 0) {
                r->limb[0] = 1;
                r->nlimbs = 1;
            } else {
                r->limb[0] |= 1u;
            }
        }

        // if r >= m: r -= m, q의 해당 bit = 1
        if (bi_cmp(r, m) >= 0) {
            BigInt tmp2;
            bi_sub(&tmp2, r, m);
            *r = tmp2;
            bi_set_bit(q, bit);
        }
    }

    bi_normalize(q);
    bi_normalize(r);
}

void bi_mod(BigInt* r, const BigInt* a, const BigInt* m) {
    BigInt q;
    bi_div_mod(&q, r, a, m);
}

// ===== 모듈러 곱 =====

void bi_modmul(BigInt* r, const BigInt* a, const BigInt* b, const BigInt* m) {
    BigInt tmp;
    bi_mul(&tmp, a, b);      // O(N^2) 곱셈
    bi_mod(r, &tmp, m);      // 나머지만 취함
}

// ===== 모듈러 거듭제곱: square-and-multiply =====

void bi_modexp(BigInt* r,
               const BigInt* base,
               const BigInt* exp,
               const BigInt* mod) {
    BigInt res;
    BigInt base_acc;

    if (bi_is_zero(mod)) {
        // mod 0은 의미 없음 -> 0으로 리턴
        bi_zero(r);
        return;
    }

    // res = 1
    bi_from_u64(&res, 1u);

    // base_acc = base mod mod
    bi_mod(&base_acc, base, mod);

    size_t e_bits = bi_bit_length(exp);
    for (size_t i = 0; i < e_bits; i++) {
        if (bi_get_bit(exp, i)) {
            BigInt tmp;
            bi_modmul(&tmp, &res, &base_acc, mod);
            res = tmp;
        }
        // base_acc = base_acc^2 mod mod
        BigInt tmp2;
        bi_modmul(&tmp2, &base_acc, &base_acc, mod);
        base_acc = tmp2;
    }

    *r = res;
    bi_normalize(r);
}
