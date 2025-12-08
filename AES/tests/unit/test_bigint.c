// tests/unit/test_bigint.c
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "bigint/bigint.h"
/*
- gcc -Wall -Wextra -O2 \
-   -Isrc/bigint -Iinclude \
-   src/bigint/bigint.c \
-   tests/unit/test_bigint.c \
-   -o build/unit/test_bigint
*/

/* - BE 변환 round-trip */
static void test_be_convert(void) {
    BigInt a;
    uint8_t buf[32];

    // 0x0123456789ABCDEF
    uint8_t src[] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF
    };
    bi_from_be_bytes(&a, src, sizeof(src));

    size_t n = bi_to_be_bytes(&a, buf, sizeof(buf));
    assert(n == sizeof(src));
    for (size_t i = 0; i < n; i++) {
        assert(buf[i] == src[i]);
    }
}

/* - 작은 값 나눗셈/나머지 검증 */
static void test_div_mod_small(void) {
    BigInt a, m, q, r;

    bi_from_u64(&a, 123456789ull);
    bi_from_u64(&m, 1000ull);
    bi_div_mod(&q, &r, &a, &m);

    // 123456789 / 1000 = 123456, 나머지 789
    assert(q.nlimbs == 1 && q.limb[0] == 123456ull);
    assert(r.nlimbs == 1 && r.limb[0] == 789ull);
}

/* - 작은 값 modexp 검증 */
static void test_modexp_small(void) {
    BigInt base, exp, mod, res;

    bi_from_u64(&base, 7);
    bi_from_u64(&exp, 128);
    bi_from_u64(&mod, 1000);

    // 7^128 mod 1000 = (미리 계산해둔 값)
    // 간단히 파이썬 등으로 계산하면: 7**128 % 1000 =  801
    bi_modexp(&res, &base, &exp, &mod);
    assert(res.nlimbs == 1 && res.limb[0] == 801ull);
}

/* - 엔트리포인트: 기본 BigInt 테스트 */
int main(void) {
    test_be_convert();
    test_div_mod_small();
    test_modexp_small();

    printf("BigInt basic tests: OK\n");
    return 0;
}
