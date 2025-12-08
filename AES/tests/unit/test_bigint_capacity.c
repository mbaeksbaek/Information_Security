// tests/unit/test_bigint_capacity.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "bigint/bigint.h"

/*
- gcc -Wall -Wextra -O2 \
-   -Iinclude \
-   src/bigint/bigint.c \
-   tests/unit/test_bigint_capacity.c \
-   -o build/unit/test_bigint_capacity
*/
// 원하는 테스트 키 길이 (필요에 따라 128, 256 등으로 조정)
#define KEY_BYTES 256

/* - 고정 패턴 채우기 (선두 0 보정) */
static void fill_pattern(uint8_t *buf, size_t len) {
    // 간단한 패턴으로 채움 (고정값, 랜덤 X)
    uint8_t v = 0x13;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(v + (uint8_t)(i * 37u));
    }
    // 맨 앞이 0x00으로 시작하면 실제 길이가 줄어드니까,
    // 적당히 상위 바이트 하나는 0이 아니게 보정
    if (len > 0 && buf[0] == 0x00) {
        buf[0] = 0x7F;
    }
}

/* - 큰 BigInt 변환 round-trip 검증 */
static void test_bigint_roundtrip_large(void) {
    uint8_t src[KEY_BYTES];
    uint8_t out[KEY_BYTES];

    fill_pattern(src, sizeof(src));

    BigInt a;
    bi_from_be_bytes(&a, src, sizeof(src));

    // a 를 다시 big-endian 바이트로 뽑았을 때 길이가 KEY_BYTES 이하인지,
    // 그리고 상위 바이트 0을 고려해서 다시 넣으면 동일해지는지 확인
    size_t need = bi_to_be_bytes(&a, NULL, 0);
    assert(need > 0);
    assert(need <= KEY_BYTES);

    memset(out, 0, sizeof(out));
    size_t written = bi_to_be_bytes(&a, out, sizeof(out));
    assert(written == need);

    BigInt b;
    bi_from_be_bytes(&b, out, written);

    // a == b 여야 함
    assert(bi_cmp(&a, &b) == 0);
}

/* - 큰 modulus에 대한 modexp 범위 검증 */
static void test_bigint_modexp_large(void) {
    // mod: KEY_BYTES 바이트짜리 큰 수
    uint8_t mod_bytes[KEY_BYTES];
    fill_pattern(mod_bytes, sizeof(mod_bytes));

    BigInt mod;
    bi_from_be_bytes(&mod, mod_bytes, sizeof(mod_bytes));
    assert(!bi_is_zero(&mod));

    // base: 작은 값 (u64)로 충분, 항상 base < mod 성립하도록
    BigInt base;
    bi_from_u64(&base, 123456789u);

    // exp: 적당한 값 (17 같은 작은 지수여도 충분)
    BigInt exp;
    bi_from_u64(&exp, 65537u);

    BigInt res;
    bi_modexp(&res, &base, &exp, &mod);

    // 결과는 0 <= res < mod 여야 함
    assert(!bi_is_zero(&res));          // base != 0, mod != 0 이니 실제로는 0 아닐 확률 큼
    assert(bi_cmp(&res, &mod) < 0);     // mod 연산이 제대로 된 경우

    // 결과 길이도 KEY_BYTES 이하인지 확인
    size_t need = bi_to_be_bytes(&res, NULL, 0);
    assert(need <= KEY_BYTES);
}

/* - 엔트리포인트: 용량 테스트 실행 */
int main(void) {
    test_bigint_roundtrip_large();
    test_bigint_modexp_large();
    printf("BigInt capacity tests (KEY_BYTES=%d) : OK\n", KEY_BYTES);
    return 0;
}
