// AES_백승민_2020253045
// [11.12] - New Module, Not Tested : Tested With Runner Smoke Test > PASS
#include "crypto_ops.h"
#include <stdlib.h>
#include <string.h>
/*
Crypto Ops Dummy
runner.c 에서 사용할 수 있는 형식만 맞는 더미임.
실제 암호 연산은 하지 않고 입력을 그대로 출력함
(파이프라인/파일 io/에러 전파 흐름 검증용)
*/

// [11.12] - Dummy Key Schedule
typedef struct {
    int ph;
} DummyKS;

/* Key Schedule Dummies */
static int dummy_ks_init(void* ks_mem, const uint8_t* key, size_t key_len) {
    (void)key; (void)key_len;
    if(!ks_mem) return -1;
    ((DummyKS*)ks_mem)->ph = 0;
    return 0;
}

static void dummy_ks_clear(void* ks_mem) {
    if(!ks_mem) return;
    memset(ks_mem, 0, sizeof(DummyKS));
}

/* === 암/복호 더미 구현: 입력 그대로 복사 === */
static int dummy_enc(const void* ks_mem, const uint8_t* in, size_t n, uint8_t** out, size_t* on) {
    (void)ks_mem;
    if (!out || !on) return -1;
    *out = (uint8_t*)malloc(n ? n : 1); /* n=0이면 0바이트 malloc은 구현차 존재 => 1바이트 */
    if (!*out) return -1;
    if (n) memcpy(*out, in, n);
    *on = n;
    return 0;
}

static int dummy_dec(const void* ks_mem, const uint8_t* in, size_t n, uint8_t** out, size_t* on) {
    return dummy_enc(ks_mem, in, n, out, on);
}

// open instance : injection to runner
const CryptoOps DUMMY_OPS = {
    .ks_init = dummy_ks_init,
    .ks_clear = dummy_ks_clear,
    .encrypt_ecb_zeropad = dummy_enc,
    .decrypt_ecb_strip = dummy_dec,
    .ks_size = sizeof(DummyKS)
};