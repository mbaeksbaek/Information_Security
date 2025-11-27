// AES_백승민_2020253045
#include "crypto_ops.h"
#include <stdlib.h>
#include <string.h>
/*
그냥 스모크 테스트용 빈 깡통, 인스턴스에 연결해서 러너 스모크 테스트 진행용도
동작은 아무것도 하지않고, 들어오는 그대로 반환

실제 AES 연산이 준비되기 전 runner pipeline 검증용도
키 스케줄은 DummyKS 구조체로 크기만 맞추고, 암복호는 입력을 출력으로
파일 io/라인처리/에러전파 가 잘동작하는지 검증할 용도로 만듬
*/
typedef struct { int placeholder; } DummyKS;

static int dummy_ks_init(void* ks_mem, const uint8_t* key, size_t key_len) {
    (void)key; (void)key_len;
    if (!ks_mem) return -1;
    ((DummyKS*)ks_mem)->placeholder = 0;
    return 0;
}

static void dummy_ks_clear(void* ks_mem) {
    if (!ks_mem) return;
    memset(ks_mem, 0, sizeof(DummyKS));
}

static int dummy_copy(const void* ks_mem, const uint8_t* in, size_t n, uint8_t** out, size_t* on) {
    (void)ks_mem;
    *out = (uint8_t*)malloc(n ? n : 1);
    if (!*out) return -1;
    if (n) memcpy(*out, in, n);
    *on = n;
    return 0;
}

const CryptoOps DUMMY_OPS = {
    .ks_init = dummy_ks_init,
    .ks_clear = dummy_ks_clear,
    .encrypt_ecb_zeropad = dummy_copy,
    .decrypt_ecb_strip   = dummy_copy,
    .ks_size = sizeof(DummyKS)
};
