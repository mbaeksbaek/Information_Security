// RSA_백승민_2020253045
// RSA-ECB + ZeroPadding CryptoOps Adapter
// - BigInt 기반 textbook RSA 를 CryptoOps 인터페이스에 맞게 감싼 모듈
// - Runner 는 AES 와 동일하게 CryptoOps 만 교체해서 사용 가능

#include "rsa/rsa_ops.h"
#include "bigint/bigint.h"     // BigInt, bi_* APIs
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // stderr
// [주의]
// 여기서는 RSA Core 를 간단히 래핑하는 KS 구조체만 둔다.
// RSA Core 쪽에서 BigInt 기반 모듈러 지수 계산이 준비되어 있으므로
//  -> bi_modexp() 를 그대로 사용해서 m^exp mod n 수행.

// =======================
// Key Schedule 구조체
// =======================

typedef struct {
    BigInt n;              // modulus
    BigInt exp;            // exponent (e or d, enc/dec 에 따라 CLI 에서 선택)
    size_t k_bytes;        // modulus 블록 길이 (ciphertext one block len)
    size_t pt_block_bytes; // plaintext block len (= k_bytes - 1, textbook 제약)
} RSAKS;

// 내부 헬퍼: 구조체 전체 0 초기화
static void rsaks_zero(RSAKS *ks) {
    if (!ks) return;
    bi_zero(&ks->n);
    bi_zero(&ks->exp);
    ks->k_bytes = 0;
    ks->pt_block_bytes = 0;
}

// =======================
// ks_init / ks_clear
// =======================

/*
 * ks_init
 * - key_bytes: [ N | EXP ] big-endian
 * - key_len  : even, key_len/2 >= 2
 * - N, EXP 모두 0 이면 실패
 */
static int rsa_ks_init(void *ks_mem, const uint8_t *key_bytes, size_t key_len) {
    if (!ks_mem || !key_bytes || key_len == 0)
        return -1;

    // key_len 은 짝수여야 하고, 절반이 최소 2바이트 이상이라고 가정
    if ((key_len & 1u) != 0 || key_len < 4)
        return -1;

    RSAKS *ks = (RSAKS *)ks_mem;
    rsaks_zero(ks);

    size_t half = key_len / 2;
    const uint8_t *n_bytes   = key_bytes;
    const uint8_t *exp_bytes = key_bytes + half;

    // Big-endian -> BigInt
    bi_from_be_bytes(&ks->n, n_bytes,   half);
    bi_from_be_bytes(&ks->exp, exp_bytes, half);

    if (bi_is_zero(&ks->n) || bi_is_zero(&ks->exp)) {
        rsaks_zero(ks);
        return -1;
    }

    ks->k_bytes        = half;          // ciphertext block size
    if (ks->k_bytes <= 1) {
        rsaks_zero(ks);
        return -1;
    }
    ks->pt_block_bytes = ks->k_bytes - 1; // plaintext block size (m < n 보장용)

    return 0;
}

static void rsa_ks_clear(void *ks_mem) {
    if (!ks_mem) return;
    RSAKS *ks = (RSAKS *)ks_mem;

    // BigInt 내부 limb + 메타데이터 전부 0으로
    rsaks_zero(ks);
    // 혹시 컴파일러 최적화 방지를 더 하고 싶으면 volatile loop 도 추가 가능
}

// =======================
// RSA 한 블록 처리
// =======================

/*
 * RSA 블록 암/복호 공통
 * - in_bytes  : big-endian block, 길이는 in_len
 * - out_bytes : big-endian block, 길이는 out_len (호출자가 정확한 길이 확보)
 *
 * enc:
 *   m = BigInt(in_bytes)
 *   c = m^exp mod n
 *   c 를 out_len(k_bytes) 길이에 맞춰 big-endian 으로 채움 (왼쪽 0패딩)
 *
 * dec:
 *   c = BigInt(in_bytes)
 *   m = c^exp mod n   (exp 에 d 가 들어있으면 복호)
 *   m 를 out_len(pt_block_bytes) 길이로 big-endian 0패딩
 */
static int rsa_process_block(const RSAKS *ks,
                             const uint8_t *in_bytes, size_t in_len,
                             uint8_t *out_bytes, size_t out_len)
{
    if (!ks || !in_bytes || !out_bytes)
        return -1;

    BigInt in_bi, out_bi;
    bi_zero(&in_bi);
    bi_zero(&out_bi);

    // big-endian 바이트 -> BigInt
    bi_from_be_bytes(&in_bi, in_bytes, in_len);

    // m < n 조건 보장 (잘못된 입력이면 실패)
    if (bi_cmp(&in_bi, &ks->n) >= 0) return -1;

    // out_bi = in_bi^exp mod n
    bi_modexp(&out_bi, &in_bi, &ks->exp, &ks->n);

    // BigInt -> big-endian 바이트
    // 일단 필요한 길이 계산 (<= out_len 이어야 함)
    size_t needed = bi_to_be_bytes(&out_bi, NULL, 0);
    if (needed > out_len) {
        // modulus / block size 설정 이상
        // debugging test 
        fprintf(stderr,
        "[DBG][rsa-process-block] needed %zu, out len %zu (k bytes=%zu, pt_blk=%zu)\n",
        needed, out_len, ks->k_bytes, ks->pt_block_bytes);
        return -1;
    }

    // out_bytes 전체 0으로 채워놓고, 뒤쪽에 붙인다 (왼쪽 0패딩)
    memset(out_bytes, 0, out_len);
    if (needed > 0) {
        size_t start = out_len - needed;
        size_t written = bi_to_be_bytes(&out_bi, out_bytes + start, needed);
        if (written != needed)
            return -1;
    }
    return 0;
}

// =======================
// encrypt_ecb_zeropad
// =======================

/*
 * RSA-ECB + ZeroPadding (encrypt)
 *
 * - plaintext 는 pt_block_bytes 단위로 자른다.
 *   마지막 블록이 모자라면 0x00 으로 채운다.
 * - 각 블록은 m < 256^(pt_block_bytes) 이므로 적절한 n 에 대해 m < n 을 기대.
 * - 각 블록은 RSA 한 번 (m^exp mod n) 수행 후 k_bytes 길이의 ciphertext 로 출력.
 *
 * out_len = num_blocks * k_bytes
 * n == 0이면 out_len = 0, malloc(1) 로 NULL 아님 포인터만 보장
 */
static int rsa_encrypt_ecb_zeropad(const void *ks_mem,
                                   const uint8_t *in, size_t n,
                                   uint8_t **out, size_t *on)
{
    if (!ks_mem || !out || !on)
        return -1;

    const RSAKS *ks = (const RSAKS *)ks_mem;

    // 빈 입력 처리
    if (!in && n != 0)
        return -1;

    size_t pt_blk = ks->pt_block_bytes;
    size_t ct_blk = ks->k_bytes;

    if (pt_blk == 0 || ct_blk == 0)
        return -1;

    if (n == 0) {
        *out = (uint8_t *)malloc(1);
        if (!*out) return -1;
        *on = 0;
        return 0;
    }

    size_t num_blocks = (n + pt_blk - 1) / pt_blk;
    size_t total_out  = num_blocks * ct_blk;

    uint8_t *buf = (uint8_t *)malloc(total_out ? total_out : 1);
    if (!buf) return -1;

    // 임시 블록 버퍼 (heap, VLA 안 씀)
    uint8_t *pt_block = (uint8_t *)malloc(pt_blk);
    uint8_t *ct_block = (uint8_t *)malloc(ct_blk);
    if (!pt_block || !ct_block) {
        free(buf);
        if (pt_block) free(pt_block);
        if (ct_block) free(ct_block);
        return -1;
    }

    size_t offset_in  = 0;
    size_t offset_out = 0;

    for (size_t b = 0; b < num_blocks; ++b) {
        size_t remain  = (n > offset_in) ? (n - offset_in) : 0;
        size_t take    = (remain > pt_blk) ? pt_blk : remain;

        // pt_block 채우기 + zero padding
        memset(pt_block, 0, pt_blk);
        if (take > 0)
            memcpy(pt_block, in + offset_in, take);

        // RSA 한 블록 처리
        if (rsa_process_block(ks,
                              pt_block, pt_blk,
                              ct_block, ct_blk) != 0)
        {
            free(buf);
            free(pt_block);
            free(ct_block);
            return -1;
        }

        // 출력 버퍼로 복사
        memcpy(buf + offset_out, ct_block, ct_blk);

        offset_in  += take;
        offset_out += ct_blk;
    }

    free(pt_block);
    free(ct_block);

    *out = buf;
    *on  = total_out;
    return 0;
}

// =======================
// decrypt_ecb_strip (ZeroPadding 제거)
// =======================

/*
 * RSA-ECB + ZeroPadding (decrypt)
 *
 * - ciphertext 길이 n 은 반드시 k_bytes 의 배수여야 함.
 * - 각 k_bytes 블록을 RSA 한 번 돌려서 pt_block_bytes bytes 로 복원
 *   (RSA 결과를 pt_block_bytes 길이에 맞게 big-endian 0패딩)
 * - 전체 plaintext 끝에서부터 0x00 을 strip : AES zero-padding 과 동일 정책
 *
 * out_len <= num_blocks * pt_block_bytes
 */
static int rsa_decrypt_ecb_strip(const void *ks_mem,
                                 const uint8_t *in, size_t n,
                                 uint8_t **out, size_t *on)
{
    if (!ks_mem || !out || !on)
        return -1;

    const RSAKS *ks = (const RSAKS *)ks_mem;

    if (!in && n != 0)
        return -1;

    size_t pt_blk = ks->pt_block_bytes;
    size_t ct_blk = ks->k_bytes;

    if (pt_blk == 0 || ct_blk == 0)
        return -1;

    if (n == 0) {
        *out = (uint8_t *)malloc(1);
        if (!*out) return -1;
        *on = 0;
        return 0;
    }

    // ciphertext 길이는 반드시 블록 크기의 배수
    if (n % ct_blk != 0)
        return -1;

    size_t num_blocks = n / ct_blk;
    size_t alloc_len  = num_blocks * pt_blk;

    uint8_t *buf = (uint8_t *)malloc(alloc_len ? alloc_len : 1);
    if (!buf) return -1;

    uint8_t *pt_block = (uint8_t *)malloc(pt_blk);
    uint8_t *ct_block = (uint8_t *)malloc(ct_blk);
    if (!pt_block || !ct_block) {
        free(buf);
        if (pt_block) free(pt_block);
        if (ct_block) free(ct_block);
        return -1;
    }

    size_t offset_in  = 0;
    size_t offset_out = 0;

    for (size_t b = 0; b < num_blocks; ++b) {
        memcpy(ct_block, in + offset_in, ct_blk);
        // RSA 한 블록 처리
        if (rsa_process_block(ks,
                              ct_block, ct_blk,
                              pt_block, pt_blk) != 0)
        {
            free(buf);
            free(pt_block);
            free(ct_block);
            return -1;
        }

        memcpy(buf + offset_out, pt_block, pt_blk);

        offset_in  += ct_blk;
        offset_out += pt_blk;
    }

    free(pt_block);
    free(ct_block);

    // trailing zero strip (ZeroPadding 제거)
    size_t out_len = alloc_len;
    while (out_len > 0 && buf[out_len - 1] == 0x00) {
        out_len--;
    }

    *out = buf;
    *on  = out_len;
    return 0;
}

// =======================
// CryptoOps 인스턴스
// =======================

const CryptoOps RSA_OPS = {
    .ks_init            = rsa_ks_init,
    .ks_clear           = rsa_ks_clear,
    .encrypt_ecb_zeropad= rsa_encrypt_ecb_zeropad,
    .decrypt_ecb_strip  = rsa_decrypt_ecb_strip,
    .ks_size            = sizeof(RSAKS)
};
