#ifndef __AES_BLOCK_H__
#define __AES_BLOCK_H__
// test passed
#include "aes/aes.h"
#include <stdint.h>
#include <stddef.h>
// [11.15] - Block Op Test Passed with Negative Cases.
AES_Status aes_encrypt_block(const AES_KeySchedule* ks, const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES]);
AES_Status aes_decrypt_block(const AES_KeySchedule* ks, const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES]);

/* ===== UNIT TEST HELPERS (테스트 빌드 전용) ========================= */
// [TODO] : Wrap this Test Functions to Macro
/* in/out 은 row-major 16바이트:
 *   [r0c0 r0c1 r0c2 r0c3  r1c0 ... r3c3]
 */

AES_Status aes_block_test_subbytes(const uint8_t in[AES_BLOCK_BYTES],
                                   uint8_t out[AES_BLOCK_BYTES]);

AES_Status aes_block_test_shiftrows(const uint8_t in[AES_BLOCK_BYTES],
                                    uint8_t out[AES_BLOCK_BYTES]);

AES_Status aes_block_test_mixcolumns(const uint8_t in[AES_BLOCK_BYTES],
                                     uint8_t out[AES_BLOCK_BYTES]);

/* AddRoundKey 테스트용
 *  - round_words[4] : 한 라운드용 4 word (column 0~3)
 */
AES_Status aes_block_test_addroundkey(const uint8_t in[AES_BLOCK_BYTES],
                                      uint8_t out[AES_BLOCK_BYTES],
                                      const uint32_t round_words[4]);

// inverse test helper
/* inverse 연산용 테스트 헬퍼 (decrypt 검증용) */
AES_Status aes_block_test_inv_subbytes(const uint8_t in[AES_BLOCK_BYTES],
                                       uint8_t out[AES_BLOCK_BYTES]);

AES_Status aes_block_test_inv_shiftrows(const uint8_t in[AES_BLOCK_BYTES],
                                        uint8_t out[AES_BLOCK_BYTES]);

AES_Status aes_block_test_inv_mixcolumns(const uint8_t in[AES_BLOCK_BYTES],
                                         uint8_t out[AES_BLOCK_BYTES]);


#endif  // aes_block.h