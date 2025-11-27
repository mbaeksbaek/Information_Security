// AES_백승민_2020253045
#include "aes/aes_modes.h"
#include "aes/aes_block.h"
#include <stdlib.h>
#include <string.h>

// [11.15] - ZeroPadding / Strip : [Test] - Segmentation Fault : Mem
// - AES ECB 모드에서 가변 길이 버퍼를 처리하기 위한 헬퍼 계층
// "여러블록+패딩정책" 담당, 연산은 aes_block이 함
// 상위 레이어(runner/app)은 여기만 호출하고 블록단위 암복호는 절대 만지지 않음

// KeySchedule의 Nr가 유효한지 체크
// KeySchedule 이 Nr를 결정, 모드는 정상범위인지만 체크만 해야함
// ks = null : INVALID_ARG
static int aes_modes_check_nr(const AES_KeySchedule* ks)
{
    if (!ks) return 0;
    return (ks->Nr == 10 || ks->Nr == 12 || ks->Nr == 14);
}

/*
AES ECB + Zero Padding(Enc.)

in/in_len: 평문 버퍼(길이 0 허용)
out/out_len: 암호문 버퍼(malloc 할당, 주의* 호출자가 free)

패딩 Policy
- in_len == 0: 0x00 16 byte block 1개 생성
- in_len % 16 == 0, >0: N블록
- else: 마지막 블록 남은 바이트에 0 패딩

- ks=NULL : AES_ERR_INVALID_ARG
- out=NULL || out_len=NULL : AES_ERR_INVALID
- in_len>0, in=NULL : AES_ERR_INVALID_ARG
- ks->Nr != 10|12|14 : AES_ERR_INVALID_ARG (Wrong Key Init.)

호출자가 *out에 malloc 버퍼 반드시 free(*out) 해줘야함..
*/
AES_Status aes_encrypt_zeropad(const AES_KeySchedule* ks, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len)
{
    if (!ks || !out || !out_len) return AES_ERR_INVALID_ARG;    // Null ptr
    if (in_len > 0 && !in)       return AES_ERR_INVALID_ARG;    // null buff
    if (!aes_modes_check_nr(ks)) return AES_ERR_INVALID_ARG;    // wrong nr

    const size_t block = AES_BLOCK_BYTES;
    size_t padded_len;
    // 입력 길이에 따라 암호화할 전체 길이 결정
    if (in_len == 0) {
        // 0B 파일은 0x00 16바이트 블록 하나로 패딩
        padded_len = block;
    } else if ((in_len % block) == 0) {
        // 16배수 그대로 사용
        padded_len = in_len;
    } else {
        // 마지막 블록 0패딩
        padded_len = (in_len / block + 1) * block;
    }

    uint8_t* out_buff = (uint8_t*)malloc(padded_len);
    if (!out_buff) return AES_ERR_OOM;  // OOM Exception

    size_t num_blocks = padded_len / block;

    // 각 블록 순회, 평문 복사 + 패딩 후 블록 암호화
    for (size_t b = 0; b < num_blocks; ++b) {
        uint8_t plain[AES_BLOCK_BYTES];
        size_t offset = b * block;

        // 이 블록에서 실제로 복사할 평문 길이 계산
        size_t copy_len = 0;
        if (offset < in_len) {
            copy_len = in_len - offset;
            if (copy_len > block) copy_len = block;  // 최대 16바이트만
            memcpy(plain, in + offset, copy_len);
        }

        // 나머지는 0x00으로 패딩
        if (copy_len < block) {
            memset(plain + copy_len, 0x00, block - copy_len);
        }

        AES_Status st = aes_encrypt_block(ks, plain, out_buff + offset);
        if (st != AES_OK) {
            // 블록 암호화 실패시 곧바로 해제 후 해당 error status 반환
            free(out_buff);
            return st;
        }
    }

    *out     = out_buff;
    *out_len = padded_len;
    return AES_OK;
}

/*
AES ECB + Zero Strip (Dec.)

in/in_len: 암호문 버퍼, 길이:16배수 & >0
out/out_len: 뒤쪽 0 패딩 제거 후 평문

동작 요약:
1) in_len / 16 만큼 블록 단위 aes_decrypt_block 수행 -> buff
2) buff 의 뒤쪽에서부터 연속 0 제거
 - 전부 0이면 (0b 파일의 패딩만 남은 경우) out=NULL, out_len=0
 - 중간 0은 유지 (원래 데이터와 구별은 안됨)
 
 Exception:
  - ks|in|out|out_len = NULL : AES_ERR_INVALID_ARG
  - in_len=0, 16배수가 아닌 경우: AES_ERR_INVALID_ARG
  - ks->Nr!=10|12|14 : AES_ERR_INVALID_ARG
  - malloc(buff) Error : AES_ERR_OOM
  - 첫번째 블록 복호 중 decrypt_block fail: buff 해제 후 해당 에러 코드 반환
  - 두번째 malloc(out_buff) fail : AES_ERR_OOM

  [NOTE]
  - 0 패딩은 마지막에 연속된 0이 모두 패딩이라고 가정함.
  따라서, 원래 데이터가 실제로 0으로 끝나는 경우, 복원시 길이가 줄어들 수 있음. 
*/
AES_Status aes_ecb_decrypt_stripzero(const AES_KeySchedule* ks, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len)
{
    if (!ks || !in || !out || !out_len) return AES_ERR_INVALID_ARG; // Null ptr
    if (in_len == 0 || (in_len % AES_BLOCK_BYTES) != 0)
        return AES_ERR_INVALID_ARG; // block size 위반
    if (!aes_modes_check_nr(ks)) return AES_ERR_INVALID_ARG; // wrong nr value

    uint8_t* buff = (uint8_t*)malloc(in_len);
    if (!buff) return AES_ERR_OOM;  // oom

    size_t num_blocks = in_len / AES_BLOCK_BYTES;
    for (size_t b = 0; b < num_blocks; ++b) {
        AES_Status st = aes_decrypt_block(ks, in  + b * AES_BLOCK_BYTES, buff + b * AES_BLOCK_BYTES);
        if (st != AES_OK) {
            // 복호 중 오류 발생, 중간 결과 버리고 에러 반환
            free(buff);
            return st;
        }
    }

    // 뒤에서부터 0x00 패딩 제거
    size_t erased = in_len;
    while (erased > 0 && buff[erased - 1] == 0x00) {
        --erased;
    }

    if (erased == 0) {
        // 모두 패딩인 경우 > 0B 파일
        free(buff);
        *out     = NULL;
        *out_len = 0;
        return AES_OK;
    }

    // 실제 데이터 길이 만큼 새버퍼 할당후 복사
    uint8_t* out_buff = (uint8_t*)malloc(erased);
    if (!out_buff) {
        free(buff);
        return AES_ERR_OOM; // 결과 버퍼 할당 실패
    }
    memcpy(out_buff, buff, erased);
    free(buff);

    *out     = out_buff;
    *out_len = erased;
    return AES_OK;
}
