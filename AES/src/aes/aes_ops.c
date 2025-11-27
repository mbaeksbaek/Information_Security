// AES_백승민_2020253045
#include "aes/aes_ops.h"
#include "aes/aes_key_schedule.h"
#include "aes/aes_modes.h"

/*
AES Operations Adapter
- AES 내부 구현과 runner에서 사용하는 CryptoOps Interface 추상화
- runner.c / app.c 에서는 CryptoOps 구조체만 알고, 그 안에 있는 함수 포인터(ks_init, enc_ecb_zeropad, ..) 를 호출
- 실제 구현은 AES_KeySchedule, aes_encrypt_zeropad, aes_ecb_decrypt_strip 에서 담당

CryptoOps 는 void* 로 key schedule 메모리를 다루기 때문에, AES_KeySchedule* 로 캐스팅후 사용
- 에러 코드는 모두 AES_Status(AES_OK/AES_ERR*) 값을 int 로 반환
*/

/*
CryptoOps.ks_init에 연결되는 구현
ks_mem: key schedule buffer
key: master key(128 192 256)
key_len: key length

void* ks_mem -> AES_KeySchedule* 캐스팅, aes_key_schedule_init 에서 라운드 키 생성

- ks_mem|key=NULL : AES_ERR_INVALID_ARG
*/
static int aes_ops_ks_init(void* ks_mem, const uint8_t* key, size_t key_len)
{
    if (!ks_mem || !key) {
        return AES_ERR_INVALID_ARG; // null ptr
    }
    AES_KeySchedule* ks = (AES_KeySchedule*)ks_mem;
    return aes_key_schedule_init(ks, key, key_len);
}

/*
마찬가지로 CryptoOps.ks_clear 에 연결되는 구현부
Ks_mem: key schedule buffer

ks_mem -> AES_KeySchedule* 캐스팅 후 aes_key_schedule_clear 호출
내부적으로 라운드 키를 0으로 덮어써서 잔존 키 데이터 제거

- ks_mem=NULL : return
*/

static void aes_ops_ks_clear(void* ks_mem)
{
    if (!ks_mem) return; // null ptr
    AES_KeySchedule* ks = (AES_KeySchedule*)ks_mem;
    aes_key_schedule_clear(ks);
}

/*
CryptoOps.encrypt_ecb_zeropad

ks_mem: AES_KeySchedule 이 들어있는 메모리
in: PT Buffer(NULL 허용: in_len==0 일시, 처리는 aes_encrypt_zeropad 에서)
in_len: 평문길이
out: 암호문 버퍼
out_len: 암호문 길이를 돌려줄 위치

ks_mem -> const AES_KeySchedule* 캐스팅 -> aes_encrypt_zeeropad() 에 넘김

- ks_mem=NULL: AES_ERR_INVALID_ARG
- 나머지 인자 검증/패딩 규칙/메모리 할당 실패 등은 aes_encrypt_zeropad 에서 처리
*/
static int aes_ops_encrypt_ecb_zeropad(const void* ks_mem, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len)
{
    if (!ks_mem) {
        return AES_ERR_INVALID_ARG; // key schedule 없음
    }
    const AES_KeySchedule* ks = (const AES_KeySchedule*)ks_mem;
    return aes_encrypt_zeropad(ks, in, in_len, out, out_len);
}

/*
ks_mem: AES_KeySchedule메모리
in/in_len: 암호문
out/out_len: 평문 버퍼/길이

ks_mem -> AES_KeySchedule* 캐스팅 -> aes_ecb_decrypt_stripzero

- ks_mem=NULL : AES_ERR_INVALID_ARG
- in/in_len/out/out_len 검증, 블록크기/패딩제거, 메모리 할당 실패는 aes_ecb_decrypt_stripzero에서 처리
*/
static int aes_ops_decrypt_ecb_strip(const void* ks_mem, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len)
{
    if (!ks_mem) {
        return AES_ERR_INVALID_ARG; // no key schedule
    }
    const AES_KeySchedule* ks = (const AES_KeySchedule*)ks_mem;
    return aes_ecb_decrypt_stripzero(ks, in, in_len, out, out_len);
}

/* Runner에서 include "aes/aes_ops.h" 후 AES_OPS 사용 */
/*
runner.c 에서 사용하는 CryptoOps 구현 인스턴스

ks_init -> aes_ops_ks_init
ks_clear -> aes_ops_ks_clear
encrypt_ecb_zeropad -> aes_ops_encrypt_ecb_zeropad
decrypt_ecb_strip -> aes_ops_decrypt_ecb_strip
ks_size -> sizeof(AES_KeySchedule) : runner 가 내부 버퍼 크기 계산으로 사용
*/
const CryptoOps AES_OPS = {
    aes_ops_ks_init,
    aes_ops_ks_clear,
    aes_ops_encrypt_ecb_zeropad,
    aes_ops_decrypt_ecb_strip,
    sizeof(AES_KeySchedule)
};