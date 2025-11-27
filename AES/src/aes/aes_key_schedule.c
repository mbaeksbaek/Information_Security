// AES_백승민_2020253045
#include "aes/aes_key_schedule.h"
#include "aes/aes.h"
#include "aes/aes_tables.h"
#include <stdint.h>
#include <stddef.h>

#define AES_NB 4
// Key Size : 128, 192, 256 .. depends on aes keyschedule (Nr)
/*
[11.14]
Round Key Number : Nr + 1
Where Nr = 10: Key-size = 128, AES-128, 44 word
Nr = 12: Key-size = 192, AES-192, 52 word
Nr = 14: Key-Size = 256, AES-256, 60 word
1word : 32, 1block: 4 word = 128, state = 128
Basic Key Expansion : w_{i-1} - RotWord - SubWord - XOR Rcon[i/4] = t_i
RotWord : left shift 1
SubWord : S-box each byte
RCon defined on aes_tables
- Pseudo on pdf

[11.14] Unit Test Processed - Passed
- 1. (neg) Null Arg / Wrong Length
- 2. (pos) Keysize Nr mapping / total_words
- 3. aes_key_schedule_clear check
key schedule + exception + zeroization test passed

[11.14] KAT comp - pdf values + KAT (App 1) Passed - PDF Value is Wrong at w[15] : Reminder : revised wrong value w[15]
128 bit Master Key of (24 75 A2 B3 34 75 56 88 31 E2 12 00 13 AA 54 87)ff 

More Test Values of Diff key (Lecture)
12 45 a2 a1 23 31 a4 a3 b2 cc aa 34 c2 bb 77 23
12 45 a2 a1 23 31 a4 a3 b2 cc ab 34 c2 bb 77 23

- Unit Test Passed
: neg, Null Arg, wrong Length
: KeySize Mapping / total_words
: KAT + Lec values(revised)
: Key Destroy check
*/

// helpers
/* 32 byte word : 1byte rotate, abcd -> bcda : 8 */
static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/* each Word's comp S-box each byte */
static uint32_t sub_word(uint32_t w) {
    uint32_t res = 0;
    // 32 - 24
    res |= ((uint32_t)AES_SBOX[w >> 24 & 0xFF]) << 24;
    // 24 - 16
    res |= ((uint32_t)AES_SBOX[w >> 16 & 0xFF]) << 16;
    // 16 - 8
    res |= ((uint32_t)AES_SBOX[w >> 8 & 0xFF]) << 8;
    // 8 - 0
    res |= ((uint32_t)AES_SBOX[w >> 0 & 0xFF]) << 0;
    return res;
}

/*
ks : round key structure, key: master key, key_len: key length
*/
AES_Status aes_key_schedule_init(AES_KeySchedule* ks, const uint8_t* key, size_t key_len) {
    if (!ks || !key) return AES_ERR_INVALID_ARG; // null ptr for key/sch structure
    int Nk; /* key length in 32-bit word */
    switch (key_len) {
        case AES128_KEY_BYTES: {
            Nk=4; ks->Nr=10; break; // AES128
        }
        case AES192_KEY_BYTES: {
            Nk=6; ks->Nr=12; break; // AES192
        }
        case AES256_KEY_BYTES: {
            Nk=8; ks->Nr=14; break; // AES256
        }
        default:
            return AES_ERR_INVALID_ARG; // invalid key len : 15, 20, 31 ...
    }
    const int Nr = ks->Nr;
    const int total_words = AES_NB * (Nr + 1);  // w[0~Nb*(Nr+1)-1] idx
    uint32_t* w = ks->rk;

    /* 1) Nk word : key copy */
    // 초기 Nk word : Master Key
    // - key[4*i..4*i+3] 32-bit 로 묶어서 w[i] 저장
    for (int i=0; i<Nk; ++i) {
        uint32_t tmp = (
            (uint32_t)key[4*i] << 24 |
            (uint32_t)key[4*i+1] << 16 |
            (uint32_t)key[4*i+2] << 8 |
            (uint32_t)key[4*i+3]
        );
        w[i]=tmp;
    }

    /* 2) rest words */
    // i : word idx
    // w[i] = w[i-Nk] ^ tmp
    // i % Nk == 0 : rotword - subword - rcon(i/Nk)
    // aes-256 & i%Nk == 4: subword
    // else : tmp = w[i-1] 
    for (int i=Nk; i<total_words; ++i) {
        uint32_t tmp = w[i-1];
        if (i % Nk == 0) {
            // RotWord + SubWord + Rcon
            tmp = rot_word(tmp);
            tmp = sub_word(tmp);
            // aes - rcon idx
            // i/Nk : 1 ~
            // 상위 1바이트에는 rcon 더하고 나머지는 0
            tmp ^= ((uint32_t)AES_RCON[i/Nk]) << 24;
        }
        else if (Nk > 6 && (i%Nk) == 4) {
            // AES-256
            tmp = sub_word(tmp);
        }
        w[i] = w[i-Nk] ^ tmp;
    }

    // 3) remaining space -> 0
    // ks-> rk : 60 word
    // unused space : 0 init
    for (int i = total_words; i < 60; ++i)  w[i]=0;

    return AES_OK;
}

/* key destroy */
// ks->rk roundkeys => 0
// ks->Nr => 0
// ks == Null: return
void aes_key_schedule_clear(AES_KeySchedule* ks) {
    if (!ks) return; // null exception
    volatile uint8_t* p= (volatile uint8_t*)ks->rk; // memset exception
    for (size_t i = 0; i < sizeof(ks->rk); ++i) p[i] = 0;
    ks->Nr=0;
    return;
}