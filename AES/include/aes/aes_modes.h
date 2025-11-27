#ifndef __AES_MODES_H__
#define __AES_MODES_H__
// test passed
#include "aes/aes.h"
#include <stdint.h>
#include <stddef.h>
// ECB + Zeropadding / StripZero (Runner Modes)
// in : 16B zero padding -> enc., out, out_len -> must be free later
/*
aes ecb + zero padding
in/in_len : pt buffer, 0 length available
out/out_len : ct buffer, caller must free

padding policy :
-in_le == 0 : all 0 block padding
-in_len % 16 == 0, != 0 : Same
- else: last block 0 padding
*/
AES_Status aes_encrypt_zeropad(const AES_KeySchedule* ks, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
// in : 16 * N, decrypt : 0 erased later
/*
aes ecb + Zero padding decrypt
in/in_len: ct buffer, length must be 16 N & >0
out/out_len: padding 0 erased pt
Note: If Last Pt is 0, could be erased

+) if All Decrypted PT is 0, out_len = 0, out=NULL return
*/
AES_Status aes_ecb_decrypt_stripzero(const AES_KeySchedule* ks, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);


#endif  // aes_modes.h