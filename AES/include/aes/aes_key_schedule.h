#ifndef __AES_KEY_SCHEDULE_H__
#define __AES_KEY_SCHEDULE_H__
// test passed
#include "aes/aes.h"
#include <stdint.h>
#include <stddef.h>

// key -> round keys(rk) : + init Nr (could only be changed here)
AES_Status aes_key_schedule_init(AES_KeySchedule* ks, const uint8_t* key, size_t key_len);
void aes_key_schedule_clear(AES_KeySchedule* ks);

#endif  // aes_key_schedule.h