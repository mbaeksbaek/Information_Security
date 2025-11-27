#ifndef __AES_OPS_H__
#define __AES_OPS_H__
#include "aes/aes.h"
#include "crypto_ops.h"

/*
[11.15] aes_ops
*/

/* Runner에 끼울 어댑터 객체 */
extern const CryptoOps AES_OPS;

#endif  // aes_ops.h
