#ifndef RSA_OPS_H
#define RSA_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_ops.h"

/*
- RSA_OPS: CryptoOps vtable (RSA-ECB + ZeroPadding)
- Key format (key_hex -> bytes): [ N | EXP ]
- key_len: 짝수 바이트, 앞 절반 modulus n, 뒤 절반 exponent(e 또는 d)
- enc: (N || e), dec: (N || d)
*/
extern const CryptoOps RSA_OPS;

#endif /* RSA_OPS_H */
