// Reused Module from DES
#ifndef __CODEC_HEX_H__
#define __CODEC_HEX_H__

#include <stddef.h>
#include <stdint.h>
/* HEX 코덱 헤더
   - hex_encode: 바이너리 -> 대문자 HEX('0'..'9','A'..'F')
   - hex_decode_line: HEX 문자열 -> 바이너리
   - 디코드 규칙: 길이는 짝수, 문자 유효성 검사를 통과해야 함(아니면 -1) */
/* Encoding: Binary -> Hex
   out_hex 크기 -> 2 * in_len 바이트 이상 필요 */
void hex_encode(const uint8_t *in, size_t in_len, uint8_t *out_hex);

// Decoding : Hexadecimal to Binary
// One line of HEX to Binary
// Success : returns number of decoded bytes
// Failure : returns -1, if len is odd number OR invalid hex character found
long hex_decode_line(const uint8_t *in_hex, size_t in_hex_len, uint8_t *out_bytes);

#endif // codec_hex.h