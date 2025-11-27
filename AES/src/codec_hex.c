// AES_백승민_2020253045
#include "codec_hex.h"
/* HEX 코덱 구현
   - to_hex/from_hex: 4비트 조각 <-> 문자
   - encode: 바이트 1개를 문자 2개(상위 4비트, 하위 4비트)로 변환
   - decode: 두 글자를 1바이트로 합침(대소문자 모두 허용) */
// One Character Encoding to Hex
static char to_hex(uint8_t x) {
    if (x < 10) 
        return (char)('0' + x);
    else
        return (char)('A'+ (x-10));
}
/* in[i] -> out_hex[2*i], out_hex[2*i+1]
   한 바이트를 두 글자 HEX로 쪼갬
   - 앞 글자: 상위 4비트
   - 뒷 글자: 하위 4비트 */
void hex_encode(const uint8_t *in, size_t in_len, uint8_t *out_hex) {
    for (size_t i = 0; i < in_len; i++) {
        // each byte to two hex chars
        uint8_t b = in[i];
        out_hex[2*i] = (uint8_t)to_hex( (b>>4) );   // high nibble
        out_hex[2*i + 1] = (uint8_t)to_hex((uint8_t) (b & 0x0F));   // low nibble
    }
}
/* 내부: '0'..'9','A'..'F','a'..'f' -> 0..15
   그 외 -> -1 (유효하지 않은 문자) */
// One Character Decoding from Hex
static int from_hex(int c) {
    if (c >= '0' && c <= '9') 
        return c - '0';
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else
        return -1;  // invalid
}
/* HEX 한 줄 디코드
   - 길이는 반드시 짝수
   - 두 글자(각 4비트)를 합쳐서 1바이트로 만든다: (앞<<4) | 뒤 */
long hex_decode_line(const uint8_t *in_hex, size_t in_hex_len, uint8_t *out_bytes) {
    // check even length
    if (in_hex_len % 2 != 0)
        return -1;
    size_t i;
    for (i = 0; i < in_hex_len; i+=2) {
        int high = from_hex((int)in_hex[i]);
        int low = from_hex((int)in_hex[i+1]);
        // check invalid
        if (high < 0 || low < 0) 
            return -1;
        out_bytes[i/2] = (uint8_t)((high << 4) | low);  // combine
    }
    return (long)(in_hex_len / 2);
}