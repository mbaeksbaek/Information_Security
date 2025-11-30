#include "big_int.h"
#include <stdio.h>

int main(void) {
    BigInt a, b, c;

    bi_from_u64(&a, 1234567890123456ULL);
    bi_from_u64(&b, 987654321ULL);

    bi_add(&c, &a, &b);
    printf("a + b = ");
    bi_print_hex(&c);

    bi_mul(&c, &a, &b);
    printf("a * b = ");
    bi_print_hex(&c);

    return 0;
}
