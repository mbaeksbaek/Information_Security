#!/usr/bin/env python3
"""
RSA Vector Generator for Assignment
- Generates RSA keys (512 / 1024 / 2048 bits)
- For each key, generates multiple (pt_hex, ct_hex) pairs
- Output: rsa_vectors.json  (big-endian HEX, N/e/d padded to k_bytes*2)

주의:
- 이것은 과제 검증용 KAT 벡터 생성기일 뿐, 실제 보안용 키 생성기 아님.
- Miller-Rabin / RNG 구현도 "과제용 수준"임.
"""

import json
import random
from math import gcd

# 재현 가능한 벡터 생성을 위해 고정 seed
random.seed(0xDEADBEEF)


def is_probable_prime(n: int, k: int = 16) -> bool:
    """Miller-Rabin primality test (과제용, constant-time 아님)."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n-1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    """bits 길이의 확률적 소수 생성 (상위비트 세우고, 홀수)."""
    while True:
        n = random.getrandbits(bits)
        # 상위 비트 세우고, 홀수로
        n |= (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


def modinv(a: int, m: int) -> int:
    """a^{-1} mod m (extended Euclid)."""
    def egcd(x, y):
        if y == 0:
            return x, 1, 0
        g, s1, t1 = egcd(y, x % y)
        return g, t1, s1 - (x // y) * t1

    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("modinv: gcd != 1")
    return x % m


def gen_rsa_key(bits: int):
    """교재 스타일 RSA 키 (n, e, d) 생성."""
    e = 65537
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue
        d = modinv(e, phi)
        return n, e, d


def int_to_hex(n: int, width_bytes: int) -> str:
    """n을 big-endian hex 문자열로 (길이=width_bytes*2, 앞쪽 zero-pad)."""
    hex_str = f"{n:x}"
    return hex_str.rjust(width_bytes * 2, "0")


def gen_vectors_for_key(bits: int, num_cases: int = 6):
    """하나의 RSA 키에 대해 여러 (pt, ct) 벡터 생성."""
    print(f"[+] Generating RSA-{bits} key...")
    n, e, d = gen_rsa_key(bits)
    k_bytes = (n.bit_length() + 7) // 8
    width_hex = k_bytes * 2

    N_hex = int_to_hex(n, k_bytes)
    e_hex = int_to_hex(e, k_bytes)
    d_hex = int_to_hex(d, k_bytes)

    # 고정 plaintext들 + 난수 plaintext들
    fixed_pts = [
        "00",                          # 0
        "01",                          # 1
        "48656c6c6f20525341",          # "Hello RSA"
        "5465737420766563746f722031",  # "Test vector 1"
    ]

    cases = []
    idx = 0

    # 고정 케이스
    for pt_hex in fixed_pts:
        m = int(pt_hex, 16)
        if m >= n:
            # 매우 희귀 but 혹시 모를 경우 방어
            raise ValueError("fixed plaintext >= modulus")
        c = pow(m, e, n)
        ct_hex = f"{c:x}".rjust(width_hex, "0")
        cases.append(
            {
                "name": f"RSA{bits}_case{idx}",
                "pt_hex": pt_hex,
                "ct_hex": ct_hex,
            }
        )
        idx += 1

    # 랜덤 케이스 (길이 16바이트짜리 난수)
    while idx < num_cases:
        l = 16
        rnd = random.getrandbits(l * 8)
        pt_hex = f"{rnd:x}".rjust(l * 2, "0")
        m = int(pt_hex, 16)
        if m >= n:
            continue  # 이론상 거의 없음
        c = pow(m, e, n)
        ct_hex = f"{c:x}".rjust(width_hex, "0")
        cases.append(
            {
                "name": f"RSA{bits}_case{idx}",
                "pt_hex": pt_hex,
                "ct_hex": ct_hex,
            }
        )
        idx += 1

    return {
        "bits": bits,
        "k_bytes": k_bytes,
        "N_hex": N_hex,
        "e_hex": e_hex,
        "d_hex": d_hex,
        "cases": cases,
    }


def main():
    # 필요하면 여기서 키 길이 추가/삭제 가능
    key_sizes = [512, 1024, 2048]
    num_cases_per_key = 6

    all_vectors = []
    for bits in key_sizes:
        v = gen_vectors_for_key(bits, num_cases=num_cases_per_key)
        all_vectors.append(v)

    out = {
        "source": "custom-generated for RSA assignment (textbook RSA, big-endian HEX)",
        "note": (
            "Key sizes 512/1024/2048 bits. "
            "Values are big-endian hex. "
            "For CryptoOps: key_hex = N_hex || e_hex (ENC) or N_hex || d_hex (DEC)."
        ),
        "vectors": all_vectors,
    }

    with open("rsa_vectors.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("[+] Wrote rsa_vectors.json")


if __name__ == "__main__":
    main()
