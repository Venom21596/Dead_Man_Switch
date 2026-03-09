import secrets
from typing import List, Tuple

PRIME = 0x11B  # GF(2^8) irreducible polynomial

def _gf_mul(a, b):
    result = 0
    while b:
        if b & 1: result ^= a
        a <<= 1
        if a & 0x100: a ^= PRIME
        b >>= 1
    return result & 0xFF

def _gf_pow(base, exp):
    result = 1
    while exp > 0:
        if exp & 1: result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result

def _gf_inv(a):
    if a == 0: raise ValueError("Cannot invert zero")
    return _gf_pow(a, 254)

def _eval_poly(coeffs, x):
    result = 0
    for c in reversed(coeffs):
        result = _gf_mul(result, x) ^ c
    return result

def _lagrange(x, points):
    result = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = _gf_mul(num, x ^ xj)
                den = _gf_mul(den, xi ^ xj)
        result ^= _gf_mul(yi, _gf_mul(num, _gf_inv(den)))
    return result

def split_secret(secret: bytes, threshold: int, num_shares: int) -> List[Tuple[int, bytes]]:
    assert threshold >= 2, "Threshold must be >= 2"
    assert num_shares >= threshold, "num_shares must be >= threshold"
    shares = [(i, bytearray()) for i in range(1, num_shares + 1)]
    for byte_val in secret:
        coeffs = [byte_val] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i, (x, data) in enumerate(shares):
            data.append(_eval_poly(coeffs, x))
    return [(x, bytes(d)) for x, d in shares]

def reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    length = len(shares[0][1])
    result = bytearray()
    for i in range(length):
        points = [(x, s[i]) for x, s in shares]
        result.append(_lagrange(0, points))
    return bytes(result)

def shares_to_hex(shares):
    return [f"{x:02x}:{d.hex()}" for x, d in shares]

def hex_to_shares(hex_shares):
    result = []
    for s in hex_shares:
        x_str, d_str = s.split(":", 1)
        result.append((int(x_str, 16), bytes.fromhex(d_str)))
    return result

if __name__ == "__main__":
    print("=== Shamir Self-Test ===")
    secret = b"MyAES256KeyForTest!12345678901234"
    print(f"Secret: {secret.hex()}")
    shares = split_secret(secret, 3, 5)
    hexes = shares_to_hex(shares)
    for i, h in enumerate(hexes): print(f"  Share {i+1}: {h[:40]}...")
    recovered = reconstruct_secret([shares[0], shares[2], shares[4]])
    print(f"Recovered: {recovered.hex()}")
    print(f"Match: {recovered == secret}")
