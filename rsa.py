import random
from math import gcd

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def rsa_generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return ((e, n), (d, n))

def rsa_encrypt(plaintext, pubkey):
    e, n = pubkey
    return pow(plaintext, e, n)

def rsa_decrypt(ciphertext, privkey):
    d, n = privkey
    return pow(ciphertext, d, n)
