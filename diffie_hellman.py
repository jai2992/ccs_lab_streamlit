def diffie_hellman_shared_key(p, g, a, b):
    A = pow(g, a, p)
    B = pow(g, b, p)
    key_a = pow(B, a, p)
    key_b = pow(A, b, p)
    return A, B, key_a, key_b
