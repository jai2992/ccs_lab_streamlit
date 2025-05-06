import numpy as np

def hill_prepare_text(text, n):
    text = text.upper().replace(' ', '')
    while len(text) % n != 0:
        text += 'X'
    return text

def hill_text_to_numbers(text):
    return [ord(c) - 65 for c in text]

def hill_numbers_to_text(nums):
    return ''.join([chr(n + 65) for n in nums])

def hill_encrypt(plaintext, key_matrix):
    n = key_matrix.shape[0]
    text = hill_prepare_text(plaintext, n)
    numbers = hill_text_to_numbers(text)
    cipher_nums = []
    for i in range(0, len(numbers), n):
        block = np.array(numbers[i:i+n])
        enc_block = np.dot(key_matrix, block) % 26
        cipher_nums.extend(enc_block)
    return hill_numbers_to_text([int(x) for x in cipher_nums])

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def hill_inverse_matrix(matrix):
    det = int(round(np.linalg.det(matrix)))
    det_inv = modinv(det % 26, 26)
    if det_inv is None:
        return None
    matrix_mod_inv = (
        det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % 26
    ) % 26
    return matrix_mod_inv

def hill_decrypt(ciphertext, key_matrix):
    n = key_matrix.shape[0]
    inv_matrix = hill_inverse_matrix(key_matrix)
    if inv_matrix is None:
        return None
    numbers = hill_text_to_numbers(ciphertext)
    plain_nums = []
    for i in range(0, len(numbers), n):
        block = np.array(numbers[i:i+n])
        dec_block = np.dot(inv_matrix, block) % 26
        plain_nums.extend(dec_block)
    return hill_numbers_to_text([int(round(x)) for x in plain_nums])
