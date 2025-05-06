def rail_fence_encrypt_col_major(text, cols):
    if cols <= 1:
        return text
    rows = (len(text) + cols - 1) // cols
    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(text):
                matrix[r][c] = text[idx]
                idx += 1
            else:
                matrix[r][c] = ''
    encrypted = ''
    for c in range(cols):
        for r in range(rows):
            if matrix[r][c]:
                encrypted += matrix[r][c]
    return encrypted

def rail_fence_decrypt_col_major(cipher, cols):
    if cols <= 1:
        return cipher
    rows = (len(cipher) + cols - 1) // cols
    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(rows):
            if idx < len(cipher):
                matrix[r][c] = cipher[idx]
                idx += 1
    decrypted = ''
    for r in range(rows):
        for c in range(cols):
            if matrix[r][c]:
                decrypted += matrix[r][c]
    return decrypted
