def playfair_generate_key_matrix(keyword):
    keyword = ''.join(sorted(set(keyword.upper()), key=keyword.index)).replace('J', 'I')
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    key_string = keyword + ''.join([c for c in alphabet if c not in keyword])
    matrix = [list(key_string[i*5:(i+1)*5]) for i in range(5)]
    return matrix

def playfair_find_position(matrix, char):
    for i, row in enumerate(matrix):
        for j, c in enumerate(row):
            if c == char:
                return i, j
    return None, None

def playfair_prepare_text(text):
    text = text.upper().replace('J', 'I')
    prepared = ''
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            prepared += a + 'X'
            i += 1
        else:
            prepared += a + b
            i += 2
    if len(prepared) % 2 != 0:
        prepared += 'X'
    return prepared

def playfair_encrypt(plaintext, keyword):
    matrix = playfair_generate_key_matrix(keyword)
    text = playfair_prepare_text(plaintext)
    cipher = ''
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        row1, col1 = playfair_find_position(matrix, a)
        row2, col2 = playfair_find_position(matrix, b)
        if row1 == row2:
            cipher += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
        elif col1 == col2:
            cipher += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
        else:
            cipher += matrix[row1][col2] + matrix[row2][col1]
    return cipher

def playfair_decrypt(ciphertext, keyword):
    matrix = playfair_generate_key_matrix(keyword)
    text = ciphertext.upper()
    plain = ''
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        row1, col1 = playfair_find_position(matrix, a)
        row2, col2 = playfair_find_position(matrix, b)
        if row1 == row2:
            plain += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
        elif col1 == col2:
            plain += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
        else:
            plain += matrix[row1][col2] + matrix[row2][col1]
    return plain
