def caesar_cipher_encrypt(text, key):
    result = ''
    for char in text:
        if char.isupper():
            result += chr((ord(char) - 65 + key) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - 97 + key) % 26 + 97)
        else:
            result += char
    return result

def caesar_cipher_decrypt(cipher, key):
    return caesar_cipher_encrypt(cipher, -key)
