from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(plaintext, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'), 16)
    encrypted = cipher.encrypt(padded)
    return encrypted.hex()

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), 16)
    return decrypted.decode('utf-8')
