from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_encrypt(plaintext, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'), 8)
    encrypted = cipher.encrypt(padded)
    return encrypted.hex()

def des_decrypt(ciphertext, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), 8)
    return decrypted.decode('utf-8')
