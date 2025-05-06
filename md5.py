import hashlib

def md5_hash(message):
    return hashlib.md5(message.encode()).hexdigest()
