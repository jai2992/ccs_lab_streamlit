import hashlib

def sha_hash(message, variant='sha256'):
    if variant == 'sha1':
        return hashlib.sha1(message.encode()).hexdigest()
    elif variant == 'sha256':
        return hashlib.sha256(message.encode()).hexdigest()
    elif variant == 'sha512':
        return hashlib.sha512(message.encode()).hexdigest()
    else:
        return None
