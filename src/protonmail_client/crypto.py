import base64
from contextlib import nullcontext


class ProtonCryptoError(RuntimeError):
    pass


class PMHash:
    digest_size = 256
    name = 'PMHash'

    def __init__(self, data=b''):
        self.data = data

    def update(self, data):
        self.data += data

    def digest(self):
        import hashlib
        return b''.join(hashlib.sha512(self.data + bytes([i])).digest() for i in range(4))

    def copy(self):
        return PMHash(self.data)


def pmhash(data=b''):
    return PMHash(data)


def bcrypt_b64_encode(data: bytes) -> bytes:
    alphabet = b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    out = bytearray()
    i = 0
    while i < len(data):
        c1 = data[i]
        i += 1
        out.append(alphabet[c1 >> 2])
        c1 = (c1 & 0x03) << 4
        if i >= len(data):
            out.append(alphabet[c1])
            break
        c2 = data[i]
        i += 1
        c1 |= c2 >> 4
        out.append(alphabet[c1])
        c1 = (c2 & 0x0F) << 2
        if i >= len(data):
            out.append(alphabet[c1])
            break
        c2 = data[i]
        i += 1
        c1 |= c2 >> 6
        out.append(alphabet[c1])
        out.append(alphabet[c2 & 0x3F])
    return bytes(out)


def compute_key_password(password: str, key_salt_b64: str) -> str:
    try:
        import bcrypt
    except ImportError as e:
        raise ProtonCryptoError('missing dependency: pip install bcrypt') from e
    key_salt = base64.b64decode(key_salt_b64)
    salt = b'$2y$10$' + bcrypt_b64_encode(key_salt)[:22]
    return bcrypt.hashpw(password.encode(), salt)[29:].decode()


def decrypt_pgp_message(body: str, key, key_password: str) -> str:
    try:
        import pgpy
    except ImportError as e:
        raise ProtonCryptoError('PGPy is required for ProtonMail PGP decryption; install dependency from Pipfile') from e

    encrypted = pgpy.PGPMessage.from_blob(body)
    unlock = key.unlock(key_password) if key.is_protected else nullcontext(key)
    with unlock as unlocked_key:
        decrypted = unlocked_key.decrypt(encrypted)
    plaintext = decrypted.message
    if isinstance(plaintext, bytes):
        return plaintext.decode('utf-8', errors='replace')
    return str(plaintext)
