import secrets
from urllib.parse import quote_plus

from Crypto.Cipher import AES

from cryptopals.basics import padding

BLOCK_SIZE = 16


class Oracle16:
    def __init__(self):
        self.key = secrets.token_bytes(BLOCK_SIZE)
        self.iv = secrets.token_bytes(BLOCK_SIZE)
        self.prefix = b'"comment1=cooking%20MCs;userdata="'
        self.suffix = b'";comment2=%20like%20a%20pound%20of%20bacon"'

    def aes_cbc(self):
        return AES.new(self.key, AES.MODE_CBC, self.iv)  # NOSONAR

    def encrypt(self, input_string):
        plain_text = self.prefix + quote_plus(input_string).encode() + self.suffix
        return bytes(self.aes_cbc().encrypt(padding(plain_text)))

    def decrypt(self, ciphertext: bytes):
        return self.aes_cbc().decrypt(ciphertext)


oracle = Oracle16()


def is_broken_c16(ciphertext: bytes):
    plaintext = oracle.decrypt(ciphertext)
    return b";admin=true;" in plaintext


def modify(ct: bytes):
    mutable_ct = bytearray(ct)
    for (i, (x, y)) in enumerate(zip("g%20MCs;user", ";admin=true;")):
        mutable_ct[i] ^= ord(x) ^ ord(y)
    return bytes(mutable_ct)


def challenge16():
    """
    >>> challenge16()
    """
    ciphertext = oracle.encrypt(";admin=true;")
    modified = modify(ciphertext)

    #    print('----')
    #    plaintext = decrypt_c16(ciphertext)
    #    mod_plaintext = decrypt_c16(modified)
    #    for chunk, mod_chunk in zip(chunks(plaintext, BLOCK_SIZE), chunks(mod_plaintext, BLOCK_SIZE)):
    #        print("%s    %s\n%s    %s\n" % (chunk.hex(), chunk, mod_chunk.hex(), mod_chunk))

    assert not is_broken_c16(ciphertext)
    assert is_broken_c16(modified)


if __name__ == "__main__":
    challenge16()
