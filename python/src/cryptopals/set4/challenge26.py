
import secrets
from urllib.parse import quote_plus

from Crypto.Cipher import AES
from Crypto.Util import Counter

BLOCK_SIZE = 16


class Oracle26:

    def __init__(self):
        self.ctr_key = secrets.token_bytes(BLOCK_SIZE)
        self.prefix = b'"comment1=cooking%20MCs;userdata="'
        self.suffix = b'";comment2=%20like%20a%20pound%20of%20bacon"'

    def aes_ctr(self):
        ctr = Counter.new(64, prefix='\x00' * 8, little_endian=True, initial_value=0)
        return AES.new(self.ctr_key, AES.MODE_CTR, counter=ctr)

    def encrypt(self, input_bytes: bytes):
        plain_text = self.prefix + quote_plus(input_bytes).encode() + self.suffix
        return self.aes_ctr().encrypt(plain_text)

    def decrypt(self, ct: bytes):
        return self.aes_ctr().decrypt(ct)


oracle = Oracle26()


def is_broken_c26(ciphertext: bytes):
    plaintext = oracle.decrypt(ciphertext)
    return b';admin=true;' in plaintext


def modify(ct: bytes):
    mutable_ct = bytearray(ct)
    for (i, (x, y)) in enumerate(zip(b'g%20MCs;user', b';admin=true;')):
        mutable_ct[i+BLOCK_SIZE] ^= x ^ y
    return bytes(mutable_ct)


def challenge26():
    """
    >>> challenge26()
    """
    ciphertext = oracle.encrypt(b';admin=true;')
    modified = modify(ciphertext)
#    plaintext = oracle.decrypt(ciphertext)
#    mod_plaintext = oracle.decrypt(modified)
#    for chunk, mod_chunk in zip(chunks(plaintext, BLOCK_SIZE), chunks(mod_plaintext, BLOCK_SIZE)):
#        print("%s    %s\n%s    %s\n" % (chunk.hex(), chunk, mod_chunk.hex(), mod_chunk))
    assert not is_broken_c26(ciphertext)
    assert is_broken_c26(modified)


if __name__ == '__main__':
    challenge26()
