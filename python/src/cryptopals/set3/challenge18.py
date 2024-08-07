import base64

from Crypto.Cipher import AES
from Crypto.Util import Counter

from cryptopals.basics import from_hex

BLOCK_SIZE = 16

SECRET = base64.b64decode(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

KEY = b"YELLOW SUBMARINE"


def aes_ctr():
    ctr = Counter.new(64, prefix=from_hex("00" * 8), little_endian=True, initial_value=0)
    return AES.new(KEY, AES.MODE_CTR, counter=ctr)


def encrypt(plain_text: bytes):
    return aes_ctr().encrypt(plain_text)


def decrypt(cipher_text: bytes):
    return aes_ctr().decrypt(cipher_text)


def challenge18():
    """
    >>> challenge18()
    b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    """
    return decrypt(SECRET)


if __name__ == "__main__":
    print(challenge18())
