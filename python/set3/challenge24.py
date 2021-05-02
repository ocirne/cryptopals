
from basics import padding, strip_padding
from challenge21 import MersenneTwister
import secrets

KNOWN_PT = b'AAAAAAAAAAAAAA'
PREFIX = secrets.token_bytes(secrets.randbelow(100))

seed = secrets.randbits(16)
mt = MersenneTwister(seed)


def challenge24():
    seed = secrets.randbits(16)
    mt = MersenneTwister(seed)


def encrypt(pt: bytes):
    mt.seed(seed)
    ppt = padding(pt, 4)
    return bytes(p ^ (k % 256) for p, k in zip(ppt, mt.generate(len(ppt))))


def decrypt(ct: bytes):
    mt.seed(seed)
    ppt = bytes(c ^ (k % 256) for c, k in zip(ct, mt.generate(len(ct))))
    return strip_padding(ppt)


if __name__ == '__main__':
    challenge24()
    orig = PREFIX + KNOWN_PT
    ct = encrypt(orig)
    print('ct', ct)
    pt = decrypt(ct)
    print('pt', pt)
    assert orig == pt
