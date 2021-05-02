
from basics import padding, strip_padding, xor
from challenge21 import MersenneTwister
import secrets


class Oracle24:
    """
    >>> pt = secrets.token_bytes(100)
    >>> assert pt == oracle.decrypt(oracle.encrypt(pt))
    """

    def __init__(self):
        self.seed = secrets.randbits(16)

    @staticmethod
    def key_stream(mt: MersenneTwister, length):
        return (k % 256 for k in mt.generate(length))

    def encrypt(self, pt: bytes):
        mt = MersenneTwister(self.seed)
        ppt = padding(pt, 4)
        return xor(ppt, self.key_stream(mt, len(ppt)))

    def encrypt_with_prefix(self, pt: bytes):
        prefix = secrets.token_bytes(secrets.randbelow(100))
        return self.encrypt(prefix + pt)

    def decrypt(self, ct: bytes):
        mt = MersenneTwister(self.seed)
        ppt = xor(ct, self.key_stream(mt, len(ct)))
        return strip_padding(ppt)

    def actual_seed(self):
        return self.seed


oracle = Oracle24()


def challenge24():
    ct = oracle.encrypt_with_prefix(b'AAAAAAAAAAAAAA')
    print(ct)


if __name__ == '__main__':
    challenge24()
