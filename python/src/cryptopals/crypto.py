import sys

from cryptopals.math import invmod, random_prime


def str_to_int(s: str) -> int:
    b = bytes(s, "UTF-8")
    return int.from_bytes(b, sys.byteorder)


def int_to_str(i: int) -> str:
    b = i.to_bytes(16, sys.byteorder)
    return b.decode("UTF-8").strip("\x00")


class RSA:
    """
    >>> rsa = RSA()
    >>> rsa._decrypt(rsa._encrypt(42))
    42
    >>> rsa._encrypt(rsa._decrypt(42))
    42
    >>> rsa.verify("foo", rsa.sign("foo"))
    True
    >>> rsa.verify("bar", rsa.sign("foo"))
    False
    """

    def __init__(self, s: int = 128):
        self.d = None
        while self.d is None:
            p = random_prime(s)
            q = random_prime(s)
            self.n = p * q
            et = (p - 1) * (q - 1)
            # public key: [e, n]
            self.e = 3
            # private key: [d, n]
            self.d = invmod(self.e, et)

    def public_key(self):
        return self.e, self.n

    def _encrypt(self, m: int) -> int:
        return pow(m, self.e, self.n)

    def _decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)

    def encrypt(self, p: str) -> int:
        return self._encrypt(str_to_int(p))

    def decrypt(self, c: int) -> str:
        return int_to_str(self._decrypt(c))

    def sign(self, message) -> int:
        return self._decrypt(str_to_int(message))

    def verify(self, message, signature) -> bool:
        return self._encrypt(signature) == str_to_int(message)
