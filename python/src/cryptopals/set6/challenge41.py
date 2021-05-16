import sys

# from cryptopals.math import invmod, random_prime
from cpmath import invmod, random_prime


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
    >>> rsa.decrypt(rsa.encrypt('sticky'))
    'sticky'
    """

    def __init__(self):
        self.d = None
        while self.d is None:
            p = random_prime()
            q = random_prime()
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


class Bob:
    def __init__(self, rsa: RSA):
        self.rsa = rsa

    def get_public_key(self):
        return self.rsa.public_key()

    def please_decrypt(self, ct):
        return "sticky"


class Mallory:
    def __init__(self, server: Bob):
        self.server = server

    def blub(self):
        ...

    def get_public_key(self):
        return self.server.get_public_key()

    def please_decrypt(self, ct):
        return self.server.please_decrypt(ct)


class Alice:
    def __init__(self, rsa: RSA, server: Mallory):
        self.rsa = rsa
        self.server = server
        self.secret = "sticky"

    def run(self):
        ct = self.rsa.encrypt(self.secret)
        pt = self.server.please_decrypt(ct)
        assert pt == self.secret


def challenge41():
    # TODO a shared RSA instance is as wrong as possible
    rsa = RSA()
    bob = Bob(rsa)
    mallory = Mallory(bob)
    alice = Alice(rsa, mallory)
    alice.run()


if __name__ == "__main__":
    challenge41()
