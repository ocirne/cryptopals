def random_prime():
    return 2 ** 31 - 1


def egcd(a, b):
    """
    see https://de.wikipedia.org/wiki/Erweiterter_euklidischer_Algorithmus

    >>> egcd(18, 24)
    (6, -1, 1)
    >>> egcd(64, 32)
    (32, 0, 1)
    >>> egcd(35, 24)
    (1, 11, -16)
    """
    if b == 0:
        return a, 1, 0
    d, s, t = egcd(b, a % b)
    return d, t, s - (a // b) * t


def invmod(a, n):
    """
    >>> invmod(17, 3120)
    2753
    """
    d, s, t = egcd(a, n)
    if d != 1:
        raise Exception("a is not invertible")
    if s < 0:
        s += n
    return s % n


class RSA:
    def __init__(self):
        p = 23
        q = 41
        self.n = p * q
        et = (p - 1) * (q - 1)
        # public key: [e, n]
        self.e = 3
        # private key: [d, n]
        self.d = invmod(self.e, et)

    def _encrypt(self, m: int) -> int:
        return pow(m, self.e, self.n)

    def _decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)

    def encrypt(self, m: str) -> str:
        return pow(m, self.e, self.n)

    def decrypt(self, c: str) -> str:
        return pow(c, self.d, self.n)


def challenge39():
    rsa = RSA()
    assert rsa._decrypt(rsa._encrypt(42)) == 42
    assert rsa._encrypt(rsa._decrypt(42)) == 42


#    assert rsa.decrypt(rsa.encrypt(b'foo')) == b'foo'
#    assert rsa.encrypt(rsa.decrypt(b'foo')) == b'foo'


if __name__ == "__main__":
    egcd(24, 18)
    challenge39()
