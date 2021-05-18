from cryptopals.math import invmod
from cryptopals.crypto import RSA, int_to_str


class Bob:
    def __init__(self, rsa: RSA):
        self.rsa = rsa
        self.seen = []

    def get_public_key(self):
        return self.rsa.public_key()

    def please_decrypt(self, ct):
        if ct in self.seen:
            return None
        self.seen.append(ct)
        return self.rsa._decrypt(ct)


class Alice:
    def __init__(self, rsa: RSA, bob: Bob):
        self.rsa = rsa
        self.bob = bob
        self.secret = "Speak Friend"
        self.ct = self.rsa.encrypt(self.secret)

    def run(self):
        pt = int_to_str(self.bob.please_decrypt(self.ct))
        assert pt == self.secret
        assert self.bob.please_decrypt(self.ct) is None


class Trudy:
    def __init__(self, bob: Bob):
        self.bob = bob

    def recover_plaintext(self, ct):
        assert self.bob.please_decrypt(ct) is None
        e, n = self.bob.rsa.public_key()
        s = 4  # guaranteed random
        cs = (pow(s, e, n) * ct) % n
        ps = self.bob.please_decrypt(cs)
        p = (ps * invmod(s, n)) % n
        return int_to_str(p)


def challenge41():
    """
    >>> challenge41()
    'Speak Friend'
    """
    # TODO a shared RSA instance is as wrong as possible
    rsa = RSA()
    bob = Bob(rsa)
    alice = Alice(rsa, bob)
    alice.run()
    ct = alice.ct
    trudy = Trudy(bob)
    return trudy.recover_plaintext(ct)


if __name__ == "__main__":
    print(challenge41())
