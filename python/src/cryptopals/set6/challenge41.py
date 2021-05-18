from cpcrypto import RSA


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
        return self.rsa.decrypt(ct)


class Mallory:
    def __init__(self, server: Bob):
        self.server = server

    def please_decrypt(self, ct):
        return self.server.please_decrypt(ct)


class Alice:
    def __init__(self, rsa: RSA, server: Mallory):
        self.rsa = rsa
        self.server = server
        self.secret = "Speak Friend"

    def run(self):
        ct = self.rsa.encrypt(self.secret)
        pt = self.server.please_decrypt(ct)
        assert pt == self.secret
        assert self.server.please_decrypt(ct) is None


def challenge41():
    # TODO a shared RSA instance is as wrong as possible
    rsa = RSA()
    bob = Bob(rsa)
    mallory = Mallory(bob)
    alice = Alice(rsa, mallory)
    alice.run()


if __name__ == "__main__":
    challenge41()
