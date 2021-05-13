import hashlib
import hmac
import sys

from Crypto.Hash import SHA256

import secrets


def sha256(data: bytes) -> bytes:
    h = SHA256.new()
    h.update(data)
    return h.digest()


def hmac_sha256(key: bytes, message: bytes) -> str:
    h = hmac.new(key, message, hashlib.sha256)
    return h.hexdigest()


def to_bytes(i: int) -> bytes:
    #    print(i)
    r = i.to_bytes(128, sys.byteorder)
    # TODO seltsam, r sieht sehr sparse aus
    print(r)
    return r


def to_int(b: bytes) -> int:
    return int.from_bytes(b, sys.byteorder)


def hash_public_key(A, B):
    return to_int(sha256((str(A) + str(B)).encode()))


# for NIST Primes see https://www.johndcook.com/blog/2019/05/12/nist-primes/
N = 2 ** 521 - 1
g = 2
k = 3
email = b"test@example.com"
password = b"totally secure password"


class Server:
    def __init__(self):
        super().__init__()
        self.salt = secrets.token_bytes(16)
        # see https://pythonhosted.org/srp/srp.html
        # x = to_int(sha256(self.salt + sha256(email + b':' + password)))
        x = to_int(sha256(self.salt + b":" + password))
        self.v = pow(g, x, N)

    def _server_k(self, A, b, u):
        S = pow(A * pow(self.v, u, N), b, N)
        return sha256(to_bytes(S))

    def request_key(self, I, A):
        b = secrets.randbelow(N)
        B = (k * self.v + pow(g, b, N)) % N
        u = hash_public_key(A, B)
        self.K = self._server_k(A, b, u)
        return self.salt, B

    def validate(self, client_hmac):
        return client_hmac == hmac_sha256(self.K, self.salt)


class Client:
    def __init__(self, server: Server):
        super().__init__()
        self.server = server

    def _client_k(self, salt, a, B, u):
        x = to_int(sha256(salt + b":" + password))
        S = pow(B - k * pow(g, x, N), a + u * x, N)
        return sha256(to_bytes(S))

    def run(self):
        a = secrets.randbelow(N)
        A = pow(g, a, N)
        salt, B = self.server.request_key(email, A)
        u = hash_public_key(A, B)
        K = self._client_k(salt, a, B, u)
        is_valid = self.server.validate(hmac_sha256(K, salt))
        assert is_valid


def challenge36():
    """
    >>> challenge36()
    """
    server = Server()
    client = Client(server)

    client.run()


if __name__ == "__main__":
    challenge36()
