import sys

import secrets
from pathlib import Path
from typing import Union

from cryptopals.set5.challenge36 import sha256, hmac_sha256


CRACKLIB_SMALL = "/usr/share/dict/cracklib-small"  # ~35 seconds
CRACKLIB_SMALLER = Path(__file__).parent / "resources/38.txt"


def to_bytes(i: int) -> bytes:
    return i.to_bytes(128, sys.byteorder)


def to_int(b: bytes) -> int:
    return int.from_bytes(b, sys.byteorder)


def hash_public_key(A, B):  # NOSONAR
    return to_int(sha256((str(A) + str(B)).encode()))


def words():
    for line in open(CRACKLIB_SMALLER):
        yield bytes(line.strip(), "UTF-8")


# https://datatracker.ietf.org/doc/html/rfc5054#appendix-A, 1. 1024-bit Group
N = int(
    "EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C"
    "9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4"
    "8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29"
    "7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A"
    "FD5138FE 8376435B 9FC61D2F C0EB06E3".replace(" ", ""),
    16,
)

g = 2
k = 3
email = b"test@example.com"
password = b"sticky"  # NOSONAR


class Server:
    def __init__(self):
        self.salt = secrets.token_bytes(16)
        x = to_int(sha256(self.salt + password))
        self.v = pow(g, x, N)

    def _server_k(self, A, b, u):  # NOSONAR
        S = pow(A * pow(self.v, u, N), b, N)
        return sha256(to_bytes(S))

    def request_key(self, I, A):  # NOSONAR
        b = secrets.randbelow(N)
        B = pow(g, b, N)
        u = secrets.randbits(128)
        self.K = self._server_k(A, b, u)
        return self.salt, B, u

    def validate(self, client_hmac):
        return client_hmac == hmac_sha256(self.K, self.salt)


class Mallory:
    """ modifies (b), B, u, (salt) """

    def __init__(self, server: Server):
        self.server = server

    def request_key(self, I, A):  # NOSONAR
        self.A = A
        self.salt, _, _ = self.server.request_key(I, A)
        # set B = g, u = 1
        return self.salt, g, 1

    def _simulate_hmac(self, guess):
        """
        S = B ** (a+ u*x) = B**a * B**(u*x) mod N
        set B = g, u = 1
        S = g**a * g**(1*x) = A * g**x mod N
        """
        x = to_int(sha256(self.salt + guess))
        S = (self.A * pow(g, x, N)) % N
        K = sha256(to_bytes(S))
        return hmac_sha256(K, self.salt)

    def _crack_password(self, client_hmac):
        for word in words():
            guess_hmac = self._simulate_hmac(word)
            if guess_hmac == client_hmac:
                return word

    def validate(self, client_hmac):
        recovered_password = self._crack_password(client_hmac)
        print("recovered password:", recovered_password.decode())
        # the hmac doesn't validate for the server, but can be calculated from the known password
        return self.server.validate(client_hmac)


class Client:
    def __init__(self, server: Mallory | Server):
        self.server = server

    def _client_k(self, salt, a, B, u):  # NOSONAR
        x = to_int(sha256(salt + password))
        S = pow(B, a + u * x, N)
        return sha256(to_bytes(S))

    def run(self):
        a = secrets.randbelow(N)
        A = pow(g, a, N)
        salt, B, u = self.server.request_key(email, A)
        K = self._client_k(salt, a, B, u)
        return self.server.validate(hmac_sha256(K, salt))


def challenge38():
    """
    >>> challenge38()
    recovered password: sticky
    """
    server = Server()
    mallory = Mallory(server)
    client = Client(mallory)

    client.run()


if __name__ == "__main__":
    challenge38()
