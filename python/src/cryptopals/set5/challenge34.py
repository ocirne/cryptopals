import random
import secrets
from typing import Union

from Crypto.Cipher import AES

from basics import padding
from digests import SHA1


def aes_cbc(priv_key: int, message: bytes) -> bytes:
    s = priv_key.to_bytes(8, byteorder="big")
    key = SHA1().digest(s)[:16]
    iv = secrets.token_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    aes.encrypt(padding(message))
    return aes.encrypt(padding(message)) + iv


class Bob:
    def request_pub_key(self, p, g, A):
        """
        B -> M
        Send "B"
        """
        b = random.randrange(0, p)
        B = pow(g, b, p)
        self.s = pow(A, b, p)
        print("bob s", self.s)
        return B

    def request_message(self, ciphertext_a: bytes) -> bytes:
        """
        B->M
        Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
        """
        return aes_cbc(self.s, ciphertext_a)


class Mallory:
    def __init__(self, bob: Bob):
        self.bob = bob

    def request_pub_key(self, p, g, A):
        """
        A->M
        Send "p", "g", "p"
        ---
        M->A
        Send "p"
        """
        self.bob.request_pub_key(p, g, p)
        return p

    def request_message(self, ciphertext_a: bytes) -> bytes:
        """
        M->B
        Relay that to B
        ---
        M->A
        Relay that to A
        """
        ct_b = self.bob.request_message(ciphertext_a)
        return ct_b


class Alice:
    def __init__(self, bob: Union[Bob, Mallory]):
        self.bob = bob
        self.pt = b"Ice Ice Baby"

    def request_pub_key(self):
        """
        A -> M
        Send "p", "g", "A"
        """
        p = 3700001
        g = 50
        a = random.randrange(0, p)
        A = pow(g, a, p)
        B = self.bob.request_pub_key(p, g, A)
        self.s = pow(B, a, p)
        print("alice s", self.s)

    def request_message(self):
        """
        A -> M
        Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        """
        ct = aes_cbc(self.s, self.pt)
        response = self.bob.request_message(ct)
        print("response", response)


def challenge34():
    bob = Bob()
    mallory = Mallory(bob)
    alice = Alice(mallory)

    alice.request_pub_key()
    alice.request_message()


if __name__ == "__main__":
    challenge34()
