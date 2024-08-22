import random
import secrets
from typing import Union

from Crypto.Cipher import AES

from cryptopals.basics import padding, strip_padding
from cryptopals.digests import SHA1


def aes_cbc_encrypt(priv_key: int, pt: bytes) -> bytes:
    s = priv_key.to_bytes(8, byteorder="big")
    key = SHA1().digest(s)[:16]
    iv = secrets.token_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, iv)  # NOSONAR
    ct = aes.encrypt(padding(pt))
    return ct + iv


def aes_cbc_decrypt(priv_key: int, ct: bytes, iv: bytes) -> bytes:
    s = priv_key.to_bytes(8, byteorder="big")
    key = SHA1().digest(s)[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)  # NOSONAR
    pt = aes.decrypt(ct)
    return strip_padding(pt)


class Bob:
    def request_pub_key(self, p, g, A):  # NOSONAR
        """
        B -> M
        Send "B"
        """
        b = random.randrange(0, p)
        B = pow(g, b, p)
        self.s = pow(A, b, p)
        return B

    def request_message(self, ciphertext_a: bytes) -> bytes:
        """
        B->M
        Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
        """
        return aes_cbc_encrypt(self.s, ciphertext_a)


class Mallory:
    def __init__(self, bob: Bob):
        self.bob = bob

    def request_pub_key(self, p, g, A):  # NOSONAR
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

        Unknown: s
        s = pow(B, a, p) -> s = pow(p, a, p) = 0
        """
        ct_b = self.bob.request_message(ciphertext_a)
        ct, iv = ciphertext_a[:-16], ciphertext_a[-16:]
        recovered_pt = aes_cbc_decrypt(0, ct, iv)
        print("recovered pt:", recovered_pt)
        return ct_b


class Alice:
    def __init__(self, bob: Bob | Mallory):
        self.bob = bob
        self.pt = b"Ice Ice Baby"

    def request_pub_key(self):
        """
        A -> M
        Send "p", "g", "A"
        """
        # should be a prime, good enough
        p = random.randint(0, 2 ** 31)
        g = random.randint(0, 100)
        a = random.randrange(0, p)
        A = pow(g, a, p)
        B = self.bob.request_pub_key(p, g, A)
        self.s = pow(B, a, p)

    def request_message(self):
        """
        A -> M
        Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        """
        ct = aes_cbc_encrypt(self.s, self.pt)
        self.bob.request_message(ct)


def challenge34():
    """
    >>> challenge34()
    recovered pt: b'Ice Ice Baby'
    """
    bob = Bob()
    mallory = Mallory(bob)
    alice = Alice(mallory)

    alice.request_pub_key()
    alice.request_message()


if __name__ == "__main__":
    challenge34()
