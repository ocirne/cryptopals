import random
import secrets
from abc import abstractmethod, ABC
from typing import Union

from Crypto.Cipher import AES

from cryptopals.basics import padding, strip_padding, InvalidPaddingException
from cryptopals.digests import SHA1


def aes_cbc_encrypt(priv_key: int, pt: bytes) -> bytes:
    s = priv_key.to_bytes(8, byteorder="big")
    key = SHA1().digest(s)[:16]
    iv = secrets.token_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    ct = aes.encrypt(padding(pt))
    return ct + iv


def aes_cbc_decrypt(priv_key: int, ct: bytes, iv: bytes) -> bytes:
    s = priv_key.to_bytes(8, byteorder="big")
    key = SHA1().digest(s)[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    pt = aes.decrypt(ct)
    return strip_padding(pt)


class Bob:
    def request_groups(self, p, g):
        self.p = p
        self.g = g
        return "ACK"

    def request_pub_key(self, A):
        b = random.randrange(0, self.p)
        B = pow(self.g, b, self.p)
        self.s = pow(A, b, self.p)
        return B

    def request_message(self, ciphertext_a: bytes) -> bytes:
        return aes_cbc_encrypt(self.s, ciphertext_a)


class AbstractMallory(ABC):
    def __init__(self, bob: Bob):
        self.bob = bob

    @abstractmethod
    def request_groups(self, p, g):
        ...

    def request_pub_key(self, A):
        return self.bob.request_pub_key(A)

    def request_message(self, ciphertext_a: bytes) -> bytes:
        ct_b = self.bob.request_message(ciphertext_a)
        ct, iv = ciphertext_a[:-16], ciphertext_a[-16:]
        self.easy_decrypt(ct, iv)
        return ct_b

    @abstractmethod
    def easy_decrypt(self, ct: bytes, iv: bytes):
        ...


class Mallory1(AbstractMallory):
    """ g = 1 """

    def request_groups(self, p, g):
        self.bob.request_groups(p, 1)

    def easy_decrypt(self, ct: bytes, iv: bytes):
        """
        s = B**a = (g**b)**a = (1**b)**a = 1**a = 1  mod p
        """
        recovered_pt = aes_cbc_decrypt(1, ct, iv)
        print("recovered pt (g = 1):", recovered_pt)


class Mallory2(AbstractMallory):
    """ g = p """

    def request_groups(self, p, g):
        self.bob.request_groups(p, p)

    def easy_decrypt(self, ct: bytes, iv: bytes) -> bytes:
        """
        s = B**a = (g**b)**a = (p**b)**a = 0  mod p
        """
        recovered_pt = aes_cbc_decrypt(0, ct, iv)
        print("recovered pt (g = p):", recovered_pt)


class Mallory3(AbstractMallory):
    """ g = p - 1 """

    def request_groups(self, p, g):
        self.p = p
        self.bob.request_groups(p, p - 1)

    def easy_decrypt(self, ct: bytes, iv: bytes):
        """
        s = B**a = (g**b)**a = ((p-1)**b)**a = ((-1)**b)**a = {p-1, 1}  mod p
        """
        try:
            recovered_pt = aes_cbc_decrypt(1, ct, iv)
        except InvalidPaddingException:
            recovered_pt = aes_cbc_decrypt(self.p - 1, ct, iv)
        print("recovered pt (g = p - 1):", recovered_pt)


class Alice:
    def __init__(self, bob: Union[Bob, Mallory1, Mallory2, Mallory3]):
        self.bob = bob
        self.pt = b"Ice Ice Baby"

    def request_groups(self):
        self.p = random.randint(0, 2 ** 31)
        self.g = random.randint(0, 100)
        self.a = random.randrange(0, self.p)
        self.bob.request_groups(self.p, self.g)

    def request_pub_key(self):
        """
        A -> M
        Send "p", "g", "A"
        """
        A = pow(self.g, self.a, self.p)
        B = self.bob.request_pub_key(A)
        self.s = pow(B, self.a, self.p)

    def request_message(self):
        """
        A -> M
        Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        """
        ct = aes_cbc_encrypt(self.s, self.pt)
        self.bob.request_message(ct)


def challenge34(mallory_class):
    """
    >>> challenge34(Mallory1)
    recovered pt (g = 1): b'Ice Ice Baby'
    >>> challenge34(Mallory2)
    recovered pt (g = p): b'Ice Ice Baby'
    >>> challenge34(Mallory3)
    recovered pt (g = p - 1): b'Ice Ice Baby'
    """
    bob = Bob()
    mallory = mallory_class(bob)
    alice = Alice(mallory)

    alice.request_groups()
    alice.request_pub_key()
    alice.request_message()


if __name__ == "__main__":
    challenge34(Mallory2)
    challenge34(Mallory3)
