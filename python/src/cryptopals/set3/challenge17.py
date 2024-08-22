# see https://en.wikipedia.org/wiki/Padding_oracle_attack

import base64
import random
import secrets

from Crypto.Cipher import AES

from cryptopals.basics import padding, strip_padding, InvalidPaddingException

BLOCK_SIZE = 16


class Oracle17:

    SECRETS = [
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ]

    KEY = secrets.token_bytes(BLOCK_SIZE)
    IV = secrets.token_bytes(BLOCK_SIZE)

    def __init__(self):
        self.plain_text = base64.b64decode(random.choice(self.SECRETS))

    def encrypt(self):
        aes = AES.new(self.KEY, AES.MODE_CBC, self.IV)  # NOSONAR
        return bytes(aes.encrypt(padding(self.plain_text))), self.IV  # NOSONAR

    def decrypt(self, ciphertext: bytes, iv: bytes = IV):
        aes = AES.new(self.KEY, AES.MODE_CBC, iv)
        plain_text = aes.decrypt(ciphertext)
        return strip_padding(plain_text)


# TODO refactor, only one bytes changes
def modify(chunk: bytes, known: bytes, block_end: int, c: int):
    ct = bytearray(chunk)
    t = len(known) + 1
    for i in range(t - 1):
        ct[block_end - 1 - i] = ct[block_end - 1 - i] ^ known[i] ^ t
    ct[block_end - t] = ct[block_end - t] ^ c ^ t
    return bytes(ct)


def decrypt(oracle: Oracle17, ciphertext: bytes, nth: int, iv: bytes = None):
    known = bytearray()
    for _ in range(BLOCK_SIZE):
        cc = []
        for c in range(256):
            try:
                if nth == 1:
                    modified_iv = modify(iv, known, BLOCK_SIZE, c)
                    oracle.decrypt(ciphertext[:BLOCK_SIZE], modified_iv)
                else:
                    modified_ciphertext = modify(ciphertext, known, (nth - 1) * BLOCK_SIZE, c)
                    oracle.decrypt(modified_ciphertext[: nth * BLOCK_SIZE])
            except InvalidPaddingException:
                continue
            cc.append(c)
        if len(cc) == 0:
            break
        else:
            # TODO Good enough for now: when multiple because of padding, the second is correct
            known.append(cc[-1])
    return bytes(reversed(known))


def challenge17():
    """
    >>> challenge17()
    True
    """
    oracle = Oracle17()
    cookie, iv = oracle.encrypt()
    plain_chunks = decrypt(oracle, cookie, 1, iv)
    nth = 2
    while nth * BLOCK_SIZE <= len(cookie):
        plain_chunks += decrypt(oracle, cookie, nth)
        nth += 1
    actual = strip_padding(plain_chunks)
    return actual == oracle.plain_text


if __name__ == "__main__":
    challenge17()
