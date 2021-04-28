
# see https://en.wikipedia.org/wiki/Padding_oracle_attack

import random
import secrets

from Crypto.Cipher import AES

from basics import padding, strip_padding

BLOCK_SIZE = 16

class Oracle17:

    SECRETS = [
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]

    KEY = secrets.token_bytes(BLOCK_SIZE)
    IV = secrets.token_bytes(BLOCK_SIZE)

    def encrypt_c17(self):
        plain_text = random.choice(self.SECRETS)
        print('target', plain_text[:3*BLOCK_SIZE])
        aes = AES.new(self.KEY, AES.MODE_CBC, self.IV)
        return bytes(aes.encrypt(padding(plain_text))), self.IV

    def decrypt_c17(self, ciphertext: bytes, iv: bytes = None):
        if iv is None:
            iv = self.IV
    #    print(ciphertext, len(ciphertext), iv, len(iv))
        aes = AES.new(self.KEY, AES.MODE_CBC, iv)
        plain_text = aes.decrypt(ciphertext)
    #    print(plain_text, len(plain_text))
        return strip_padding(plain_text)


def chunk(text: bytes, nth: int):
    return text[nth*BLOCK_SIZE:(nth+1)*BLOCK_SIZE]


def modify_first(ciphertext: bytes, known: bytes, c: int):
    iv = bytearray(ciphertext)
    t = len(known) + 1
    for i in range(t-1):
        iv[15-i] = iv[15-i] ^ known[i] ^ t
    iv[16-t] = iv[16-t] ^ c ^ t
    return bytes(iv)


def decrypt_first(ciphertext: bytes, iv: bytes):
    known = bytearray()
    for _ in range(16):
        for c in range(256):
            candidate = modify_first(iv, known, c)
            if oracle.decrypt_c17(ciphertext[:BLOCK_SIZE], candidate) is not None:
                known.append(c)
                break
    return bytes(reversed(known))


def modify_second(ciphertext: bytes, known: bytes, block_end: int, c: int):
    ct = bytearray(ciphertext)
    t = len(known) + 1
    for i in range(t-1):
        ct[block_end - 1 - i] = ct[block_end - 1 - i] ^ known[i] ^ t
    ct[block_end - t] = ct[block_end - t] ^ c ^ t
    return bytes(ct)


def decrypt_second(ciphertext: bytes):
    known = bytearray()
    for _ in range(16):
        for c in range(256):
            candidate = modify_second(ciphertext, known, BLOCK_SIZE, c)
            if oracle.decrypt_c17(candidate[:2*BLOCK_SIZE]) is not None:
                known.append(c)
                break
    return bytes(reversed(known))

#todo gegencheck - vorletztes padding checken
#Andere chunks decoden
#ersten chunk mit IV entschlüsseln


def decrypt_third(ciphertext: bytes):
    known = bytearray()
    for _ in range(16):
        for c in range(256):
            candidate = modify_second(ciphertext, known, 2*BLOCK_SIZE, c)
            if oracle.decrypt_c17(candidate[:3*BLOCK_SIZE]) is not None:
                known.append(c)
                break
    return bytes(reversed(known))


oracle = Oracle17()

cookie, iv = oracle.encrypt_c17()

print('result', decrypt_first(cookie, iv) + decrypt_second(cookie) + decrypt_third(cookie))
