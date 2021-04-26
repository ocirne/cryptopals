
# see https://en.wikipedia.org/wiki/Padding_oracle_attack

import random
import secrets

from Crypto.Cipher import AES

from basics import padding, strip_padding

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

BLOCK_SIZE = 16

KEY = secrets.token_bytes(BLOCK_SIZE)
IV = secrets.token_bytes(BLOCK_SIZE)


def encrypt_c17():
    plain_text = random.choice(SECRETS)
    print('target', plain_text[16:32])
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    return bytes(aes.encrypt(padding(plain_text)))


def decrypt_c17(ciphertext: bytes):
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    plain_text = aes.decrypt(ciphertext)
    return strip_padding(plain_text)


def modify(ciphertext: bytes, known: bytes, c: int):
    ct = bytearray(ciphertext)
    t = len(known) + 1
    for i in range(t-1):
        ct[15-i] = ct[15-i] ^ known[i] ^ t
    ct[16-t] = ct[16-t] ^ c ^ t
    return bytes(ct)

todo gegencheck - vorlettzes padding checken
Andere chunks decoden

def decrypt(ciphertext: bytes):
    known = bytearray()
    for _ in range(16):
        for c in range(256):
            candidate = modify(ciphertext, known, c)
            if decrypt_c17(candidate[:32]) is not None:
                known.append(c)
                break
    return bytes(reversed(known))


cookie = encrypt_c17()

print('result', decrypt(cookie))
