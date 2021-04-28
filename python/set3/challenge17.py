
# see https://en.wikipedia.org/wiki/Padding_oracle_attack

import random
import secrets

from Crypto.Cipher import AES

from basics import padding, strip_padding, InvalidPaddingException

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

    def encrypt(self):
        plain_text = random.choice(self.SECRETS)
        print('target', plain_text)
        aes = AES.new(self.KEY, AES.MODE_CBC, self.IV)
        return bytes(aes.encrypt(padding(plain_text))), self.IV

    def decrypt(self, ciphertext: bytes, iv: bytes = None):
        if iv is None:
            iv = self.IV
    #    print(ciphertext, len(ciphertext), iv, len(iv))
        aes = AES.new(self.KEY, AES.MODE_CBC, iv)
        plain_text = aes.decrypt(ciphertext)
    #    print(plain_text, len(plain_text))
        return strip_padding(plain_text)


def modify(chunk: bytes, known: bytes, block_end: int, c: int):
    ct = bytearray(chunk)
    t = len(known) + 1
    for i in range(t-1):
        ct[block_end - 1 - i] = ct[block_end - 1 - i] ^ known[i] ^ t
    ct[block_end - t] = ct[block_end - t] ^ c ^ t
    return bytes(ct)

TODO modify entschlacken


def decrypt(ciphertext: bytes, nth: int, iv: bytes = None):
    known = bytearray()
    for _ in range(16):
        for c in range(256):
            try:
                if nth == 1:
                    modified_iv = modify(iv, known, BLOCK_SIZE, c)
                    oracle.decrypt(ciphertext[:BLOCK_SIZE], modified_iv)
                else:
                    modified_ciphertext = modify(ciphertext, known, (nth-1)*BLOCK_SIZE, c)
                    oracle.decrypt(modified_ciphertext[:nth*BLOCK_SIZE])
            except InvalidPaddingException:
                continue
            known.append(c)
            break
    return bytes(reversed(known))

#todo gegencheck - vorletztes padding checken


oracle = Oracle17()

cookie, iv = oracle.encrypt()

print('result', decrypt(cookie, 1, iv) + decrypt(cookie, 2) + decrypt(cookie, 3) + decrypt(cookie, 4) + decrypt(cookie, 5))
