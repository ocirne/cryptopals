from random import randint

from Crypto.Cipher import AES
import secrets
from base64 import b64decode
from cryptopals.basics import padding, chunks

BLOCK_SIZE = 16

key = secrets.token_bytes(BLOCK_SIZE)
random_prefix = secrets.token_bytes(randint(1, 100))

target_bytes = b64decode(
    """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
)


def encryption_oracle(attacker_controlled):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(padding(random_prefix + attacker_controlled + target_bytes))


def lookup(skip, inject_length, known_secret: bytes, known_content: bytes):
    for b in range(256):
        secret = encryption_oracle((b"\x00" * inject_length) + known_content + bytes([b]))
        if secret[skip : skip + BLOCK_SIZE] == known_secret[skip : skip + BLOCK_SIZE]:
            return b


def find_ignorable_part(ignore_blocks):
    blank_blocks = b"\x00" * ignore_blocks * BLOCK_SIZE
    secret = encryption_oracle(blank_blocks)
    last_chunk = None
    for length_prefix, chunk in chunks(secret, BLOCK_SIZE):
        if last_chunk == chunk:
            # Magic Seven
            return length_prefix + 7 * BLOCK_SIZE
        last_chunk = chunk


def encryption_detector(printing=False):
    """
    >>> encryption_detector().startswith('Rollin')
    True
    """
    skip = find_ignorable_part(3)

    known = bytearray()
    for inject_length in range(159, -100, -1):
        secret = encryption_oracle(b"\x00" * inject_length)
        b = lookup(skip, inject_length, secret, known)
        if b is None:
            return known.decode()
        if b != 0:
            known.append(b)
            if printing:
                print(chr(b), end="")


if __name__ == "__main__":
    encryption_detector(True)
