from Crypto.Cipher import AES
import secrets
from base64 import b64decode
from cryptopals.basics import padding

key = secrets.token_bytes(16)

unknown_string = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""


def encryption_oracle(your_string):
    padded = padding(your_string + b64decode(unknown_string))
    aes = AES.new(key, AES.MODE_ECB)  # NOSONAR
    return aes.encrypt(padded)


def discover_next_hop(old_bs):
    i = 1
    while True:
        new_bs = len(encryption_oracle(b"\x00" * i))
        if old_bs < new_bs:
            return new_bs
        i += 1


def discover_block_size():
    """
    >>> discover_block_size()
    16
    """
    first_bs = len(encryption_oracle(b""))
    hop1 = discover_next_hop(first_bs)
    hop2 = discover_next_hop(hop1 + 1)
    return hop2 - hop1


def discover_mode():
    """
    >>> discover_mode()
    'ECB'
    """
    secret = encryption_oracle(b"\x00" * 48)
    return "ECB" if secret[16:32] == secret[32:48] else "CBC"


def lookup(i, known_secret: bytes, known_content: bytes):
    for b in range(256):
        secret = encryption_oracle(b"\x00" * i + known_content + bytes([b]))
        if secret[:160] == known_secret:
            return b


def encryption_detector(printing=False):
    """
    >>> encryption_detector().startswith('Rollin')
    True
    """
    known = bytearray()
    for i in range(159, -1, -1):
        secret = encryption_oracle(b"\x00" * i)
        b = lookup(i, secret[:160], known)
        if not b:
            return known.decode()
        known.append(b)
        if printing:
            print(chr(b), end="")


if __name__ == "__main__":
    encryption_detector(True)
