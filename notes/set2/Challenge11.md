from Crypto.Cipher import AES
import random
import secrets
from cryptopals.basics import padding


def encryption_oracle(content, mode_for_testing=None):
    prefix = secrets.token_bytes(random.randint(5, 10))
    suffix = secrets.token_bytes(random.randint(5, 10))
    padded = padding(prefix + content + suffix)
    key = secrets.token_bytes(16)
    if mode_for_testing is None:
        mode = AES.MODE_ECB if bool(random.getrandbits(1)) else AES.MODE_CBC
    else:
        mode = mode_for_testing
    iv = secrets.token_bytes(16)
    aes = AES.new(key, mode, iv)
    return aes.encrypt(padded)


def encryption_detector(mode_for_testing=None):
    """
    >>> encryption_detector(AES.MODE_ECB)
    'ECB'
    >>> encryption_detector(AES.MODE_CBC)
    'CBC'
    """
    # Why 48?: Make sure that block1 and block2 are all zero
    content = b"\x00" * 48
    secret = encryption_oracle(content, mode_for_testing)
    block1 = secret[16:32]
    block2 = secret[32:48]
    return "ECB" if block1 == block2 else "CBC"
