import random
import time

from basics import padding, strip_padding, xor, InvalidPaddingException
from challenge21 import MersenneTwister
import secrets


class MersenneTwisterStreamCipher:
    """
    >>> mtsc = MersenneTwisterStreamCipher(42)
    >>> pt = b'Ice Ice Baby :)'
    >>> assert pt == mtsc.decrypt(mtsc.encrypt(pt))
    """

    def __init__(self, seed):
        self.seed = seed
        self.mt = MersenneTwister(self.seed)

    def key_stream(self, length):
        return (k % 256 for k in self.mt.generate(length))

    def encrypt(self, pt: bytes):
        self.mt = MersenneTwister(self.seed)
        ppt = padding(pt, 4)
        return xor(ppt, self.key_stream(len(ppt)))

    def decrypt(self, ct: bytes):
        self.mt = MersenneTwister(self.seed)
        ppt = xor(ct, self.key_stream(len(ct)))
        try:
            return strip_padding(ppt)
        except InvalidPaddingException:
            return None


class Oracle24:

    def __init__(self):
        self.seed = secrets.randbits(16)
        self.mtsc = MersenneTwisterStreamCipher(self.seed)

    def encrypt_with_random_prefix(self, pt: bytes):
        prefix = secrets.token_bytes(secrets.randbelow(100))
        return self.mtsc.encrypt(prefix + pt)


oracle = Oracle24()


def recover_seed(ct: bytes, known: bytes):
    """
    >>> plain_text = secrets.token_bytes(16)
    >>> cipher_text = oracle.encrypt_with_random_prefix(plain_text)
    >>> recovered_seed = recover_seed(cipher_text, plain_text)
    >>> assert recovered_seed == oracle.seed
    """
    for seed in range(2**16):
        mt = MersenneTwisterStreamCipher(seed)
        cpt = mt.decrypt(ct)
        if cpt is not None and known in cpt:
            return seed


def generate_password_reset_token(seed: int):
    mt = MersenneTwisterStreamCipher(seed)
    return bytes(mt.key_stream(16))


def password_token_oracle():
    """
    Create a password token randomly in the past hour
    """
    past_time = int(time.time()) - random.randint(1, 3600)
    return generate_password_reset_token(past_time), past_time


def recover_password_token(pw_token: bytes):
    """
    >>> password_token, expected_timestamp = password_token_oracle()
    >>> recovered_timestamp = recover_password_token(password_token)
    >>> assert recovered_timestamp == expected_timestamp
    """
    current_time = int(time.time())
    for ut in range(current_time - 3700, current_time):
        if generate_password_reset_token(ut) == pw_token:
            return ut
