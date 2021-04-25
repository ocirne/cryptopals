import itertools
from collections import Counter
from typing import Iterable


def from_hex(hex_string: str):
    if len(hex_string) % 2 != 0:
        return bytearray.fromhex(hex_string[:-1])
    return bytearray.fromhex(hex_string)


def xor(t: bytearray, s: bytearray or Iterable):
    return bytearray(a ^ b for a, b in zip(t, s))


def xor_single(t: bytearray, key):
    return bytearray(c ^ key for c in t)


def xor_cycle(t: bytearray, key: bytearray):
    return xor(t, itertools.cycle(key))


def most_common(ba: bytearray):
    return Counter(ba).most_common(1)[0][0]


def calc_score(plain: bytearray):
    # 'A' - 'Z'
    total_upper = sum(1 for c in plain if 65 <= c <= 90)
    # 'a' - 'z'
    total_lower = sum(1 for c in plain if 97 <= c <= 122)
    # ' '
    total_blank = sum(1 for s in plain if s == 32)
    return (total_upper + total_lower + total_blank) / len(plain)


def hamming_distance(s1: bytearray, s2: bytearray):
    """
    >>> t1 = bytearray('this is a test', 'UTF-8')
    >>> t2 = bytearray('wokka wokka!!!', 'UTF-8')
    >>> hamming_distance(t1, t2)
    37
    """
    return sum(bin(x ^ y).count('1') for x, y in zip(s1, s2))


def padding(ba: bytes, block_size=16):
    pad_length = block_size - len(ba) % block_size
    if pad_length == 0:
        pad_length = block_size
    pad_byte = chr(pad_length)
    return ba + bytes(pad_byte * pad_length, 'UTF-8')


def strip_padding(plaintext: bytes):
    c = plaintext[-1]
    i = c
    t, s = plaintext[:-i], plaintext[-i:]
    if s == bytes([c] * len(s)) and t[-1] != c:
        return t
    return None
