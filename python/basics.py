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


def pretty_format(ba: bytearray):
    return "".join(chr(b) for b in ba)
