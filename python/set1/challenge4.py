from collections import Counter
from pathlib import Path


def fixed_xor_single_byte(secret, key):
    s_ba = bytearray.fromhex(secret)
    return bytearray(c ^ key for c in s_ba)


def pretty_print(ba):
    return "".join(chr(b) for b in ba)


def from_hex(hex_string):
    if len(hex_string) % 2 != 0:
        return bytearray.fromhex(hex_string[:-1])
    return bytearray.fromhex(hex_string)


def check_plain(plain: bytearray):
    total_ascii = total_blank = 0
    for x in plain:
        # 97: 'a', 122: 'z'
        if 97 <= x <= 122:
            total_ascii += 1
        # 32: space
        if 32 == x:
            total_blank += 1
    return total_ascii >= 20 and total_blank >= 5


def with_challenge3(secret):
    counts = Counter(from_hex(secret))
    most_common_byte = counts.most_common(1)[0][0]
    key = most_common_byte ^ ord(' ')
    plain_ba = fixed_xor_single_byte(secret, key)
    if check_plain(plain_ba):
        print(pretty_print(plain_ba), end='')


def challenge4(lines):
    """
    >>> challenge4(open(Path(__file__).parent / 'resources/4.txt', 'r').readlines())
    Now that the party is jumping
    """
    for line in lines:
        with_challenge3(line)
