from pathlib import Path
from ..basics import from_hex, most_common, pretty_format, xor_single


def is_plausible_plain(plain: bytearray):
    total_ascii = total_blank = 0
    for x in plain:
        # 97: 'a', 122: 'z'
        if 97 <= x <= 122:
            total_ascii += 1
        # 32: space
        if 32 == x:
            total_blank += 1
    return total_ascii >= 20 and total_blank >= 5


def decrypt(secret):
    s = from_hex(secret)
    most_common_byte = most_common(s)
    key = most_common_byte ^ ord(' ')
    plain = xor_single(s, key)
    if is_plausible_plain(plain):
        return pretty_format(plain)


def challenge4(lines):
    """
    >>> challenge4(open(Path(__file__).parent / 'resources/4.txt', 'r').readlines())
    Now that the party is jumping
    """
    results = (decrypt(line) for line in lines)
    [print(p, end='') for p in results if p]
