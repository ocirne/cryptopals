from pathlib import Path
from ..basics import from_hex, most_common, xor_single, calc_score


def decrypt(secret):
    s = from_hex(secret)
    most_common_byte = most_common(s)
    key = most_common_byte ^ ord(' ')
    plain = xor_single(s, key)
    score = calc_score(plain)
    if score > 0.9:
        return plain.decode()


def challenge4(lines):
    """
    >>> challenge4(open(Path(__file__).parent / 'resources/4.txt').readlines())
    Now that the party is jumping
    """
    results = (decrypt(line) for line in lines)
    [print(p, end='') for p in results if p]
