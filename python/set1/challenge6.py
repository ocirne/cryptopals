import base64
from itertools import combinations
from collections import defaultdict, Counter
from operator import itemgetter
from pathlib import Path
from statistics import mean
from ..basics import calc_score, xor_cycle, xor_single, pretty_format


def hamming_distance(s1: bytearray, s2: bytearray):
    """
    >>> t1 = bytearray('this is a test', 'UTF-8')
    >>> t2 = bytearray('wokka wokka!!!', 'UTF-8')
    >>> hamming_distance(t1, t2)
    37
    """
    return sum(bin(x ^ y).count('1') for x, y in zip(s1, s2))


def factor(x):
    """
    Cheap prime factors without repitition
    >>> factor(91)
    [7, 13]
    >>> factor(12)
    [2, 3]
    """
    ret = defaultdict(lambda: 0)
    while x > 1:
        for i in range(2, x + 1):
            while x % i == 0:
                x = x // i
                ret[i] += 1
    return list(ret.keys())


def read_file():
    with open(Path(__file__).parent / 'resources/6.txt', 'r') as f:
        return bytearray(base64.b64decode(f.read()))


def get_common_distance(count_blocks=4):
    """
    >>> get_common_distance(4)
    29
    """
    cipher = read_file()
    distances = []
    for key_size in range(2, 100):
        blocks = (cipher[i * key_size:(i + 1) * key_size] for i in range(count_blocks))
        normalized_mean_distance = \
            mean(hamming_distance(block1, block2) / key_size for block1, block2 in combinations(blocks, 2))
        if normalized_mean_distance < 3:
            distances.extend(factor(key_size))
    return Counter(distances).most_common(1)[0][0]


def transpose(text, key_size):
    return [text[i::key_size] for i in range(key_size)]


def find_key(transposed_block):
    key, score = max(((key, calc_score(xor_single(transposed_block, key))) for key in range(256)), key=itemgetter(1))
    return key


def find_keys():
    """
    >>> find_keys()
    'Terminator X: Bring the noise'
    """
    cipher = read_file()
    return ''.join(chr(find_key(block)) for block in transpose(cipher, 29))


def decrypt_text(key):
    cipher = read_file()
    k = bytearray(key, 'UTF-8')
    plain = xor_cycle(cipher, k)
    return pretty_format(plain)


if __name__ == '__main__':
    print(decrypt_text('Terminator X: Bring the noise'))
