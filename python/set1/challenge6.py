import base64
from itertools import combinations
from collections import Counter
from pathlib import Path
from statistics import mean
from ..basics import hamming_distance, most_common, xor_cycle


def cheap_factor(x):
    """
    Cheap prime factors without repetition
    >>> cheap_factor(91)
    [7, 13]
    >>> cheap_factor(12)
    [2, 3]
    """
    ret = list()
    i = 2
    while i <= x:
        if x % i == 0:
            ret.append(i)
            while x % i == 0:
                x //= i
        i += 1
    return ret


def read_file():
    with open(Path(__file__).parent / 'resources/6.txt') as f:
        return bytes(base64.b64decode(f.read()))


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
            distances.extend(cheap_factor(key_size))
    return Counter(distances).most_common(1)[0][0]


def transpose(text, key_size):
    return [text[i::key_size] for i in range(key_size)]


def find_key(transposed_block):
    most_common_byte = most_common(transposed_block)
    return most_common_byte ^ ord(' ')


def detect_key():
    """
    >>> detect_key()
    'Terminator X: Bring the noise'
    """
    cipher = read_file()
    key = bytes(find_key(block) for block in transpose(cipher, 29))
    return key.decode()


def decrypt_text(key):
    cipher = read_file()
    k = bytes(key, 'UTF-8')
    plain = xor_cycle(cipher, k)
    return plain.decode()


if __name__ == '__main__':
    print(decrypt_text('Terminator X: Bring the noise'))
