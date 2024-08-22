from itertools import combinations
from pathlib import Path

from cryptopals.basics import from_hex

debug = False

def detect_collision(line):
    a = line[::16]
    b = line[1::16]
    for i, j in combinations(range(10), 2):
        if a[i] == a[j] and b[i] == b[j]:
            if debug:
                print(i, j)
                print(line.hex()[1 * 32:2 * 32])
                print(line.hex()[5 * 32:6 * 32])
                print(line.hex()[7 * 32:8 * 32])
            return True


def detect_all_collisions(lines):
    """
    >>> detect_all_collisions(open(Path(__file__).parent / 'resources/8.txt').readlines())
    133
    """
    for line_no, line in enumerate(lines):
        cipher = from_hex(line)
        if detect_collision(cipher):
            print(line_no + 1)
