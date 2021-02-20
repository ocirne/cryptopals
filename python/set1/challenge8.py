from itertools import combinations
from pathlib import Path

from ..basics import from_hex


def detect_collision(line):
    detected = False
    a0 = line[::16]
    a1 = line[1::16]
    for i, j in combinations(range(10), 2):
        if a0[i] == a0[j] and a1[i] == a1[j]:
            # print(i, j)
            # print(line.hex()[1 * 32:2 * 32])
            # print(line.hex()[5 * 32:6 * 32])
            # print(line.hex()[7 * 32:8 * 32])
            detected = True
    return detected


def detect_all_collisions(lines):
    """
    >>> detect_all_collisions(open(Path(__file__).parent / 'resources/8.txt', 'r').readlines())
    133
    """
    for line_no, line in enumerate(lines):
        cipher = from_hex(line)
        if detect_collision(cipher):
            print(line_no + 1)
