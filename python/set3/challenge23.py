import random

from challenge21 import MersenneTwister


def untempering(p):
    """
    see https://occasionallycogent.com/inverting_the_mersenne_temper/index.html

    >>> mt = MersenneTwister(0)
    >>> mt.tempering(42)
    168040107
    >>> untempering(168040107)
    42
    """
    e = p ^ (p >> 18)
    e ^= (e << 15) & 0xEFC6_0000
    e ^= (e << 7) & 0x0000_1680
    e ^= (e << 7) & 0x000C_4000
    e ^= (e << 7) & 0x0D20_0000
    e ^= (e << 7) & 0x9000_0000
    e ^= (e >> 11) & 0xFFC0_0000
    e ^= (e >> 11) & 0x003F_F800
    e ^= (e >> 11) & 0x0000_07FF
    return e


def challenge23():
    """
    >>> orig, copy = challenge23()
    >>> assert all(o == c for o, c in zip(orig.generate(624), copy.generate(624)))
    """
    seed = random.randint(1, 2**31)
    orig_mt = MersenneTwister(seed)
    copy_mt = MersenneTwister(0)
    for index, p in enumerate(orig_mt.generate(624)):
        copy_mt.y[index] = untempering(p)
    return orig_mt, copy_mt


if __name__ == '__main__':
    orig, copy = challenge23()
    assert all(o == c for o, c in zip(orig.generate(3*624), copy.generate(3*624)))
