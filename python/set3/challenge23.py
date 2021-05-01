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
    ...


if __name__ == '__main__':
    challenge23()
