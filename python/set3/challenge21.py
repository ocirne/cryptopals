
# https://de.wikipedia.org/wiki/Mersenne-Twister

class MersenneTwister:

    M = 1 << 31

    def __init__(self, seed):
        self.y = []
        x = seed
        self.y.append(x)
        for i in range(1, 624):
            x = (1812433253 * (x ^ (x >> 30)) + i) & 0xFFFF_FFFF
            self.y.append(x)

    def vector_generator(self, count):
        for _ in range(count):
            h = self.y[0] - (self.y[0] % self.M) + (self.y[1] % self.M)
            v = self.y[397] ^ (h >> 1) ^ ((h & 1) * 0x9908_B0DF)
            self.y.append(v)
            self.y.pop(0)
            yield v

    @staticmethod
    def tempering(p):
        e = p
        e ^= (e >> 11)
        e ^= (e << 7) & 0x9D2C_5680
        e ^= (e << 15) & 0xEFC6_0000
        return e ^ (e >> 18)

    def generate(self, count=1):
        for raw in self.vector_generator(count):
            yield self.tempering(raw)

    def next(self):
        raw = next(self.vector_generator(1))
        return self.tempering(raw)


def challenge21(seed):
    """
    test vectors see https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed

    >>> challenge21(1131464071)
    3521569528
    1101990581
    1076301704
    2948418163
    3792022443
    2697495705
    2002445460
    502890592
    3431775349
    1040222146
    3582980688
    """
    mt = MersenneTwister(seed)
    for pr in mt.generate(10):
        print(pr)
    print(mt.next())


if __name__ == '__main__':
    challenge21(1131464071)
