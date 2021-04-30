
# https://de.wikipedia.org/wiki/Mersenne-Twister

class MersenneTwister:

    N = 624
    f = 1812433253
    M = 1 << 31

    def __init__(self, seed):
        self.y = []
        x = seed
        self.y.append(x)
        for i in range(1, self.N):
            x = (self.f * (x ^ (x >> 30)) + i) & 0xFFFFFFFF
            self.y.append(x)
        self.i = self.N

    def base_generator(self, count):
        for _ in range(count):
            h = self.y[self.i-self.N] - (self.y[self.i-self.N] % self.M) + (self.y[self.i-self.N+1] % self.M)
            v = self.y[self.i-227] ^ (h >> 1) ^ ((h & 1) * 0x9908B0DF)
            self.y.append(v)
            yield self.y[self.i]
            self.i += 1

    @staticmethod
    def tempering(p):
        e = p
        e ^= (e >> 11)
        e ^= (e << 7) & 0x9D2C5680
        e ^= (e << 15) & 0xEFC60000
        return e ^ (e >> 18)

    def next(self, count=1):
        for n in self.base_generator(count):
            yield self.tempering(n)


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
    """
    mt = MersenneTwister(seed)
    for pr in mt.next(10):
        print(pr)


if __name__ == '__main__':
    challenge21(0)
