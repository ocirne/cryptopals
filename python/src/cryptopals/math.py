import math
import secrets


class MillerRabinTest:
    """
    from https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python:_Proved_correct_up_to_large_N

    >>> mrt = MillerRabinTest()
    >>> [p for p in range(2, 100) if mrt.is_prime(p)]
    [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    >>> mrt.is_prime(2**31-1)
    True
    """

    def __init__(self):
        self._known_primes = [2, 3]
        self._known_primes += [x for x in range(5, 1000, 2) if self.is_prime(x)]

    def _try_composite(self, a, d, n, s):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True

    def is_prime(self, n, _precision_for_huge_n=16):
        if n in self._known_primes:
            return True
        if any((n % p) == 0 for p in self._known_primes) or n in (0, 1):
            return False
        d, s = n - 1, 0
        while not d % 2:
            d, s = d >> 1, s + 1
        # Returns exact according to http://primes.utm.edu/prove/prove2_3.html
        if n < 1373653:
            return not any(self._try_composite(a, d, n, s) for a in (2, 3))
        if n < 25326001:
            return not any(self._try_composite(a, d, n, s) for a in (2, 3, 5))
        if n < 118670087467:
            if n == 3215031751:
                return False
            return not any(self._try_composite(a, d, n, s) for a in (2, 3, 5, 7))
        if n < 2152302898747:
            return not any(self._try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11))
        if n < 3474749660383:
            return not any(self._try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13))
        if n < 341550071728321:
            return not any(self._try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13, 17))
        return not any(self._try_composite(a, d, n, s) for a in self._known_primes[:_precision_for_huge_n])


def random_prime():
    mrt = MillerRabinTest()
    while True:
        p = secrets.randbits(128)
        if mrt.is_prime(p):
            return p


def egcd(a, b):
    """
    see https://de.wikipedia.org/wiki/Erweiterter_euklidischer_Algorithmus

    >>> egcd(18, 24)
    (6, -1, 1)
    >>> egcd(64, 32)
    (32, 0, 1)
    >>> egcd(35, 24)
    (1, 11, -16)
    """
    if b == 0:
        return a, 1, 0
    d, s, t = egcd(b, a % b)
    return d, t, s - (a // b) * t


def invmod(a, n):
    """
    >>> invmod(17, 3120)
    2753
    >>> invmod(1, 2)
    1
    >>> invmod(3, 6)
    >>> invmod(7, 87)
    25
    >>> invmod(25, 87)
    7
    >>> invmod(2, 91)
    46
    >>> invmod(13, 91)
    >>> invmod(19, 1212393831)
    701912218
    >>> invmod(31, 73714876143)
    45180085378
    >>> invmod(3, 73714876143)
    """
    d, s, t = egcd(a, n)
    if d != 1:
        return
    if s < 0:
        s += n
    return s % n


def crt(n: list, a: list):
    """
    adapted from https://rosettacode.org/wiki/Chinese_remainder_theorem#Python_3.6
    >>> crt([3, 5, 7], [2, 3, 2])
    23
    """
    total = 0
    prod = math.prod(n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        total += a_i * invmod(p, n_i) * p
    return total % prod
