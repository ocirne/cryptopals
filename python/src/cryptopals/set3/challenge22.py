import random
import time

from challenge21 import MersenneTwister

ONE_HOUR = 60 * 60


def wait_random():
    wait_seconds = random.randint(40, 1000)
    time.sleep(wait_seconds)


def prepare_challenge22():
    wait_random()
    unix_timestamp = int(time.time())
    print("hint %s" % unix_timestamp)
    mt = MersenneTwister(unix_timestamp)
    wait_random()
    end_timestamp = int(time.time())
    return unix_timestamp, mt.next(), end_timestamp


def challenge22(prn, now):
    """
    Brute force is good enough :)

    >>> challenge22(prn=3339454654, now=1619796899)
    1619795688
    """
    for ut in range(now - ONE_HOUR, now):
        if MersenneTwister(ut).next() == prn:
            return ut


if __name__ == "__main__":
    expected, prn, now = prepare_challenge22()
    tic = time.perf_counter()
    actual = challenge22(prn, now)
    toc = time.perf_counter()
    print(f"recovered {actual} in {toc - tic:0.2f} seconds")
