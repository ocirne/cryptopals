import random
import time

import requests

URL = "http://localhost:9000/test"


def random_padding(length):
    return "".join(random.choice("0123456789abcdef") for _ in range(length))


def timed_request(signature_prefix: str, guess: str):
    padding = random_padding(39 - len(signature_prefix))
    signature = "%s%s%s" % (signature_prefix, guess, padding)
    response = requests.get(url=URL, params={"file": "foo", "signature": signature})
    return response, signature


def is_definitive(response_times: list):
    srt = sorted(response_times, reverse=True)
    # Challenge 31:
    #    return srt[0] - srt[1] > srt[1] - srt[2]
    # Challenge 32:
    return srt[0] - srt[1] > srt[1] - srt[6]


def guess_next(known: str):
    """
    Alternative:
    - Base time mit falschen Request berechnen
    - Ersten Wert nehmen, wo die response.elapsed um mehr als 25 ms größer ist
    """
    # known false request
    response_ms_max = 0
    response_times = []
    result = None
    for i in range(16):
        c = f"{i:x}"
        response, signature = timed_request(known, c)
        if response.ok:
            return True, True, c, i + 1
        response_ms = response.elapsed.total_seconds()
        # use the value with the longest response
        response_times.append(response_ms)
        if response_ms_max < response_ms:
            response_ms_max = response_ms
            result = c
    return False, is_definitive(response_times), result, 17


def challenge31():
    known_signature = ""
    total_requests = 0
    tic = time.perf_counter()
    while True:
        found, definitive, nibble, count_requests = guess_next(known_signature)
        if definitive:
            known_signature += nibble
            print(known_signature)
            if found:
                toc = time.perf_counter()
                print("found", known_signature, "in", toc - tic, "seconds with", total_requests, "requests")
                break
        else:
            # no definitive result, try again
            print("try again")
        total_requests += count_requests


if __name__ == "__main__":
    challenge31()
