import random
import time

import requests

URL = 'http://localhost:9000/test'


def random_padding(length):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))


def timed_request(signature_prefix: str, guess: str):
    padding = random_padding(39 - len(signature_prefix))
    signature = '%s%s%s' % (signature_prefix, guess, padding)
    response = requests.get(url=URL, params={'file': 'foo', 'signature': signature})
    return response, signature


def guess_next(known: str):
    # known false request
    response, _ = timed_request(known, 'x')
    base_ms = response.elapsed.microseconds
    response_ms_max = 0
    result = None
    for i in range(16):
        c = f'{i:x}'
        response, signature = timed_request(known, c)
        if response.ok:
            return True, c, i + 1
        response_ms = response.elapsed.microseconds
        # shortcut
#        if response_ms - base_ms > 40_000:
#            return False, c, i + 1
        # fallback, use the value with the longest response
        if response_ms_max < response_ms:
            response_ms_max = response_ms
            result = c
    return False, result, 17


def challenge31():
    known_signature = ''
    total_requests = 0
    tic = time.perf_counter()
    while True:
        found, nibble, count_requests = guess_next(known_signature)
        known_signature += nibble
        print(known_signature)
        total_requests += count_requests
        if found:
            toc = time.perf_counter()
            print('found', known_signature, 'in', toc - tic, 'seconds with', total_requests, 'requests')
            break


if __name__ == '__main__':
    challenge31()
