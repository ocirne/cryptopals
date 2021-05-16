from cryptopals.set5.challenge39 import RSA, int_to_str
from cryptopals.math import invmod, crt

plaintext = "trivially"


def cube_root(n):
    cr = int(pow(n, 1 / 3))
    while cr ** 3 < n:
        cr += 1
    return cr


def rsa_encrypt(pt: str):
    rsa = RSA()
    _, n = rsa.public_key()
    c = rsa.encrypt(pt)
    return n, c


def challenge40():
    """
    >>> challenge40()
    'trivially'
    """
    ct_n = [rsa_encrypt(plaintext) for _ in range(3)]
    result = crt(ct_n)
    cr = cube_root(result)
    return int_to_str(cr)
