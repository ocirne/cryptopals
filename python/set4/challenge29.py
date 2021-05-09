import random
import secrets

from challenge28 import SHA1


class Oracle29:

    def __init__(self):
        self.key = secrets.token_bytes(random.randint(10, 100))
        self.original_message = "Ice Ice Baby"

    def mac(self, message):
        sha1 = SHA1()
        return sha1.digest(self.key + message)


def challenge29():
    oracle = Oracle29()
    original_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    provided_mac = oracle.mac(original_message)

    orig_bit_length = len(original_message) * 8
    glue_padding = SHA1().padding(oracle.key + original_message)

    additional_data = b";admin=true"
    original_mac = oracle.mac(original_message + glue_padding + additional_data)

    a, b, c, d, e = [int(provided_mac[i:i+8], 16) for i in range(0, 40, 8)]
    forge_sha1 = SHA1(a, b, c, d, e, 128)
    forge_mac = forge_sha1.digest(additional_data)

    assert forge_mac == original_mac


if __name__ == '__main__':
    challenge29()
