import random
import secrets

from challenge28 import SHA1


class Oracle29:

    def __init__(self):
        self.key = secrets.token_bytes(random.randrange(5, 10))

    def mac(self, message):
        sha1 = SHA1()
        return sha1.hexdigest(self.key + message)


# TODO Does not find a collision 100% of the time
def challenge29():
    oracle = Oracle29()
    original_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    additional_data = b';admin=true'
    provided_mac = oracle.mac(original_message)

    # guess
    for key_length in range(5, 10):
        glue_padding = SHA1().padding(b'#' * key_length + original_message)
        reference_mac = oracle.mac(original_message + glue_padding + additional_data)
        a, b, c, d, e = [int(provided_mac[i:i+8], 16) for i in range(0, 40, 8)]
        # 128: len(key) + len(message) < 10 + 77 = 87 -> 128 = len(preprocessed message)
        forged_mac = SHA1(a, b, c, d, e, 128).hexdigest(additional_data)
        if reference_mac == forged_mac:
            print('Found a collision!')


if __name__ == '__main__':
    challenge29()
