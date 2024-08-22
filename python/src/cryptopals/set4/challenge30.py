import random
import secrets

from cryptopals.digests import MD5, MASK


class Oracle30:
    def __init__(self):
        self.key = secrets.token_bytes(random.randrange(5, 10))  # NOSONAR
        self.original_message = "Ice Ice Baby"

    def mac(self, message):
        md5 = MD5()
        return md5.hexdigest(self.key + message)


def find_init_values(provided_mac):
    raw = int(provided_mac, 16).to_bytes(16, byteorder="big")
    digest = int.from_bytes(raw, byteorder="little")
    a = digest & MASK
    b = (digest >> 32) & MASK
    c = (digest >> 64) & MASK
    d = (digest >> 96) & MASK
    return a, b, c, d


# this seems to work 100% of the time
def challenge30():
    oracle = Oracle30()
    original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    additional_data = b";admin=true"
    provided_mac = oracle.mac(original_message)

    # guess
    for key_length in range(5, 10):
        glue_padding = MD5().padding(b"#" * key_length + original_message)
        reference_mac = oracle.mac(original_message + glue_padding + additional_data)
        a, b, c, d = find_init_values(provided_mac)
        # 128: len(key) + len(message) < 10 + 77 = 87 -> 128 = len(preprocessed message)
        forged_mac = MD5(a, b, c, d, 128).hexdigest(additional_data)
        if reference_mac == forged_mac:
            print("Found a collision!")


if __name__ == "__main__":
    challenge30()
