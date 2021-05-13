import secrets

from Crypto.Cipher import AES

from cryptopals.basics import padding, xor

BLOCK_SIZE = 16


class Oracle26:
    def __init__(self):
        self.key = secrets.token_bytes(BLOCK_SIZE)
        self.iv = self.key

    def aes_cbc(self):
        return AES.new(self.key, AES.MODE_CBC, self.iv)

    def encrypt(self, pt: bytes):
        # ??
        #        try:
        #            plain_text = pt.decode("ascii")
        #        except UnicodeDecodeError as e:
        #            raise Exception(e, "pt")
        return bytes(self.aes_cbc().encrypt(padding(pt)))

    def decrypt(self, ct: bytes):
        return self.aes_cbc().decrypt(ct)


oracle = Oracle26()


def modify(ct: bytes):
    c1 = ct[:BLOCK_SIZE]
    return bytes(c1 + bytes([0] * BLOCK_SIZE) + c1)


def challenge27():
    """
    >>> challenge27()
    """
    p1 = secrets.token_bytes(BLOCK_SIZE)
    p2 = secrets.token_bytes(BLOCK_SIZE)
    p3 = secrets.token_bytes(BLOCK_SIZE)
    ciphertext = oracle.encrypt(p1 + p2 + p3)
    modified = modify(ciphertext)

    rpt = oracle.decrypt(modified)
    rpt1, rpt3 = rpt[:BLOCK_SIZE], rpt[2 * BLOCK_SIZE : 3 * BLOCK_SIZE]
    xor_p1_p3 = xor(rpt1, rpt3)

    assert xor_p1_p3 == oracle.key


if __name__ == "__main__":
    challenge27()
