import base64
import secrets
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util import Counter


class Oracle25:
    def __init__(self):
        self.ecb_key = "YELLOW SUBMARINE"
        self.ctr_key = secrets.token_bytes(16)

    def decrypt_aes_ecb(self, ct: bytes):
        aes = AES.new(self.ecb_key)
        return aes.decrypt(ct)

    def aes_ctr(self):
        ctr = Counter.new(64, prefix="\x00" * 8, little_endian=True, initial_value=0)
        return AES.new(self.ctr_key, AES.MODE_CTR, counter=ctr)

    def encrypt_aes_ctr(self, pt: bytes):
        return self.aes_ctr().encrypt(pt)

    def decrypt_aes_ctr(self, ct: bytes):
        return self.aes_ctr().decrypt(ct)

    def prepare_cipher_text(self):
        with open(Path(__file__).parent / "resources/25.txt") as f:
            ct = base64.b64decode(f.read())
        pt = self.decrypt_aes_ecb(ct)
        return self.encrypt_aes_ctr(pt)

    def edit(self, ciphertext: bytes, offset: int, newtext: bytes):
        original = self.decrypt_aes_ctr(ciphertext)
        modified = original[:offset] + newtext + original[offset + len(newtext) :]
        assert len(original) == len(modified)
        return self.encrypt_aes_ctr(modified)


def recover(oracle: Oracle25, ct: bytes, index: int):
    for b in range(256):
        mod = oracle.edit(ct, index, bytes([b]))
        if mod == ct:
            return b


def challenge25():
    oracle = Oracle25()
    ct = oracle.prepare_cipher_text()
    for i in range(len(ct)):
        b = recover(oracle, ct, i)
        if b is not None:
            print(chr(b), end="")


if __name__ == "__main__":
    challenge25()
