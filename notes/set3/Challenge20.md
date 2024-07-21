import base64
import secrets
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter as AesCounter

from cryptopals.basics import xor, calc_score, xor_single


class Oracle20:
    KEY = secrets.token_bytes(16)

    def aes_ctr(self):
        ctr = AesCounter.new(64, prefix="\x00" * 8, little_endian=True, initial_value=0)
        return AES.new(self.KEY, AES.MODE_CTR, counter=ctr)

    def encrypt(self, plain_text: bytes):
        return self.aes_ctr().encrypt(plain_text)

    def encrypt_lines(self, lines):
        return [self.encrypt(base64.b64decode(line)) for line in lines]


def columns(ciphertexts: [bytes]):
    size = min(len(line) for line in ciphertexts)
    for col_no in range(size):
        yield [line[col_no] for line in ciphertexts]


def find_key(column):
    return max(((calc_score(xor_single(column, k)), k) for k in range(256)))[1]


def challenge20():
    oracle = Oracle20()
    f = open(Path(__file__).parent / "resources/20.txt")
    cipher_texts = oracle.encrypt_lines(f)
    key = bytes(find_key(column) for column in columns(cipher_texts))
    for line in cipher_texts:
        print(xor(key, line))


if __name__ == "__main__":
    challenge20()
