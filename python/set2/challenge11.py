from Crypto.Cipher import AES
import random
import secrets
from basics import padding


def encryption_oracle(content):
    before = secrets.token_bytes(random.randint(5, 10))
    after = secrets.token_bytes(random.randint(5, 10))
    padded1 = before + content + after
    padded2 = padding(padded1)
    key = secrets.token_bytes(16)
    mode = AES.MODE_ECB if bool(random.getrandbits(1)) else AES.MODE_CBC
    iv = secrets.token_bytes(16)
    aes = AES.new(key, mode, iv)
    return aes.encrypt(padded2)


for _ in range(8):
    secret = encryption_oracle(b"\x00" * 4)
    print('sec', list(secret))
