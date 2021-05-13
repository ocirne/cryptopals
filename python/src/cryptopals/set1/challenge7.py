import base64
from pathlib import Path
from Crypto.Cipher import AES

KEY = "YELLOW SUBMARINE"


def decrypt(enc, key):
    cipher = AES.new(key)
    return cipher.decrypt(enc)


if __name__ == "__main__":
    with open(Path(__file__).parent / "resources/7.txt") as f:
        secret = base64.b64decode(f.read())
    plain = decrypt(secret, KEY)
    print(plain.decode())
