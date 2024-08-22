import base64
from pathlib import Path

from Crypto.Cipher import AES


def challenge10(filename, key, iv):
    """
    >>> plain = challenge10(Path(__file__).parent / 'resources/10.txt', 'YELLOW SUBMARINE', '\\x00' * 16)
    >>> plain.startswith(b"I'm back and I'm ringin' the bell")
    True
    """
    with open(filename) as f:
        content = f.read()
    ba = base64.b64decode(content)
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())  # NOSONAR
    return cipher.decrypt(ba)
