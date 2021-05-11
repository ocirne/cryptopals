import secrets
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from basics import xor, from_hex
from challenge28 import SHA1
from challenge30 import MD5


def hmac(key: bytes, message: bytes, mac, block_size):
    """
    see https://en.wikipedia.org/wiki/HMAC
    see https://datatracker.ietf.org/doc/html/rfc2202
    """
    # Keys longer than blockSize are shortened by hashing them
    if len(key) > block_size:
        key = mac.digest(key)  # key is outputSize bytes long

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if len(key) < block_size:
        key += b'\x00' * (block_size - len(key))  # Pad key with zeros to make it blockSize bytes long

    o_key_pad = xor(key, b'\x5c' * block_size)   # Outer padded key
    i_key_pad = xor(key, b'\x36' * block_size)   # Inner padded key

    return mac.hexdigest(o_key_pad + mac.digest(i_key_pad + message))


def hmac_sha1(key: bytes, message: bytes):
    """
    >>> hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog")
    'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9'
    >>> hmac_sha1(from_hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), b"Hi There")
    'b617318655057264e28bc0b6fb378c8ef146be00'
    >>> hmac_sha1(b"Jefe", b"what do ya want for nothing?")
    'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'
    >>> hmac_sha1(from_hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), b'\\xdd' * 50)
    '125d7342b9ac11cd91a39af48aa17b4f63f175d3'
    >>> hmac_sha1(from_hex('0102030405060708090a0b0c0d0e0f10111213141516171819'), b'\\xcd' * 50)
    '4c9007f4026250c6bc8414f9bf50c86c2d7235da'
    >>> hmac_sha1(from_hex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'), b"Test With Truncation")
    '4c1a03424b55e07fe7f27be1d58bb9324a9a5a04'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key - Hash Key First")
    'aa4ae5e15272d00e95705637ce8a3b55ed402112'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")
    'e8e99d0f45237d786d6bbaa7965c7808bbff1a91'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key - Hash Key First")
    'aa4ae5e15272d00e95705637ce8a3b55ed402112'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")
    'e8e99d0f45237d786d6bbaa7965c7808bbff1a91'
    """
    return hmac(key, message, SHA1(), block_size=64)


def hmac_md5(key: bytes, message: bytes):
    """
    >>> hmac_md5(b"key", b"The quick brown fox jumps over the lazy dog")
    '80070713463e7749b90c2dc24911e275'
    >>> hmac_md5(from_hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), b"Hi There")
    '9294727a3638bb1c13f48ef8158bfc9d'
    >>> hmac_md5(b"Jefe", b"what do ya want for nothing?")
    '750c783e6ab0b503eaa86e310a5db738'
    >>> hmac_md5(from_hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), b'\\xdd' * 50)
    '56be34521d144c88dbb8c733f0e8b3f6'
    >>> hmac_md5(from_hex('0102030405060708090a0b0c0d0e0f10111213141516171819'), b'\\xcd' * 50)
    '697eaf0aca3a3aea3a75164746ffaa79'
    >>> hmac_md5(from_hex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'), b"Test With Truncation")
    '56461ef2342edc00f9bab995690efd4c'
    >>> hmac_md5(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key - Hash Key First")
    '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd'
    >>> hmac_md5(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")
    '6f630fad67cda0ee1fb1f562db3aa53e'
    """
    return hmac(key, message, MD5(), block_size=64)


SECRET_KEY = secrets.token_bytes(16)


def insecure_compare(s: str, r: str):
    if len(s) != len(r):
        return False
    for c, d in zip(s, r):
        if c != d:
            return False
        time.sleep(0.05)
    return True


class TinyServer(BaseHTTPRequestHandler):
    """
    e.g. http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
    """

    # noinspection PyPep8Naming
    def do_GET(self):
        query = urlparse(self.path).query

        query_components = parse_qs(query)
        file_param = query_components["file"][0]
        signature_param = query_components["signature"][0]
        # Use filename as file for simplicity
        hmac = hmac_sha1(SECRET_KEY, file_param.encode())
        print('hint:', hmac)
        if insecure_compare(hmac, signature_param):
            self.send_response(200)
        else:
            self.send_response(500)
        self.end_headers()


if __name__ == '__main__':
    httpd = HTTPServer(('localhost', 9000), TinyServer)
    httpd.serve_forever()
