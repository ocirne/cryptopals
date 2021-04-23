
import secrets
from urllib.parse import quote_plus

from Crypto.Cipher import AES

from basics import padding

BLOCK_SIZE = 16
KEY = secrets.token_bytes(BLOCK_SIZE)
IV = secrets.token_bytes(BLOCK_SIZE)
PREFIX = b'"comment1=cooking%20MCs;userdata="'
SUFFIX = b'";comment2=%20like%20a%20pound%20of%20bacon"'


def encrypt_c16(input_string):
    plain_text = PREFIX + quote_plus(input_string).encode() + SUFFIX
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    return aes.encrypt(padding(plain_text))


def decrypt_c16(ciphertext):
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = aes.decrypt(ciphertext)
    print(plaintext)
    return b';admin=true;' in plaintext


ciphertext = encrypt_c16(';admin=true;')
print(decrypt_c16(ciphertext))
