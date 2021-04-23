
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
    return bytearray(aes.encrypt(padding(plain_text)))


def decrypt_c16(ciphertext: bytearray):
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = aes.decrypt(bytes(ciphertext))
    return plaintext


def is_broken_c16(ciphertext: bytearray):
    plaintext = decrypt_c16(ciphertext)
    return b';admin=true;' in plaintext


def chunks(content, block_size):
    i = 0
    while i < len(content):
        yield content[i:i + block_size]
        i += block_size


def modify(ciphertext):
    for (i, (x, y)) in enumerate(zip('g%20MCs;user', ';admin=true;')):
        ciphertext[i] = ciphertext[i] ^ ord(x) ^ ord(y)
    return ciphertext


ciphertext = encrypt_c16(';admin=true;')
modified = modify(ciphertext[:])

print('----')
plaintext = decrypt_c16(ciphertext)
mod_plaintext = decrypt_c16(modified)

for chunk, mod_chunk in zip(chunks(plaintext, BLOCK_SIZE), chunks(mod_plaintext, BLOCK_SIZE)):
    print("%s    %s\n%s    %s\n" % (chunk.hex(), chunk, mod_chunk.hex(), mod_chunk))

print(is_broken_c16(modified))
