import itertools


def challenge5(plain, key):
    """
    >>> plain = "Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal"
    >>> key = "ICE"
    >>> challenge5(plain, key)
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    """
    plain_ba = bytearray(plain, 'UTF-8')
    key_ba = bytearray(key, 'UTF-8')
    cipher_ba = bytearray(c ^ k for c, k in zip(plain_ba, itertools.cycle(key_ba)))
    return cipher_ba.hex()
