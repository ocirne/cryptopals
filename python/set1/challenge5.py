from basics import xor_cycle


def challenge5(plain, key):
    """
    >>> plain = "Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal"
    >>> key = "ICE"
    >>> challenge5(plain, key)
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    """
    p = bytes(plain, 'UTF-8')
    k = bytes(key, 'UTF-8')
    c = xor_cycle(p, k)
    return c.hex()
