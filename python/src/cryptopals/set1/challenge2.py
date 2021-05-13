from cryptopals.basics import from_hex, xor


def fixed_xor(text, secret):
    """
    >>> a = '1c0111001f010100061a024b53535009181c'
    >>> b = '686974207468652062756c6c277320657965'
    >>> fixed_xor(a, b)
    '746865206b696420646f6e277420706c6179'
    """
    t = from_hex(text)
    s = from_hex(secret)
    c = xor(t, s)
    return c.hex()
