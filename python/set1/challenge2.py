def fixed_xor(t, s):
    """
    >>> a = '1c0111001f010100061a024b53535009181c'
    >>> b = '686974207468652062756c6c277320657965'
    >>> fixed_xor(a, b)
    '746865206b696420646f6e277420706c6179'
    """
    t_ba = bytearray.fromhex(t)
    s_ba = bytearray.fromhex(s)
    c_ba = bytearray(a ^ b for a, b in zip(t_ba, s_ba))
    return c_ba.hex()
