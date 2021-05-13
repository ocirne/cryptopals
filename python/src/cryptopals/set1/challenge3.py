from cryptopals.basics import from_hex, most_common, xor_single


def challenge3(secret):
    """
    >>> challenge3('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    "Cooking MC's like a pound of bacon"
    """
    s = from_hex(secret)
    most_common_byte = most_common(s)
    key = most_common_byte ^ ord(" ")
    plain_ba = xor_single(s, key)
    return plain_ba.decode()
