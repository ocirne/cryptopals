from collections import Counter


def fixed_xor_single_byte(secret, key):
    s_ba = bytearray.fromhex(secret)
    return bytearray(c ^ key for c in s_ba)


def pretty_print(ba):
    return "".join(chr(b) for b in ba)


def challenge3(secret):
    """
    >>> challenge3('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    "Cooking MC's like a pound of bacon"
    """
    counts = Counter(bytearray.fromhex(secret))
    most_common_byte = counts.most_common(1)[0][0]
    key = most_common_byte ^ ord(' ')
    plain_ba = fixed_xor_single_byte(secret, key)
    return pretty_print(plain_ba)
