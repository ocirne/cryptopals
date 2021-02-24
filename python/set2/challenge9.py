from basics import padding


def challenge9(text, pad_byte, block_size):
    """
    >>> padded = challenge9("YELLOW SUBMARINE", '\\x04', 20)
    >>> padded
    'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'
    >>> len(padded)
    20
    """
    ba = bytearray(text, 'UTF-8')
    return padding(ba, pad_byte, block_size).decode()
