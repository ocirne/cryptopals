
def challenge9(text, pad_byte, block_length):
    """
    >>> padded = challenge9("YELLOW SUBMARINE", '\\x04', 20)
    >>> padded
    'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'
    >>> len(padded)
    20
    """
    return text + pad_byte * (block_length - len(text))