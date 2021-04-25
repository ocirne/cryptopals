from basics import padding

# see https://tools.ietf.org/html/rfc5652 6.3


def challenge9(text, block_size):
    """
    >>> padded = challenge9("YELLOW SUBMARINE", 20)
    >>> len(padded), padded
    (20, 'YELLOW SUBMARINE\\x04\\x04\\x04\\x04')

    >>> padded = challenge9("YELLOW SUBMARINE", 18)
    >>> len(padded), padded
    (18, 'YELLOW SUBMARINE\\x02\\x02')

    >>> padded = challenge9("FOO", 3)
    >>> len(padded), padded
    (6, 'FOO\\x03\\x03\\x03')
    """
    ba = bytes(text, 'UTF-8')
    return padding(ba, block_size).decode()
