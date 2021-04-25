
# see https://tools.ietf.org/html/rfc5652 6.3

from basics import strip_padding


def challenge15(plaintext: bytes):
    """
    >>> challenge15(b"ICE ICE BABY\x04\x04\x04\x04")
    b'ICE ICE BABY'
    >>> challenge15(b"ICE ICE BAB\x04\x04\x04\x04\x04")
    Traceback (most recent call last):
      ...
    Exception: Invalid padding
    >>> challenge15(b"ICE ICE BABY\x05\x05\x05\x05")
    Traceback (most recent call last):
      ...
    Exception: Invalid padding
    >>> challenge15(b"ICE ICE BABY\x01\x02\x03\x04")
    Traceback (most recent call last):
      ...
    Exception: Invalid padding
    >>> challenge15(b'YELLOW SUBMARINE\\x04\\x04\\x04\\x04')
    b'YELLOW SUBMARINE'
    >>> challenge15(b'YELLOW SUBMARINE\\x02\\x02')
    b'YELLOW SUBMARINE'
    >>> challenge15(b'FOO\\x03\\x03\\x03')
    b'FOO'
    """
    t = strip_padding(plaintext)
    if t is None:
        raise Exception('Invalid padding')
    return t
