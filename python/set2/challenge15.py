
# see https://tools.ietf.org/html/rfc5652 6.3

def strip_padding(plaintext):
    """
    >>> strip_padding("ICE ICE BABY\x04\x04\x04\x04")
    'ICE ICE BABY'
    >>> strip_padding("ICE ICE BAB\x04\x04\x04\x04\x04")
    Traceback (most recent call last):
      ...
    Exception: Invalid padding
    >>> strip_padding("ICE ICE BABY\x05\x05\x05\x05")
    Traceback (most recent call last):
      ...
    Exception: Invalid padding
    >>> strip_padding("ICE ICE BABY\x01\x02\x03\x04")
    Traceback (most recent call last):
      ...
    Exception: Invalid padding
    """
    c = plaintext[-1]
    i = ord(c)
    t, s = plaintext[:-i], plaintext[-i:]
    if s == len(s) * c and t[-1] != c:
        return t
    raise Exception('Invalid padding')
