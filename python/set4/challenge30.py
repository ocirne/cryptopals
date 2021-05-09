import math
import random
import secrets

MASK = 0xFFFF_FFFF


# TODO refactor


def chunks(message: bytes):
    i = 0
    while i < len(message):
        yield message[i:i + 64]
        i += 64


def left_rotate(w, r):
    return ((w << r) | (w >> (32 - r))) & MASK


def word(w: bytes):
    return int.from_bytes(w, byteorder='little', signed=False)


class MD5:
    """
    see https://en.wikipedia.org/wiki/SHA-1
    see https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data

    >>> md5 = MD5()
    >>> md5.digest(b"")
    'd41d8cd98f00b204e9800998ecf8427e'
    >>> md5.digest(b"The quick brown fox jumps over the lazy dog")
    '9e107d9d372bb6826bd81d3542a419d6'
    >>> md5.digest(b"The quick brown fox jumps over the lazy dog.")
    'e4d909c290d0fb1ca068ffaddf22cbd0'
    >>> md5.digest(b"abc")
    '900150983cd24fb0d6963f7d28e17f72'
    >>> md5.digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    '8215ef0796a20bcaaae116d3876c664a'
    >>> md5.digest(b"a" * 1_000_000)
    '7707d6ae4e027c70eea2a935c2296f21'
    """

    def padding(self, message: bytes):
        # ml = message length in bits
        ml = len(message) + self.pa
        # Pre-processing: adding a single 1 bit
        padding = b'\x80'
        # Pre-processing: padding with zeros
        padding += b'\x00' * ((56 - (ml + 1) & 0x3F) & 0x3F)
        # append original length in bits mod 264 to message
        padding += ((ml * 8) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, byteorder='little')
        return bytes(padding)

    def _preprocess(self, message: bytes):
        return message + self.padding(message)

    def __init__(self, a=0x67452301, b=0xefcdab89, c=0x98badcfe, d=0x10325476, pa=0):
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.pa = pa

    def digest(self, message: bytes):
        # s specifies the per-round shift amounts
        s = []
        s.extend([7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22])
        s.extend([5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20])
        s.extend([4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23])
        s.extend([6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21])

        # Use binary integer part of the sines of integers (Radians) as constants:
        k = [int((2**32) * abs(math.sin(i + 1))) & MASK for i in range(64)]

        # Initialize variables:
        a0 = self.a
        b0 = self.b
        c0 = self.c
        d0 = self.d

        padded_message = self._preprocess(message)
        # Process the message in successive 512-bit chunks:
        for chunk in chunks(padded_message):
            # break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15
            m = [word(chunk[i:i+4]) for i in range(0, 64, 4)]
            # Initialize hash value for this chunk:
            a = a0
            b = b0
            c = c0
            d = d0
            # Main loop:
            for i in range(64):
                if 0 <= i <= 15:
                    f = d ^ (b & (c ^ d))
                    g = i
                elif 16 <= i <= 31:
                    f = c ^ (d & (b ^ c))
                    g = (5*i + 1) & 0xF
                elif 32 <= i <= 47:
                    f = b ^ c ^ d
                    g = (3*i + 5) & 0xF
                elif 48 <= i <= 63:
                    f = c ^ (b | (~d))
                    g = (7*i) & 0xF
                else:
                    raise

                # Be wary of the below definitions of a,b,c,d
                f = (f + a + k[i] + m[g]) & MASK  # M[g] must be a 32-bits block
                a = d
                d = c
                c = b
                b = b + left_rotate(f, s[i])
            # Add this chunk's hash to result so far:
            a0 = (a0 + a) & MASK
            b0 = (b0 + b) & MASK
            c0 = (c0 + c) & MASK
            d0 = (d0 + d) & MASK

        result = (d0 << 96) | (c0 << 64) | (b0 << 32) | a0   # (Output is in little-endian)
        raw = result.to_bytes(16, byteorder='little')
        return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


class Oracle30:

    def __init__(self):
        self.key = secrets.token_bytes(random.randrange(5, 10))
        self.original_message = "Ice Ice Baby"

    def mac(self, message):
        md5 = MD5()
        return md5.digest(self.key + message)


def find_init_values(provided_mac):
    raw = int(provided_mac, 16).to_bytes(16, byteorder='big')
    digest = int.from_bytes(raw, byteorder='little')
    a = digest & MASK
    b = (digest >> 32) & MASK
    c = (digest >> 64) & MASK
    d = (digest >> 96) & MASK
    return a, b, c, d


# this seems to work 100% of the time
def challenge30():
    oracle = Oracle30()
    original_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    additional_data = b';admin=true'
    provided_mac = oracle.mac(original_message)

    # guess
    for key_length in range(5, 10):
        glue_padding = MD5().padding(b'#' * key_length + original_message)
        reference_mac = oracle.mac(original_message + glue_padding + additional_data)
        a, b, c, d = find_init_values(provided_mac)
        # 128: len(key) + len(message) < 10 + 77 = 87 -> 128 = len(preprocessed message)
        forged_mac = MD5(a, b, c, d, 128).digest(additional_data)
        if reference_mac == forged_mac:
            print('Found a collision!')


if __name__ == '__main__':
    challenge30()
