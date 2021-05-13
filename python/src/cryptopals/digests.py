import math

from cryptopals.basics import chunks, xor, from_hex

MASK = 0xFFFF_FFFF


def left_rotate(w, r):
    return ((w << r) | (w >> (32 - r))) & MASK


def big_endian_word(w: bytes):
    return int.from_bytes(w, byteorder='big', signed=False)


def little_endian_word(w: bytes):
    return int.from_bytes(w, byteorder='little', signed=False)


class SHA1:
    """
    see https://en.wikipedia.org/wiki/SHA-1
    see https://www.di-mgt.com.au/sha_testvectors.html

    >>> sha1 = SHA1()
    >>> sha1.hexdigest(b"")
    'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    >>> sha1.hexdigest(b"The quick brown fox jumps over the lazy dog")
    '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'
    >>> sha1.hexdigest(b"The quick brown fox jumps over the lazy cog")
    'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3'
    >>> sha1.hexdigest(b"abc")
    'a9993e364706816aba3e25717850c26c9cd0d89d'
    >>> sha1.hexdigest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
    >>> sha1.hexdigest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    'a49b2446a02c645bf419f995b67091253a04a259'
    >>> sha1.hexdigest(b"a" * 1_000_000)
    '34aa973cd4c4daa4f61eeb2bdbad27316534016f'
    """

    def padding(self, message: bytes):
        # ml = message length in bits, 64 bit quantity
        ml = (len(message) + self.pa) * 8
        # append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
        padding = b'\x80'
        # append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
        padding += b'\x00' * (((448 - (ml + 8) % 512) % 512) // 8)
        # append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
        padding += (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8, byteorder='big')
        return bytes(padding)

    def _preprocess(self, message: bytes):
        return message + self.padding(message)

    def __init__(self, i0=0x67452301, i1=0xEFCDAB89, i2=0x98BADCFE, i3=0x10325476, i4=0xC3D2E1F0, pa=0):
        """ Overwrite initialization variables for challenge 29 """
        self.i0 = i0
        self.i1 = i1
        self.i2 = i2
        self.i3 = i3
        self.i4 = i4
        self.pa = pa

    def _digest(self, message: bytes):
        # Initialize variables:
        h0 = self.i0
        h1 = self.i1
        h2 = self.i2
        h3 = self.i3
        h4 = self.i4

        preprocessed_message = self._preprocess(message)
        # Process the message in successive 512-bit chunks:
        for _, chunk in chunks(preprocessed_message, 64):
            # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            w = [big_endian_word(chunk[i:i+4]) for i in range(0, 64, 4)]

            # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
            for i in range(16, 80):
                w.append(left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

            # Initialize hash value for this chunk:
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4

            # Main loop:[3][57]
            for i in range(80):
                if 0 <= i <= 19:
                    # variant 1 to avoid not
                    f = d ^ (b & (c ^ d))
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                else:
                    raise

                temp = (left_rotate(a, 5) + f + e + k + w[i]) & MASK
                e = d
                d = c
                c = left_rotate(b, 30)
                b = a
                a = temp

            # Add this chunk's hash to result so far:
            h0 = (h0 + a) & MASK
            h1 = (h1 + b) & MASK
            h2 = (h2 + c) & MASK
            h3 = (h3 + d) & MASK
            h4 = (h4 + e) & MASK

        return h0, h1, h2, h3, h4

    def digest(self, message: bytes):
        hh = self._digest(message)
        return b''.join(h.to_bytes(4, byteorder='big') for h in hh)

    def hexdigest(self, message: bytes):
        h0, h1, h2, h3, h4 = self._digest(message)
        # Produce the final hash value (big-endian) as a 160-bit number:
        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
        return '{:040x}'.format(hh)


class MD5:
    """
    see https://en.wikipedia.org/wiki/SHA-1
    see https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data

    >>> md5 = MD5()
    >>> md5.hexdigest(b"")
    'd41d8cd98f00b204e9800998ecf8427e'
    >>> md5.hexdigest(b"The quick brown fox jumps over the lazy dog")
    '9e107d9d372bb6826bd81d3542a419d6'
    >>> md5.hexdigest(b"The quick brown fox jumps over the lazy dog.")
    'e4d909c290d0fb1ca068ffaddf22cbd0'
    >>> md5.hexdigest(b"abc")
    '900150983cd24fb0d6963f7d28e17f72'
    >>> md5.hexdigest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    '8215ef0796a20bcaaae116d3876c664a'
    >>> md5.hexdigest(b"a" * 1_000_000)
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

    def _digest(self, message: bytes):
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
        for _, chunk in chunks(padded_message, 64):
            # break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15
            m = [little_endian_word(chunk[i:i+4]) for i in range(0, 64, 4)]
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

        return a0, b0, c0, d0

    def digest(self, message: bytes):
        dd = self._digest(message)
        return b''.join(d.to_bytes(4, byteorder='little') for d in dd)

    def hexdigest(self, message: bytes):
        a0, b0, c0, d0 = self._digest(message)
        result = (d0 << 96) | (c0 << 64) | (b0 << 32) | a0   # (Output is in little-endian)
        raw = result.to_bytes(16, byteorder='little')
        return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


def hmac(key: bytes, message: bytes, mac, block_size):
    """
    see https://en.wikipedia.org/wiki/HMAC
    see https://datatracker.ietf.org/doc/html/rfc2202
    """
    # Keys longer than blockSize are shortened by hashing them
    if len(key) > block_size:
        key = mac.digest(key)  # key is outputSize bytes long

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if len(key) < block_size:
        key += b'\x00' * (block_size - len(key))  # Pad key with zeros to make it blockSize bytes long

    o_key_pad = xor(key, b'\x5c' * block_size)   # Outer padded key
    i_key_pad = xor(key, b'\x36' * block_size)   # Inner padded key

    return mac.hexdigest(o_key_pad + mac.digest(i_key_pad + message))


def hmac_sha1(key: bytes, message: bytes):
    """
    >>> hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog")
    'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9'
    >>> hmac_sha1(from_hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), b"Hi There")
    'b617318655057264e28bc0b6fb378c8ef146be00'
    >>> hmac_sha1(b"Jefe", b"what do ya want for nothing?")
    'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'
    >>> hmac_sha1(from_hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), b'\\xdd' * 50)
    '125d7342b9ac11cd91a39af48aa17b4f63f175d3'
    >>> hmac_sha1(from_hex('0102030405060708090a0b0c0d0e0f10111213141516171819'), b'\\xcd' * 50)
    '4c9007f4026250c6bc8414f9bf50c86c2d7235da'
    >>> hmac_sha1(from_hex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'), b"Test With Truncation")
    '4c1a03424b55e07fe7f27be1d58bb9324a9a5a04'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key - Hash Key First")
    'aa4ae5e15272d00e95705637ce8a3b55ed402112'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")
    'e8e99d0f45237d786d6bbaa7965c7808bbff1a91'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key - Hash Key First")
    'aa4ae5e15272d00e95705637ce8a3b55ed402112'
    >>> hmac_sha1(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")
    'e8e99d0f45237d786d6bbaa7965c7808bbff1a91'
    """
    return hmac(key, message, SHA1(), block_size=64)


def hmac_md5(key: bytes, message: bytes):
    """
    >>> hmac_md5(b"key", b"The quick brown fox jumps over the lazy dog")
    '80070713463e7749b90c2dc24911e275'
    >>> hmac_md5(from_hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), b"Hi There")
    '9294727a3638bb1c13f48ef8158bfc9d'
    >>> hmac_md5(b"Jefe", b"what do ya want for nothing?")
    '750c783e6ab0b503eaa86e310a5db738'
    >>> hmac_md5(from_hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), b'\\xdd' * 50)
    '56be34521d144c88dbb8c733f0e8b3f6'
    >>> hmac_md5(from_hex('0102030405060708090a0b0c0d0e0f10111213141516171819'), b'\\xcd' * 50)
    '697eaf0aca3a3aea3a75164746ffaa79'
    >>> hmac_md5(from_hex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'), b"Test With Truncation")
    '56461ef2342edc00f9bab995690efd4c'
    >>> hmac_md5(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key - Hash Key First")
    '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd'
    >>> hmac_md5(b'\\xaa' * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data")
    '6f630fad67cda0ee1fb1f562db3aa53e'
    """
    return hmac(key, message, MD5(), block_size=64)

