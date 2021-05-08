import struct

MASK = 0xFFFF_FFFF


def chunks(message: bytes):
    i = 0
    while i < len(message):
        yield message[i:i + 64]
        i += 64


def left_rotate(w, r):
    return ((w << r) | (w >> (32 - r))) & MASK


def word(w: bytes):
    return struct.unpack(b'>I', w)[0]


class SHA1:
    """
    see https://en.wikipedia.org/wiki/SHA-1
    see https://www.di-mgt.com.au/sha_testvectors.html

    >>> sha1 = SHA1()
    >>> sha1.digest(b"")
    'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    >>> sha1.digest(b"The quick brown fox jumps over the lazy dog")
    '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'
    >>> sha1.digest(b"The quick brown fox jumps over the lazy cog")
    'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3'
    >>> sha1.digest(b"abc")
    'a9993e364706816aba3e25717850c26c9cd0d89d'
    >>> sha1.digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
    >>> sha1.digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    'a49b2446a02c645bf419f995b67091253a04a259'
    >>> sha1.digest(b"a" * 1_000_000)
    '34aa973cd4c4daa4f61eeb2bdbad27316534016f'
    """

    @staticmethod
    def preprocess(message: bytes):
        msg = bytearray(message)
        # ml = message length in bits, 64 bit quantity
        ml = len(msg) * 8
        # append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
        msg += b'\x80'
        # append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
        msg += b'\x00' * (((448 - (ml + 8) % 512) % 512) // 8)
        # append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
        msg += struct.pack(b'>Q', ml)
        return bytes(msg)

    def digest(self, message: bytes):
        # Initialize variables:
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0

        preprocessed_message = self.preprocess(message)
        # Process the message in successive 512-bit chunks:
        for chunk in chunks(preprocessed_message):
            # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            w = [word(chunk[i:i+4]) for i in range(0, 64, 4)]

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

        # Produce the final hash value (big-endian) as a 160-bit number:
        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
        return hex(hh)[2:]


def challenge28():
    sha1 = SHA1()
    print(sha1.digest(b''))


if __name__ == '__main__':
    challenge28()