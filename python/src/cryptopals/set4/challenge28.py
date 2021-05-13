import secrets

from cryptopals.digests import SHA1


def authenticate_mac(key: bytes, message: bytes):
    sha1 = SHA1()
    return sha1.hexdigest(key + message)


def msg_replace(message: bytes, index: int, b: int):
    msg = bytearray(message)
    msg[index] = b
    return bytes(msg)


def msg_append(message: bytes, b: int):
    return message + bytes([b])


def challenge28():
    key = secrets.token_bytes(16)
    message = b"Ice Ice Baby"
    mac = authenticate_mac(key, message)

    # Tampering 1: Replace char
    for b in range(0, 256):
        if b == message[0]:
            continue
        tampered_mac = authenticate_mac(key, msg_replace(message, 0, b))
        assert tampered_mac != mac

    # Tampering 2: Append char
    for b in range(1, 256):
        tampered_mac = authenticate_mac(key, msg_append(message, b))
        assert tampered_mac != mac


if __name__ == '__main__':
    challenge28()
