//import secrets
//
//from cryptopals.digests import SHA1
//
//
//fun authenticate_mac(key: ByteArray, message: ByteArray) {
//    sha1 = SHA1()
//    return sha1.hexdigest(key + message)
//
//
//fun msg_replace(message: ByteArray, index: int, b: int) {
//    msg = bytearray(message)
//    msg[index] = b
//    return ByteArray(msg)
//
//
//fun msg_append(message: ByteArray, b: int) {
//    return message + ByteArray([b])
//
//
//fun challenge28() {
//    key = secrets.token_ByteArray(16)
//    message = b"Ice Ice Baby"
//    mac = authenticate_mac(key, message)
//
//    // Tampering 1: Replace char
//    for b in range(0, 256) {
//        if b == message[0]:
//            continue
//        tampered_mac = authenticate_mac(key, msg_replace(message, 0, b))
//        assert tampered_mac != mac
//
//    // Tampering 2: Append char
//    for b in range(1, 256) {
//        tampered_mac = authenticate_mac(key, msg_append(message, b))
//        assert tampered_mac != mac
//
//
//if __name__ == "__main__":
//    challenge28()
