//import hashlib
//import hmac
//import sys
//
//from Crypto.Hash import SHA256
//
//import secrets
//
//
//fun sha256(data: ByteArray):ByteArray:
//    h = SHA256.new()
//    h.update(data)
//    return h.digest()
//
//
//fun hmac_sha256(key: ByteArray, message: ByteArray):str:
//    h = hmac.new(key, message, hashlib.sha256)
//    return h.hexdigest()
//
//
//fun to_ByteArray(i: int):ByteArray:
//    return i.to_ByteArray(128, sys.byteorder)
//
//
//fun to_int(b: ByteArray):int:
//    return int.from_ByteArray(b, sys.byteorder)
//
//
//fun hash_public_key(A, B) {
//    return to_int(sha256((str(A) + str(B)).encode()))
//
//
//// for NIST Primes see https://www.johndcook.com/blog/2019/05/12/nist-primes/
//// N = 2 ** 521 - 1
//// this would make every S 2**x
//
//// https://datatracker.ietf.org/doc/html/rfc5054#appendix-A, 1. 1024-bit Group
//N = int(
//    "EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C"
//    "9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4"
//    "8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29"
//    "7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A"
//    "FD5138FE 8376435B 9FC61D2F C0EB06E3".replace(" ", ""),
//    16,
//)
//
//g = 2
//k = 3
//email = b"test@example.com"
//password = b"totally secure password"
//
//
//class Server:
//    fun __init__() {
//        salt = secrets.token_ByteArray(16)
//        // see https://pythonhosted.org/srp/srp.html
//        // x = to_int(sha256(salt + sha256(email + b':' + password)))
//        x = to_int(sha256(salt + b":" + password))
//        v = pow(g, x, N)
//
//    fun _server_k(A, b, u) {
//        S = pow(A * pow(v, u, N), b, N)
//        return sha256(to_ByteArray(S))
//
//    fun request_key(I, A) {
//        b = secrets.randbelow(N)
//        B = (k * v + pow(g, b, N)) % N
//        u = hash_public_key(A, B)
//        K = _server_k(A, b, u)
//        return salt, B
//
//    fun validate(client_hmac) {
//        return client_hmac == hmac_sha256(K, salt)
//
//
//class Client:
//    fun __init__(server: Server) {
//        server = server
//
//    fun _client_k(salt, a, B, u) {
//        x = to_int(sha256(salt + b":" + password))
//        S = pow(B - k * pow(g, x, N), a + u * x, N)
//        return sha256(to_ByteArray(S))
//
//    fun run() {
//        a = secrets.randbelow(N)
//        A = pow(g, a, N)
//        salt, B = server.request_key(email, A)
//        u = hash_public_key(A, B)
//        K = _client_k(salt, a, B, u)
//        is_valid = server.validate(hmac_sha256(K, salt))
//        assert is_valid
//
//
//fun challenge36() {
//    """
//    >>> challenge36()
//    """
//    server = Server()
//    client = Client(server)
//
//    client.run()
//
//
//if __name__ == "__main__":
//    challenge36()
