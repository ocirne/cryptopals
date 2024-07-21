//import sys
//
//import secrets
//from pathlib import Path
//from typing import Union
//
//from cryptopals.set5.challenge36 import sha256, hmac_sha256
//
//
//CRACKLIB_SMALL = "/usr/share/dict/cracklib-small"  // ~35 seconds
//CRACKLIB_SMALLER = Path(__file__).parent / "resources/38.txt"
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
//fun words() {
//    for line in open(CRACKLIB_SMALLER) {
//        yield ByteArray(line.strip(), "UTF-8")
//
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
//password = b"sticky"
//
//
//class Server:
//    fun __init__() {
//        salt = secrets.token_ByteArray(16)
//        x = to_int(sha256(salt + password))
//        v = pow(g, x, N)
//
//    fun _server_k(A, b, u) {
//        S = pow(A * pow(v, u, N), b, N)
//        return sha256(to_ByteArray(S))
//
//    fun request_key(I, A) {
//        b = secrets.randbelow(N)
//        B = pow(g, b, N)
//        u = secrets.randbits(128)
//        K = _server_k(A, b, u)
//        return salt, B, u
//
//    fun validate(client_hmac) {
//        return client_hmac == hmac_sha256(K, salt)
//
//
//class Mallory:
//    """ modifies (b), B, u, (salt) """
//
//    fun __init__(server: Server) {
//        server = server
//
//    fun request_key(I, A) {
//        A = A
//        salt, _, _ = server.request_key(I, A)
//        // set B = g, u = 1
//        return salt, g, 1
//
//    fun _simulate_hmac(guess) {
//        """
//        S = B ** (a+ u*x) = B**a * B**(u*x) mod N
//        set B = g, u = 1
//        S = g**a * g**(1*x) = A * g**x mod N
//        """
//        x = to_int(sha256(salt + guess))
//        S = (A * pow(g, x, N)) % N
//        K = sha256(to_ByteArray(S))
//        return hmac_sha256(K, salt)
//
//    fun _crack_password(client_hmac) {
//        for word in words() {
//            guess_hmac = _simulate_hmac(word)
//            if guess_hmac == client_hmac:
//                return word
//
//    fun validate(client_hmac) {
//        recovered_password = _crack_password(client_hmac)
//        print("recovered password:", recovered_password.decode())
//        // the hmac doesn't validate for the server, but can be calculated from the known password
//        return server.validate(client_hmac)
//
//
//class Client:
//    fun __init__(server: Union[Mallory, Server]) {
//        server = server
//
//    fun _client_k(salt, a, B, u) {
//        x = to_int(sha256(salt + password))
//        S = pow(B, a + u * x, N)
//        return sha256(to_ByteArray(S))
//
//    fun run() {
//        a = secrets.randbelow(N)
//        A = pow(g, a, N)
//        salt, B, u = server.request_key(email, A)
//        K = _client_k(salt, a, B, u)
//        return server.validate(hmac_sha256(K, salt))
//
//
//fun challenge38() {
//    """
//    >>> challenge38()
//    recovered password: sticky
//    """
//    server = Server()
//    mallory = Mallory(server)
//    client = Client(mallory)
//
//    client.run()
//
//
//if __name__ == "__main__":
//    challenge38()
