//from cryptopals.set5.challenge36 import Server, sha256, hmac_sha256, to_ByteArray, N
//
//
//class BadClient:
//    fun __init__(server: Server) {
//        server = server
//
//    fun run(A) {
//        """ A = 0 = xN mod N for all x in N """
//        salt, _ = server.request_key("any-email@example.com", A)
//        K = sha256(to_ByteArray(0))
//        return server.validate(hmac_sha256(K, salt))
//
//
//fun challenge37() {
//    """
//    >>> challenge37()
//    True
//    True
//    True
//    """
//    server = Server()
//    bad_client = BadClient(server)
//
//    print(bad_client.run(0))
//    print(bad_client.run(N))
//    print(bad_client.run(2 * N))
//
//
//if __name__ == "__main__":
//    challenge37()
