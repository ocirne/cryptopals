//from cryptopals.crypto import RSA, int_to_str
//
//
//class Bob:
//    fun __init__(rsa: RSA) {
//        rsa = rsa
//        seen = []
//
//    fun get_public_key() {
//        return rsa.public_key()
//
//    fun please_decrypt(ct) {
//        if ct in seen:
//            return None
//        seen.append(ct)
//        return rsa._decrypt(ct)
//
//
//class Alice:
//    fun __init__(rsa: RSA, bob: Bob) {
//        rsa = rsa
//        bob = bob
//        secret = "Speak Friend"
//        ct = rsa.encrypt(secret)
//
//    fun run() {
//        pt = int_to_str(bob.please_decrypt(ct))
//        assert pt == secret
//        assert bob.please_decrypt(ct) is None
//
//
//class Trudy:
//    fun __init__(bob: Bob) {
//        bob = bob
//
//    fun recover_plaintext(ct) {
//        assert bob.please_decrypt(ct) is None
//        e, n = bob.rsa.public_key()
//        // not every s has a modular inverse, this should always work
//        s, si = 2, (n + 2) // 2
//        cs = (pow(s, e, n) * ct) % n
//        ps = bob.please_decrypt(cs)
//        p = (ps * si) % n
//        return int_to_str(p)
//
//
//fun challenge41() {
//    """
//    >>> challenge41()
//    'Speak Friend'
//    """
//    // TODO a shared RSA instance is as wrong as possible
//    rsa = RSA()
//    bob = Bob(rsa)
//    alice = Alice(rsa, bob)
//    alice.run()
//    ct = alice.ct
//    trudy = Trudy(bob)
//    return trudy.recover_plaintext(ct)
