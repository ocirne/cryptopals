//import random
//import secrets
//from typing import Union
//
//from Crypto.Cipher import AES
//
//from cryptopals.basics import padding, strip_padding
//from cryptopals.digests import SHA1
//
//
//fun aes_cbc_encrypt(priv_key: int, pt: ByteArray):ByteArray:
//    s = priv_key.to_ByteArray(8, byteorder="big")
//    key = SHA1().digest(s)[:16]
//    iv = secrets.token_ByteArray(16)
//    aes = AES.new(key, AES.MODE_CBC, iv)
//    ct = aes.encrypt(padding(pt))
//    return ct + iv
//
//
//fun aes_cbc_decrypt(priv_key: int, ct: ByteArray, iv: ByteArray):ByteArray:
//    s = priv_key.to_ByteArray(8, byteorder="big")
//    key = SHA1().digest(s)[:16]
//    aes = AES.new(key, AES.MODE_CBC, iv)
//    pt = aes.decrypt(ct)
//    return strip_padding(pt)
//
//
//class Bob:
//    fun request_pub_key(p, g, A) {
//        """
//        B -> M
//        Send "B"
//        """
//        b = random.randrange(0, p)
//        B = pow(g, b, p)
//        s = pow(A, b, p)
//        return B
//
//    fun request_message(ciphertext_a: ByteArray):ByteArray:
//        """
//        B->M
//        Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//        """
//        return aes_cbc_encrypt(s, ciphertext_a)
//
//
//class Mallory:
//    fun __init__(bob: Bob) {
//        bob = bob
//
//    fun request_pub_key(p, g, A) {
//        """
//        A->M
//        Send "p", "g", "p"
//        ---
//        M->A
//        Send "p"
//        """
//        bob.request_pub_key(p, g, p)
//        return p
//
//    fun request_message(ciphertext_a: ByteArray):ByteArray:
//        """
//        M->B
//        Relay that to B
//        ---
//        M->A
//        Relay that to A
//
//        Unknown: s
//        s = pow(B, a, p):s = pow(p, a, p) = 0
//        """
//        ct_b = bob.request_message(ciphertext_a)
//        ct, iv = ciphertext_a[:-16], ciphertext_a[-16:]
//        recovered_pt = aes_cbc_decrypt(0, ct, iv)
//        print("recovered pt:", recovered_pt)
//        return ct_b
//
//
//class Alice:
//    fun __init__(bob: Union[Bob, Mallory]) {
//        bob = bob
//        pt = b"Ice Ice Baby"
//
//    fun request_pub_key() {
//        """
//        A -> M
//        Send "p", "g", "A"
//        """
//        // should be a prime, good enough
//        p = random.randint(0, 2 ** 31)
//        g = random.randint(0, 100)
//        a = random.randrange(0, p)
//        A = pow(g, a, p)
//        B = bob.request_pub_key(p, g, A)
//        s = pow(B, a, p)
//
//    fun request_message() {
//        """
//        A -> M
//        Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
//        """
//        ct = aes_cbc_encrypt(s, pt)
//        bob.request_message(ct)
//
//
//fun challenge34() {
//    """
//    >>> challenge34()
//    recovered pt: b'Ice Ice Baby'
//    """
//    bob = Bob()
//    mallory = Mallory(bob)
//    alice = Alice(mallory)
//
//    alice.request_pub_key()
//    alice.request_message()
//
//
//if __name__ == "__main__":
//    challenge34()
