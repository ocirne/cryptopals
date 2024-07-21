//import random
//import secrets
//from abc import abstractmethod, ABC
//from typing import Union
//
//from Crypto.Cipher import AES
//
//from cryptopals.basics import padding, strip_padding, InvalidPaddingException
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
//    fun request_groups(p, g) {
//        p = p
//        g = g
//        return "ACK"
//
//    fun request_pub_key(A) {
//        b = random.randrange(0, p)
//        B = pow(g, b, p)
//        s = pow(A, b, p)
//        return B
//
//    fun request_message(ciphertext_a: ByteArray):ByteArray:
//        return aes_cbc_encrypt(s, ciphertext_a)
//
//
//class AbstractMallory(ABC) {
//    fun __init__(bob: Bob) {
//        bob = bob
//
//    @abstractmethod
//    fun request_groups(p, g) {
//        ...
//
//    fun request_pub_key(A) {
//        return bob.request_pub_key(A)
//
//    fun request_message(ciphertext_a: ByteArray):ByteArray:
//        ct_b = bob.request_message(ciphertext_a)
//        ct, iv = ciphertext_a[:-16], ciphertext_a[-16:]
//        easy_decrypt(ct, iv)
//        return ct_b
//
//    @abstractmethod
//    fun easy_decrypt(ct: ByteArray, iv: ByteArray) {
//        ...
//
//
//class Mallory1(AbstractMallory) {
//    """ g = 1 """
//
//    fun request_groups(p, g) {
//        bob.request_groups(p, 1)
//
//    fun easy_decrypt(ct: ByteArray, iv: ByteArray) {
//        """
//        s = B**a = (g**b)**a = (1**b)**a = 1**a = 1  mod p
//        """
//        recovered_pt = aes_cbc_decrypt(1, ct, iv)
//        print("recovered pt (g = 1) {", recovered_pt)
//
//
//class Mallory2(AbstractMallory) {
//    """ g = p """
//
//    fun request_groups(p, g) {
//        bob.request_groups(p, p)
//
//    fun easy_decrypt(ct: ByteArray, iv: ByteArray):ByteArray:
//        """
//        s = B**a = (g**b)**a = (p**b)**a = 0  mod p
//        """
//        recovered_pt = aes_cbc_decrypt(0, ct, iv)
//        print("recovered pt (g = p) {", recovered_pt)
//
//
//class Mallory3(AbstractMallory) {
//    """ g = p - 1 """
//
//    fun request_groups(p, g) {
//        p = p
//        bob.request_groups(p, p - 1)
//
//    fun easy_decrypt(ct: ByteArray, iv: ByteArray) {
//        """
//        s = B**a = (g**b)**a = ((p-1)**b)**a = ((-1)**b)**a = {p-1, 1}  mod p
//        """
//        try:
//            recovered_pt = aes_cbc_decrypt(1, ct, iv)
//        except InvalidPaddingException:
//            recovered_pt = aes_cbc_decrypt(p - 1, ct, iv)
//        print("recovered pt (g = p - 1) {", recovered_pt)
//
//
//class Alice:
//    fun __init__(bob: Union[Bob, Mallory1, Mallory2, Mallory3]) {
//        bob = bob
//        pt = b"Ice Ice Baby"
//
//    fun request_groups() {
//        // should be a prime, good enough
//        p = random.randint(0, 2 ** 31)
//        g = random.randint(0, 100)
//        a = random.randrange(0, p)
//        bob.request_groups(p, g)
//
//    fun request_pub_key() {
//        """
//        A -> M
//        Send "p", "g", "A"
//        """
//        A = pow(g, a, p)
//        B = bob.request_pub_key(A)
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
//fun challenge34(mallory_class) {
//    """
//    >>> challenge34(Mallory1)
//    recovered pt (g = 1) { b'Ice Ice Baby'
//    >>> challenge34(Mallory2)
//    recovered pt (g = p) { b'Ice Ice Baby'
//    >>> challenge34(Mallory3)
//    recovered pt (g = p - 1) { b'Ice Ice Baby'
//    """
//    bob = Bob()
//    mallory = mallory_class(bob)
//    alice = Alice(mallory)
//
//    alice.request_groups()
//    alice.request_pub_key()
//    alice.request_message()
