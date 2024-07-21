//import secrets
//
//from Crypto.Cipher import AES
//
//from cryptopals.basics import padding, xor
//
//BLOCK_SIZE = 16
//
//
//class Oracle26:
//    fun __init__() {
//        key = secrets.token_ByteArray(BLOCK_SIZE)
//        iv = key
//
//    fun aes_cbc() {
//        return AES.new(key, AES.MODE_CBC, iv)
//
//    fun encrypt(pt: ByteArray) {
//        // ??
//        //        try:
//        //            plain_text = pt.decode("ascii")
//        //        except UnicodeDecodeError as e:
//        //            raise Exception(e, "pt")
//        return ByteArray(aes_cbc().encrypt(padding(pt)))
//
//    fun decrypt(ct: ByteArray) {
//        return aes_cbc().decrypt(ct)
//
//
//oracle = Oracle26()
//
//
//fun modify(ct: ByteArray) {
//    c1 = ct[:BLOCK_SIZE]
//    return ByteArray(c1 + ByteArray([0] * BLOCK_SIZE) + c1)
//
//
//fun challenge27() {
//    """
//    >>> challenge27()
//    """
//    p1 = secrets.token_ByteArray(BLOCK_SIZE)
//    p2 = secrets.token_ByteArray(BLOCK_SIZE)
//    p3 = secrets.token_ByteArray(BLOCK_SIZE)
//    ciphertext = oracle.encrypt(p1 + p2 + p3)
//    modified = modify(ciphertext)
//
//    rpt = oracle.decrypt(modified)
//    rpt1, rpt3 = rpt[:BLOCK_SIZE], rpt[2 * BLOCK_SIZE : 3 * BLOCK_SIZE]
//    xor_p1_p3 = xor(rpt1, rpt3)
//
//    assert xor_p1_p3 == oracle.key
//
//
//if __name__ == "__main__":
//    challenge27()
