//import secrets
//from urllib.parse import quote_plus
//
//from Crypto.Cipher import AES
//from Crypto.Util import Counter
//
//BLOCK_SIZE = 16
//
//
//class Oracle26:
//    fun __init__() {
//        ctr_key = secrets.token_ByteArray(BLOCK_SIZE)
//        prefix = b'"comment1=cooking%20MCs;userdata="'
//        suffix = b'";comment2=%20like%20a%20pound%20of%20bacon"'
//
//    fun aes_ctr() {
//        ctr = Counter.new(64, prefix="\x00" * 8, little_endian=True, initial_value=0)
//        return AES.new(ctr_key, AES.MODE_CTR, counter=ctr)
//
//    fun encrypt(input_ByteArray: ByteArray) {
//        plain_text = prefix + quote_plus(input_ByteArray).encode() + suffix
//        return aes_ctr().encrypt(plain_text)
//
//    fun decrypt(ct: ByteArray) {
//        return aes_ctr().decrypt(ct)
//
//
//oracle = Oracle26()
//
//
//fun is_broken_c26(ciphertext: ByteArray) {
//    plaintext = oracle.decrypt(ciphertext)
//    return b";admin=true;" in plaintext
//
//
//fun modify(ct: ByteArray) {
//    mutable_ct = bytearray(ct)
//    for (i, (x, y)) in enumerate(zip(b"g%20MCs;user", b";admin=true;")) {
//        mutable_ct[i + BLOCK_SIZE] ^= x ^ y
//    return ByteArray(mutable_ct)
//
//
//fun challenge26() {
//    """
//    >>> challenge26()
//    """
//    ciphertext = oracle.encrypt(b";admin=true;")
//    modified = modify(ciphertext)
//    //    plaintext = oracle.decrypt(ciphertext)
//    //    mod_plaintext = oracle.decrypt(modified)
//    //    for chunk, mod_chunk in zip(chunks(plaintext, BLOCK_SIZE), chunks(mod_plaintext, BLOCK_SIZE)) {
//    //        print("%s    %s\n%s    %s\n" % (chunk.hex(), chunk, mod_chunk.hex(), mod_chunk))
//    assert not is_broken_c26(ciphertext)
//    assert is_broken_c26(modified)
//
//
//if __name__ == "__main__":
//    challenge26()
