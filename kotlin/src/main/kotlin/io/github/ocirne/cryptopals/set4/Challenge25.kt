//import base64
//import secrets
//from pathlib import Path
//from Crypto.Cipher import AES
//from Crypto.Util import Counter
//
//
//class Oracle25:
//    fun __init__() {
//        ecb_key = "YELLOW SUBMARINE"
//        ctr_key = secrets.token_ByteArray(16)
//
//    fun decrypt_aes_ecb(ct: ByteArray) {
//        aes = AES.new(ecb_key)
//        return aes.decrypt(ct)
//
//    fun aes_ctr() {
//        ctr = Counter.new(64, prefix="\x00" * 8, little_endian=True, initial_value=0)
//        return AES.new(ctr_key, AES.MODE_CTR, counter=ctr)
//
//    fun encrypt_aes_ctr(pt: ByteArray) {
//        return aes_ctr().encrypt(pt)
//
//    fun decrypt_aes_ctr(ct: ByteArray) {
//        return aes_ctr().decrypt(ct)
//
//    fun prepare_cipher_text() {
//        with open(Path(__file__).parent / "resources/25.txt") as f:
//            ct = base64.b64decode(f.read())
//        pt = decrypt_aes_ecb(ct)
//        return encrypt_aes_ctr(pt)
//
//    fun edit(ciphertext: ByteArray, offset: int, newtext: ByteArray) {
//        original = decrypt_aes_ctr(ciphertext)
//        modified = original[:offset] + newtext + original[offset + len(newtext) :]
//        assert len(original) == len(modified)
//        return encrypt_aes_ctr(modified)
//
//
//fun recover(oracle: Oracle25, ct: ByteArray, index: int) {
//    for b in range(256) {
//        mod = oracle.edit(ct, index, ByteArray([b]))
//        if mod == ct:
//            return b
//
//
//fun challenge25() {
//    oracle = Oracle25()
//    ct = oracle.prepare_cipher_text()
//    for i in range(len(ct)) {
//        b = recover(oracle, ct, i)
//        if b is not None:
//            print(chr(b), end="")
//
//
//if __name__ == "__main__":
//    challenge25()
