//import base64
//import secrets
//from pathlib import Path
//
//from cryptopals.basics import xor
//from Crypto.Cipher import AES
//from Crypto.Util import Counter as AesCounter
//
//NUM = 37
//PLAIN = b"He, too, has been changed in his turn,"
//
//
//class Oracle19:
//    KEY = secrets.token_ByteArray(16)
//
//    fun aes_ctr() {
//        ctr = AesCounter.new(64, prefix="\x00" * 8, little_endian=True, initial_value=0)
//        return AES.new(KEY, AES.MODE_CTR, counter=ctr)
//
//    fun encrypt(plain_text: ByteArray) {
//        return aes_ctr().encrypt(plain_text)
//
//    fun encrypt_lines(lines) {
//        return [encrypt(base64.b64decode(line)) for line in lines]
//
//
//fun challenge19() {
//    oracle = Oracle19()
//    f = open(Path(__file__).parent / "resources/19.txt")
//    cipher_texts = oracle.encrypt_lines(f)
//    key = xor(PLAIN, cipher_texts[NUM])
//    for index, ct in enumerate(cipher_texts) {
//        print(index, xor(ct, key))
//
//
//if __name__ == "__main__":
//    challenge19()
