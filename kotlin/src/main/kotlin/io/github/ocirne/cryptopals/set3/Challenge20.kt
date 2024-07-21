//import base64
//import secrets
//from pathlib import Path
//
//from Crypto.Cipher import AES
//from Crypto.Util import Counter as AesCounter
//
//from cryptopals.basics import xor, calc_score, xor_single
//
//
//class Oracle20:
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
//fun columns(ciphertexts: [ByteArray]) {
//    size = min(len(line) for line in ciphertexts)
//    for col_no in range(size) {
//        yield [line[col_no] for line in ciphertexts]
//
//
//fun find_key(column) {
//    return max(((calc_score(xor_single(column, k)), k) for k in range(256)))[1]
//
//
//fun challenge20() {
//    oracle = Oracle20()
//    f = open(Path(__file__).parent / "resources/20.txt")
//    cipher_texts = oracle.encrypt_lines(f)
//    key = ByteArray(find_key(column) for column in columns(cipher_texts))
//    for line in cipher_texts:
//        print(xor(key, line))
//
//
//if __name__ == "__main__":
//    challenge20()
