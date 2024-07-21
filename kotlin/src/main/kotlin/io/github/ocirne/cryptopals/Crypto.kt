//import sys
//
//from cryptopals.math import invmod, random_prime
//
//
//fun str_to_int(s: str):int:
//    b = ByteArray(s, "UTF-8")
//    return int.from_ByteArray(b, sys.byteorder)
//
//
//fun int_to_str(i: int):str:
//    b = i.to_ByteArray(16, sys.byteorder)
//    return b.decode("UTF-8").strip("\x00")
//
//
//class RSA {
//
//    fun __init__(s: Int = 128) {
//        var d = null
//        while d is None:
//            p = random_prime(s)
//            q = random_prime(s)
//            n = p * q
//            et = (p - 1) * (q - 1)
//            // public key :[e, n]
//            e = 3
//            // private key :[d, n]
//            d = invmod(e, et)
//    }
//
//    fun publicKey() {
//        return e, n
//    }
//
//    fun _encrypt(m: int): int {
//        return pow(m, e, n)
//    }
//
//    fun _decrypt(c: int): int {
//        return pow(c, d, n)
//    }
//
//    fun encrypt(p: String): Int {
//        return _encrypt(str_to_int(p))
//    }
//
//    fun decrypt(c: Int): String {
//        return int_to_str(_decrypt(c))
//    }
//
//    fun sign(message: String): Int {
//        return _decrypt(str_to_int("0001ff" + message))
//    }
//
//    fun verify(signature: Int): Boolean {
//        val message = int_to_str(_encrypt(signature))
//        return message.startswith("0001ff")
//    }