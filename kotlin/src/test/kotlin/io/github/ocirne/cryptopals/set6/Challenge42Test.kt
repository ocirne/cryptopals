//
//from cpcrypto import RSA, str_to_int
//
//"00h 01h ffh ... 00h ASN.1 HASH"
//
//message = "hi mom"
//
//
//fun challenge42() {
//    rsa = RSA(128)
//    n = rsa.n
//    // message ** x = ...
//    real_signature = rsa.sign(message)
//    print(real_signature)
//    // signature ** 3 == message .. hash
//    print(rsa.verify(real_signature))
//
//    forged_signature = pow(str_to_int('0001ff'), 3, n)
//    print(rsa.verify(forged_signature))
//
//
//if __name__ == "__main__":
//    challenge42()
