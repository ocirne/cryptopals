//package io.github.ocirne.cryptopals
//
//import io.kotest.matchers.shouldBe
//import org.junit.jupiter.api.Test
//
//internal class CryptoTest {
//
//    @Test
//    fun `test rsa variants`() {
//        rsa._decrypt(rsa._encrypt(42)) shouldBe 42
//        rsa._encrypt(rsa._decrypt(42)) shouldBe 42
//        rsa.verify(rsa.sign("foo")) shouldBe true
//        rsa.verify(rsa.sign("bar")) shouldBe true
//    }
//
//    companion object {
//        val rsa = RSA()
//    }
//}
