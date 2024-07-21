package io.github.ocirne.cryptopals.set3

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import kotlin.random.Random


internal class Challenge24Test {

//    private val attacker = Challenge24.Attacker()
//
//    @Test
//    fun `can encrypt and decrypt with a Mersenne Twister Stream Cipher`() {
//        val mtsc = Challenge24.MersenneTwisterStreamCipher(42u)
//        val pt = "Ice Ice Baby :)".toByteArray()
//        val ct = mtsc.encrypt(pt)
//        mtsc.decrypt(ct) shouldBe pt
//    }
//
//    @Test
//    fun `can recover seed from password`() {
//        val oracle = Challenge24.RandomPrefixOracle()
//        val plainText = Random.nextBytes(16)
//        val cipherText = oracle.encrypt(plainText)
//        attacker.recoverSeed(cipherText, plainText) shouldBe oracle.seed
//    }
//
//    @Test
//    fun `can check password as prng product`() {
//        val oracle = Challenge24.PasswordResetTokenOracle()
//        val passwordToken = oracle.generatePasswordToken()
//        attacker.recoverTimestamp(passwordToken) shouldBe oracle.seed
//    }
}
