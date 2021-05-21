package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import org.junit.jupiter.api.Test

internal class Challenge6Test {

    companion object {
        private val content = this::class.java.classLoader.getResource("set1/6.txt")!!.readText()
        private const val key = "Terminator X: Bring the noise"
        private val challenge6 = Challenge6(content)
    }

    @Test
    fun `can decrypt`() {
        challenge6.decrypt(key) shouldStartWith "I'm back and I'm ringin' the bell"
    }

    @Test
    fun `reproduce example hamming distance`() {
        val t1 = "this is a test".toByteArray()
        val t2 = "wokka wokka!!!".toByteArray()

        Basics.hammingDistance(t1, t2) shouldBe 37
    }

    @Test
    fun `can cheap factorize number`() {
        challenge6.cheapFactor(42) shouldBe listOf(2, 3, 7)
        challenge6.cheapFactor(91) shouldBe listOf(7, 13)
    }

    @Test
    fun `can detect common distance`() {
        challenge6.getCommonDistance() shouldBe 29
    }

    @Test
    fun `can find key`() {
        challenge6.findKey(29) shouldBe key
    }
}
