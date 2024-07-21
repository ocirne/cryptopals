package io.github.ocirne.cryptopals.set4

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
internal class Challenge28Test {

    @Test
    fun `can digest sha1 examples from wikipedia`() {
        sha1.digest("") shouldBe
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha1.digest("The quick brown fox jumps over the lazy dog") shouldBe
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        sha1.digest("The quick brown fox jumps over the lazy cog") shouldBe
                "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
        sha1.digest("Franz jagt im komplett verwahrlosten Taxi quer durch Bayern") shouldBe
                "68ac906495480a3404beee4874ed853a037a7a8f"
        sha1.digest("Granz jagt im komplett verwahrlosten Taxi quer durch Bayern") shouldBe
                "89fdde0b28373dc4f361cfb810b35342cc2c3232"

    }

    /** see https://www.di-mgt.com.au/sha_testvectors.html */
    @Test
    fun `can digest sha1 test vectors`() {
        sha1.digest("abc") shouldBe
                "a9993e364706816aba3e25717850c26c9cd0d89d"
        sha1.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") shouldBe
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        sha1.digest("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") shouldBe
                "a49b2446a02c645bf419f995b67091253a04a259"
        sha1.digest("a".repeat(1_000_000)) shouldBe
                "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    }

    companion object {
        val sha1 = Challenge28.SHA1()
    }
}
