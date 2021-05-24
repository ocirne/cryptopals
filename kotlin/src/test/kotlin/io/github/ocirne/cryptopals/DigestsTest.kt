package io.github.ocirne.cryptopals

import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.github.ocirne.cryptopals.Basics.decodeHexString
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
internal class DigestsTest {

    /** see https://en.wikipedia.org/wiki/SHA-1 */
    @Test
    fun `can digest sha1 examples from wikipedia`() {
        sha1.hexdigest("") shouldBe
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha1.hexdigest("The quick brown fox jumps over the lazy dog") shouldBe
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        sha1.hexdigest("The quick brown fox jumps over the lazy cog") shouldBe
                "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
        sha1.hexdigest("Franz jagt im komplett verwahrlosten Taxi quer durch Bayern") shouldBe
                "68ac906495480a3404beee4874ed853a037a7a8f"
        sha1.hexdigest("Granz jagt im komplett verwahrlosten Taxi quer durch Bayern") shouldBe
                "89fdde0b28373dc4f361cfb810b35342cc2c3232"
    }

    /** see https://www.di-mgt.com.au/sha_testvectors.html */
    @Test
    fun `can digest sha1 test vectors`() {
        sha1.hexdigest("abc") shouldBe
                "a9993e364706816aba3e25717850c26c9cd0d89d"
        sha1.hexdigest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") shouldBe
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        sha1.hexdigest("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") shouldBe
                "a49b2446a02c645bf419f995b67091253a04a259"
        sha1.hexdigest("a".repeat(1_000_000)) shouldBe
                "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    }

    /**
     * see https://en.wikipedia.org/wiki/SHA-1
     * see https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data
     */
    @Test
    fun `can digest md5 test vectors`() {
        md5.hexdigest("") shouldBe
                "d41d8cd98f00b204e9800998ecf8427e"
        md5.hexdigest("The quick brown fox jumps over the lazy dog") shouldBe
                "9e107d9d372bb6826bd81d3542a419d6"
        md5.hexdigest("The quick brown fox jumps over the lazy dog.") shouldBe
                "e4d909c290d0fb1ca068ffaddf22cbd0"
        md5.hexdigest("abc") shouldBe
                "900150983cd24fb0d6963f7d28e17f72"
        md5.hexdigest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") shouldBe
                "8215ef0796a20bcaaae116d3876c664a"
        md5.hexdigest("a".repeat(1_000_000)) shouldBe
                "7707d6ae4e027c70eea2a935c2296f21"
    }

    @Test
    fun `can hmac sha1`() {
        hmacSha1("key", "The quick brown fox jumps over the lazy dog") shouldBe
                "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        hmacSha1(decodeHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "Hi There".toByteArray()) shouldBe
                "b617318655057264e28bc0b6fb378c8ef146be00"
        hmacSha1("Jefe", "what do ya want for nothing?") shouldBe
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        hmacSha1(decodeHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0xdd.toByte().repeat(50)) shouldBe
                "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        hmacSha1(decodeHexString("0102030405060708090a0b0c0d0e0f10111213141516171819"), 0xcd.toByte().repeat(50)) shouldBe
                "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        hmacSha1(decodeHexString("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"), "Test With Truncation".toByteArray()) shouldBe
                "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        hmacSha1(0xaa.toByte().repeat(80), "Test Using Larger Than Block-Size Key - Hash Key First".toByteArray()) shouldBe
                "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        hmacSha1(0xaa.toByte().repeat(80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".toByteArray()) shouldBe
                "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        hmacSha1(0xaa.toByte().repeat(80), "Test Using Larger Than Block-Size Key - Hash Key First".toByteArray()) shouldBe
                "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        hmacSha1(0xaa.toByte().repeat(80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".toByteArray()) shouldBe
                "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    }

    @Test
    fun `can hmac md5`() {
        hmacMd5("key", "The quick brown fox jumps over the lazy dog") shouldBe
                "80070713463e7749b90c2dc24911e275"
        hmacMd5(decodeHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "Hi There".toByteArray()) shouldBe
                "9294727a3638bb1c13f48ef8158bfc9d"
        hmacMd5("Jefe", "what do ya want for nothing?") shouldBe
                "750c783e6ab0b503eaa86e310a5db738"
        hmacMd5(decodeHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0xdd.toByte().repeat(50)) shouldBe
                "56be34521d144c88dbb8c733f0e8b3f6"
        hmacMd5(decodeHexString("0102030405060708090a0b0c0d0e0f10111213141516171819"), 0xcd.toByte().repeat(50)) shouldBe
                "697eaf0aca3a3aea3a75164746ffaa79"
        hmacMd5(decodeHexString("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"), "Test With Truncation".toByteArray()) shouldBe
                "56461ef2342edc00f9bab995690efd4c"
        hmacMd5(0xaa.toByte().repeat(80), "Test Using Larger Than Block-Size Key - Hash Key First".toByteArray()) shouldBe
                "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        hmacMd5(0xaa.toByte().repeat(80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".toByteArray()) shouldBe
                "6f630fad67cda0ee1fb1f562db3aa53e"
    }

    fun hmacSha1(key: String, message: String): String {
        return hmacSha1(key.toByteArray(), message.toByteArray())
    }

    fun hmacMd5(key: String, message: String): String {
        return hmacMd5(key.toByteArray(), message.toByteArray())
    }

    companion object {
        val sha1 = SHA1()
        val md5 = MD5()
    }
}
