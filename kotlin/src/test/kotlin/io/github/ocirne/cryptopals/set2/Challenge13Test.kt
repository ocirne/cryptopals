package io.github.ocirne.cryptopals.set2

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test


internal class Challenge13Test {

    private val profile = Challenge13Profile()

    private val challenge13 = Challenge13(profile)

    @Test
    fun `can parse key value pairs`() {
        profile.parse("foo=bar&baz=qux&zap=zazzle") shouldBe mapOf("foo" to "bar", "baz" to "qux", "zap" to "zazzle")
    }

    @Test
    fun `can create profile for email`() {
        profile.fromEMail("foo@bar.com") shouldBe "email=foo@bar.com&uid=10&role=user"
    }

    @Test
    fun `can avoid trivial injection`() {
        profile.fromEMail("foo@bar.com&role=admin") shouldBe "email=foo@bar.comroleadmin&uid=10&role=user"
    }

    @Test
    fun `can create admin role`() {
        challenge13.makeAdminRole() shouldBe mapOf("email" to "fofoo@bar.com", "uid" to "10", "role" to "admin")
    }
}
