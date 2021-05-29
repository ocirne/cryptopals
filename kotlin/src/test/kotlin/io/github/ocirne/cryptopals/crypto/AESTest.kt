package io.github.ocirne.cryptopals.crypto

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import kotlin.random.Random

internal class AESTest {

    private val key = Random.nextBytes(16)
    private val iv = Random.nextBytes(16)

    @Test
    fun `Test AES ECB one block`() {
        assertEncryptionCycle(AES.ECB(key), "foo")
    }

    @Test
    fun `Test AES ECB two blocks block`() {
        assertEncryptionCycle(AES.ECB(key), "We all live in a yellow submarine ...")
    }

    @Test
    fun `Test AES CBC one block`() {
        assertEncryptionCycle(AES.CBC(key, iv), "foo")
    }

    @Test
    fun `Test AES CBC two blocks block`() {
        assertEncryptionCycle(AES.CBC(key, iv), "We all live in a yellow submarine ...")
    }

    private fun assertEncryptionCycle(cipher: AES.AESVariant, content: String) {
        val ct = cipher.encrypt(content.toByteArray())
        val pt = cipher.decrypt(ct)
        String(pt) shouldBe content
    }
}
