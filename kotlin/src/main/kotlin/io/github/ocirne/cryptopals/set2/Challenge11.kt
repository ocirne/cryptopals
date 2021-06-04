package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics.Extensions.repeat
import io.github.ocirne.cryptopals.Basics.padding
import io.github.ocirne.cryptopals.Oracle
import io.github.ocirne.cryptopals.crypto.AES
import kotlin.random.Random

class Challenge11Oracle(private val modeForTesting: String = "RANDOM"): Oracle {

    override fun encrypt(pt: ByteArray): ByteArray {
        val prefix = Random.nextBytes(Random.nextInt(5, 10))
        val suffix = Random.nextBytes(Random.nextInt(5, 10))
        val padded = padding(prefix + pt + suffix)
        val key = Random.nextBytes(16)
        val mode = if (modeForTesting == "RANDOM") {
            if (Random.nextBoolean()) "ECB" else "CBC"
        } else {
            modeForTesting
        }
        val aes = when (mode) {
            "ECB" ->
                AES.ECB(key)
            "CBC" -> {
                val iv = Random.nextBytes(16)
                AES.CBC(key, iv)
            }
            else -> throw IllegalStateException()
        }
        return aes.encrypt(padded)
    }
}

fun detectMode(oracle: Oracle): String {
    // Why 48?: Make sure that block1 and block2 are all zero
    val content = 0x00.toByte().repeat(48)
    val secret = oracle.encrypt(content)
    val block1 = secret.sliceArray(16..31)
    val block2 = secret.sliceArray(32..47)
    return if (block1.contentEquals(block2)) "ECB" else "CBC"
}
