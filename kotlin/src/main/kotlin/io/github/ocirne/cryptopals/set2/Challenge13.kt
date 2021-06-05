package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.crypto.AES
import kotlin.random.Random

class Challenge13Profile {

    private val key = Random.nextBytes(AES.BLOCK_SIZE)

    private val aes = AES.ECB(key)

    fun parse(cookie: String): Map<String, String> {
        return cookie.split("&")
            .map { pair -> pair.split("=") }
            .associate { (key, value) -> key to value }
    }

    fun fromEMail(email: String): String {
        val cleanEMail = email.replace("&", "").replace("=", "")
        return "email=${cleanEMail}&uid=10&role=user"
    }

    fun encrypt(emailAddress: String): ByteArray {
        val profile = fromEMail(emailAddress)
        return aes.encrypt(profile.toByteArray())
    }

    fun decrypt(ct: ByteArray): Map<String, String> {
        val plain = String(aes.decrypt(ct))
        return parse(plain)
    }
}

class Challenge13(private val profile: Challenge13Profile) {

    fun makeAdminRole(): Map<String, String> {
        // Block 1: 'email=fofoo@bar.com.....role='
        val roleBlock = profile.encrypt("fofoo@bar.com").sliceArray(0..31)
        // Block 2: 'admin...' with fake padding
        val adminBlock = profile.encrypt("1234567890admin" + "\u000b".repeat(11)).slice(16..31)
        return profile.decrypt(roleBlock + adminBlock)
    }
}
