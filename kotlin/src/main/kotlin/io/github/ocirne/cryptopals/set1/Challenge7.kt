package io.github.ocirne.cryptopals.set1

import io.github.ocirne.cryptopals.Basics
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Challenge7 {

    fun run(content: String, key: String): String {
        val secret = Basics.decodeFromBase64(content)
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val secretKey = SecretKeySpec(key.toByteArray(), "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return String(cipher.doFinal(secret))
    }
}
