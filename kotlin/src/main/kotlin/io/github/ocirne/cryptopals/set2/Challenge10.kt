package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics
import io.github.ocirne.cryptopals.Basics.xor
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

fun aesEcbBlockDecrypt(pt: ByteArray, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    val secretKey = SecretKeySpec(key, "AES")
    cipher.init(Cipher.DECRYPT_MODE, secretKey)
    return cipher.doFinal(pt)
}

fun challenge10(message: String, key: String, iv: ByteArray): String {
    val secret = Basics.decodeFromBase64(message)
    var x = iv
    var result = byteArrayOf()
    secret.asIterable().chunked(16).forEach { ct ->
        val pt = aesEcbBlockDecrypt(ct.toByteArray(), key.toByteArray())
        result += xor(pt, x)
        x = ct.toByteArray()
    }
    return String(result)
}
