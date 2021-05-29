package io.github.ocirne.cryptopals.crypto

import io.github.ocirne.cryptopals.Basics.Extensions.chunked
import io.github.ocirne.cryptopals.Basics.Extensions.concatenate
import io.github.ocirne.cryptopals.Basics.padding
import io.github.ocirne.cryptopals.Basics.stripPadding
import io.github.ocirne.cryptopals.Basics.xor
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object AES {

    const val BLOCK_SIZE = 16

    interface AESVariant {
        fun encrypt(pt: ByteArray): ByteArray

        fun decrypt(ct: ByteArray): ByteArray
    }

    private class SingleBlockCipher(key: ByteArray): AESVariant {
        private val cipher = Cipher.getInstance("AES/ECB/NoPadding")!!
        private val secretKey = SecretKeySpec(key, "AES")

        override fun encrypt(pt: ByteArray): ByteArray {
            require(pt.size == BLOCK_SIZE) { "plain text block muss 16 Byte lang sein" }
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher.doFinal(pt)
        }

        override fun decrypt(ct: ByteArray): ByteArray {
            require(ct.size == BLOCK_SIZE) { "cipher text block muss 16 Byte lang sein" }
            cipher.init(Cipher.DECRYPT_MODE, secretKey)
            return cipher.doFinal(ct)
        }
    }

    class ECB(val key: ByteArray): AESVariant {
        private val blockCipher = SingleBlockCipher(key)

        override fun encrypt(pt: ByteArray): ByteArray {
            return padding(pt).chunked(BLOCK_SIZE).map(blockCipher::encrypt).concatenate()
        }

        override fun decrypt(ct: ByteArray): ByteArray {
            return stripPadding(ct.chunked(BLOCK_SIZE).map(blockCipher::decrypt).concatenate())
        }
    }

    class CBC(val key : ByteArray, val iv: ByteArray): AESVariant {
        private val blockCipher = SingleBlockCipher(key)

        override fun encrypt(pt: ByteArray): ByteArray {
            var x = iv
            var ct = byteArrayOf()
            padding(pt).chunked(BLOCK_SIZE).forEach { ptChunk ->
                val ctChunk = blockCipher.encrypt(xor(ptChunk, x))
                ct += ctChunk
                x = ctChunk
            }
            return ct
        }

        override fun decrypt(ct: ByteArray): ByteArray {
            var x = iv
            var pt = byteArrayOf()
            ct.chunked(BLOCK_SIZE).forEach { ctChunk ->
                val ptChunk = blockCipher.decrypt(ctChunk)
                pt += xor(ptChunk, x)
                x = ctChunk
            }
            return stripPadding(pt)
        }
    }
}
