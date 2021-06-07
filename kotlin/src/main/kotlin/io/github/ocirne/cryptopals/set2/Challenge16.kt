package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Oracle
import io.github.ocirne.cryptopals.crypto.AES
import java.net.URLEncoder
import kotlin.experimental.xor
import kotlin.random.Random

class Challenge16 {

    class CbcPrefixSuffix : Oracle {
        private val key = Random.nextBytes(AES.BLOCK_SIZE)
        private val iv = Random.nextBytes(AES.BLOCK_SIZE)
        private val prefix = "\"comment1=cooking%20MCs;userdata=\""
        private val suffix = "\";comment2=%20like%20a%20pound%20of%20bacon\""
        private val aes = AES.CBC(key, iv)

        override fun encrypt(pt: ByteArray): ByteArray {
            val plaintext = prefix + URLEncoder.encode(String(pt), "UTF-8") + suffix
            return aes.encrypt(plaintext.toByteArray())
        }

        override fun decrypt(ct: ByteArray): ByteArray {
            return aes.decrypt(ct)
        }
    }

    class Judge(val oracle: CbcPrefixSuffix) {

        fun isBroken(ct: ByteArray): Boolean {
            val plaintext = String(oracle.decrypt(ct))
            return plaintext.contains(";admin=true;")
        }
    }

    class Attacker {

        fun modify(ct: ByteArray): ByteArray {
            val mutableCt = ct.copyOf()
            val real = "g%20MCs;user".toByteArray()
            val wish = ";admin=true;".toByteArray()
            real.zip(wish).forEachIndexed { i, (x, y) ->
                mutableCt[i] = mutableCt[i] xor x xor y
            }
            return mutableCt
        }
    }
}
