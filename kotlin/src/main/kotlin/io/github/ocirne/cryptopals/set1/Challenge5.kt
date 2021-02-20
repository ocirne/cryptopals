package io.github.ocirne.cryptopals.set1

import com.google.common.io.BaseEncoding
import kotlin.experimental.xor

class Challenge5 {

    private fun ByteArray.cycle() =
        generateSequence(0) { (it + 1) % this.size }.map() { this[it] }.asIterable()

    fun encrypt(plain: String, key: String): String {
        val plainBa = plain.toByteArray()
        val keyBa = key.toByteArray()
        val cipherBa = plainBa.zip(keyBa.cycle()).map { (c, k) -> c xor k }.toByteArray()
        return BaseEncoding.base16().encode(cipherBa).toLowerCase()
    }
}
