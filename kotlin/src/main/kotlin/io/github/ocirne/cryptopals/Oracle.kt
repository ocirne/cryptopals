package io.github.ocirne.cryptopals

interface Oracle {

    fun encrypt(pt: ByteArray): ByteArray
}
