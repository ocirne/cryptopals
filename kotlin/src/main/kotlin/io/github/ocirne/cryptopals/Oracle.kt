package io.github.ocirne.cryptopals

interface Oracle {

    fun encrypt(pt: ByteArray): ByteArray

    fun decrypt(ct: ByteArray): ByteArray {
        throw NotImplementedError()
    }
}
