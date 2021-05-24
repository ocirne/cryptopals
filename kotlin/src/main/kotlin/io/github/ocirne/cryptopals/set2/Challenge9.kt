package io.github.ocirne.cryptopals.set2

import io.github.ocirne.cryptopals.Basics.Extensions.padding

fun challenge9(message: String, blockSize: Int): String {
    return message.toByteArray().padding(blockSize).decodeToString()
}
