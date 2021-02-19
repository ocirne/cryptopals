package io.github.ocirne.cryptopals.set1

import com.google.common.io.BaseEncoding
import java.util.Base64

class Challenge1 {

    fun hexToBase64(hexString: String): String {
        val byteArray = BaseEncoding.base16().decode(hexString.toUpperCase())
        return Base64.getEncoder().encodeToString(byteArray)
    }
}