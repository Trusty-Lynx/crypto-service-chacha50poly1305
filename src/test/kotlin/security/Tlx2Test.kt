package de.trustylynx.security

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals

// test vectors from the encryption doc (V10)
object Vectors {
    val K_CHACHA = "d904d3354ad5958cd4c714ef5cb5ca727b48614cab801010737ca5f91485641f".hexToByteArray()
    val N2 = "b4543fabe6f0040620b7fae6".hexToByteArray()
    const val C1 = "AQGElC3c4+PdZNooknZHuCveKBxC6pGXVPRxFb4lPO02949d7a5MrDAmYHiv4c7QGpYb5PtXMFFQqMW/L8M="
    const val C2 = "VExYMgICAAG0VD+r5vAEBiC3+uY3eHa2Y4baCW/Bs8r+glSo7jHYKEBu70/92N/4Vw29+5GZvz97knOkOdVTTaQB9UmBOpvFcfSAKEA9q2LevOGZtPXTwGvUhvPU4KWR+aM="
    const val C2_AES = "VExYMgIBAAHXZpAF8a91fTDcVLBKvMN9+2A/f4nQFrNv1uwEPEqKZSvmEOW+/6sxdWKU0CufByhv0YvQkXKX3Hcd9y7hZdGJ7vdC8YyMh+1gOAXEcPhe8DR8gsnXmH1qJsg="
    const val WDEK = "AQEA1JytCV1eYKpbGR0m0hQb80PBumWOHfs301ZuRzz1ORTyX3u4BPGZtZPizSOFawqTV2xY3PObZQhL2Dk="
}

fun String.base64(): ByteArray = Base64.getDecoder().decode(this)

class Tlx2Test {
    private val target = Target("u42", "i7", Part.SECRET)

    @Test
    fun `T1 seal with the test vector gives exactly the vector C2`() {
        val c2 = Tlx2.seal(Vectors.K_CHACHA, 1, Vectors.N2, Vectors.C1.base64(), target)
        assertContentEquals(Vectors.C2.base64(), c2)
    }

    @Test
    fun `open reverses the test vector`() {
        assertContentEquals(Vectors.C1.base64(), Tlx2.open(Vectors.K_CHACHA, Vectors.C2.base64(), target))
    }
}
