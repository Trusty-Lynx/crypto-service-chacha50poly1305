package de.trustylynx.security

import de.trustylynx.models.BadRequest
import de.trustylynx.models.WrongService
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class Part(val wire: String) {
    HEAD("h"),
    SECRET("s"),
    DEK("dek"),
}

class Target(val userId: String, val itemId: String?, val part: Part)

// C2 = header || nonce || ChaCha20-Poly1305 ciphertext and tag
object Tlx2 {
    const val KEY_LENGTH = 32
    const val NONCE_LENGTH = 12
    const val MAX_KEY_VERSION = 0xFFFF

    private val MAGIC = byteArrayOf(0x54, 0x4C, 0x58, 0x32) // "TLX2"
    private const val FORMAT_VERSION: Byte = 0x02
    private const val ALG_AES: Byte = 0x01
    private const val ALG_CHACHA: Byte = 0x02
    private const val HEADER_LENGTH = 8 // magic, format version, algorithm, 2 bytes key version
    private const val PAYLOAD_OFFSET = HEADER_LENGTH + NONCE_LENGTH

    // C1 = 01, 01, nonce (12), padding block, tag (16)
    private const val C1_OVERHEAD = 30
    private const val MIN_PADDING_BLOCK = 32
    private const val MAX_PADDING_BLOCK = 65_536
    private const val WDEK_LENGTH = 62

    // header + nonce + tag
    private const val C2_OVERHEAD = 36
    const val MIN_C2_LENGTH = WDEK_LENGTH + C2_OVERHEAD
    const val MAX_C2_LENGTH = MAX_PADDING_BLOCK + C1_OVERHEAD + C2_OVERHEAD

    fun isValidC1(c1: ByteArray, part: Part): Boolean {
        if (c1.size < 2 || c1[0] != 0x01.toByte() || c1[1] != 0x01.toByte()) return false
        if (part == Part.DEK) return c1.size == WDEK_LENGTH
        val block = c1.size - C1_OVERHEAD
        // a power of two has exactly one bit set
        return block in MIN_PADDING_BLOCK..MAX_PADDING_BLOCK && (block and (block - 1)) == 0
    }

    fun keyVersionOf(c2: ByteArray): Int {
        if (c2.size < HEADER_LENGTH || !c2.copyOf(MAGIC.size).contentEquals(MAGIC) || c2[4] != FORMAT_VERSION) {
            throw BadRequest()
        }
        when (c2[5]) {
            ALG_CHACHA -> Unit
            ALG_AES -> throw WrongService()
            else -> throw BadRequest()
        }
        // big endian
        val keyVersion = ((c2[6].toInt() and 0xFF) shl 8) or (c2[7].toInt() and 0xFF)
        if (keyVersion == 0) throw BadRequest()
        return keyVersion
    }

    fun seal(key: ByteArray, keyVersion: Int, nonce: ByteArray, c1: ByteArray, target: Target): ByteArray {
        require(nonce.size == NONCE_LENGTH)
        val header = MAGIC + byteArrayOf(FORMAT_VERSION, ALG_CHACHA, (keyVersion shr 8).toByte(), keyVersion.toByte())
        val cipher = cipher(Cipher.ENCRYPT_MODE, key, nonce, header, target)
        return header + nonce + cipher.doFinal(c1)
    }

    // throws AEADBadTagException if the tag, header or target don't match
    fun open(key: ByteArray, c2: ByteArray, target: Target): ByteArray {
        val header = c2.copyOfRange(0, HEADER_LENGTH)
        val nonce = c2.copyOfRange(HEADER_LENGTH, PAYLOAD_OFFSET)
        val cipher = cipher(Cipher.DECRYPT_MODE, key, nonce, header, target)
        return cipher.doFinal(c2, PAYLOAD_OFFSET, c2.size - PAYLOAD_OFFSET)
    }

    // a new Cipher every time, they aren't thread safe
    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, header: ByteArray, target: Target): Cipher =
        Cipher.getInstance("ChaCha20-Poly1305").apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(aad(header, target))
        }

    // binds the package to its user, item and part, so it can't be moved to another one
    private fun aad(header: ByteArray, target: Target): ByteArray {
        val context = when (target.part) {
            Part.DEK -> "|${target.userId}|dek"
            else -> "|${target.userId}|${target.itemId}|${target.part.wire}"
        }
        return header + context.encodeToByteArray()
    }
}
