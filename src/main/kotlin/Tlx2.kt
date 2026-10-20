package de.trustylynx

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class Part(val wire: String) {
    HEAD("h"),
    SECRET("s"),
    DEK("dek"),
}

/** Wem ein Paket gehört. Steht in der AAD, ein falscher Wert lässt den Tag scheitern. */
class Target(val userId: String, val itemId: String?, val part: Part)

/**
 * Paketformat „TLX2“, Schicht 2 mit ChaCha20-Poly1305:
 * `C2 = hdr ‖ n2 ‖ ChaCha20-Poly1305(K_chacha, n2, C1, aad)`, `hdr = "TLX2" ‖ 02 ‖ 02 ‖ Key-Version (BE)`.
 */
object Tlx2 {
    const val KEY_LENGTH = 32
    const val NONCE_LENGTH = 12
    const val MAX_KEY_VERSION = 0xFFFF

    private val MAGIC = byteArrayOf(0x54, 0x4C, 0x58, 0x32)
    private const val FORMAT_VERSION: Byte = 0x02
    private const val ALG_AES: Byte = 0x01
    private const val ALG_CHACHA: Byte = 0x02
    private const val HEADER_LENGTH = 8
    private const val PAYLOAD_OFFSET = HEADER_LENGTH + NONCE_LENGTH

    /** C1 = 01 ‖ 01 ‖ n1 (12) ‖ Padding-Block ‖ Tag (16). */
    private const val C1_OVERHEAD = 30
    private const val MIN_PADDING_BLOCK = 32
    private const val MAX_PADDING_BLOCK = 65_536
    private const val WDEK_LENGTH = 62

    /** Header + Nonce + Tag. */
    private const val C2_OVERHEAD = 36
    const val MIN_C2_LENGTH = WDEK_LENGTH + C2_OVERHEAD
    const val MAX_C2_LENGTH = MAX_PADDING_BLOCK + C1_OVERHEAD + C2_OVERHEAD

    fun isValidC1(c1: ByteArray, part: Part): Boolean {
        if (c1.size < 2 || c1[0] != 0x01.toByte() || c1[1] != 0x01.toByte()) return false
        if (part == Part.DEK) return c1.size == WDEK_LENGTH
        val block = c1.size - C1_OVERHEAD
        return block in MIN_PADDING_BLOCK..MAX_PADDING_BLOCK && (block and (block - 1)) == 0
    }

    /**
     * Prüft Magic, Format-Version und Algorithmus-Byte und liefert die Key-Version aus Byte 6–7.
     * Ein Paket von Crypto-Service 1 (AES) gibt [WrongService], alles Unbekannte [BadRequest].
     */
    fun keyVersionOf(c2: ByteArray): Int {
        if (c2.size < HEADER_LENGTH || !c2.copyOf(MAGIC.size).contentEquals(MAGIC) || c2[4] != FORMAT_VERSION) {
            throw BadRequest()
        }
        when (c2[5]) {
            ALG_CHACHA -> Unit
            ALG_AES -> throw WrongService()
            else -> throw BadRequest()
        }
        val keyVersion = ((c2[6].toInt() and 0xFF) shl 8) or (c2[7].toInt() and 0xFF)
        if (keyVersion == 0) throw BadRequest()
        return keyVersion
    }

    fun seal(key: ByteArray, keyVersion: Int, nonce: ByteArray, c1: ByteArray, target: Target): ByteArray {
        require(nonce.size == NONCE_LENGTH)
        val hdr = MAGIC + byteArrayOf(FORMAT_VERSION, ALG_CHACHA, (keyVersion shr 8).toByte(), keyVersion.toByte())
        val cipher = cipher(Cipher.ENCRYPT_MODE, key, nonce, hdr, target)
        return hdr + nonce + cipher.doFinal(c1)
    }

    /** Wirft [javax.crypto.AEADBadTagException], wenn Tag, Header oder [target] nicht passen. */
    fun open(key: ByteArray, c2: ByteArray, target: Target): ByteArray {
        val hdr = c2.copyOfRange(0, HEADER_LENGTH)
        val nonce = c2.copyOfRange(HEADER_LENGTH, PAYLOAD_OFFSET)
        val cipher = cipher(Cipher.DECRYPT_MODE, key, nonce, hdr, target)
        return cipher.doFinal(c2, PAYLOAD_OFFSET, c2.size - PAYLOAD_OFFSET)
    }

    /** Für jede Operation eine neue Instanz. */
    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, hdr: ByteArray, target: Target): Cipher =
        Cipher.getInstance("ChaCha20-Poly1305").apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(aad(hdr, target))
        }

    private fun aad(hdr: ByteArray, target: Target): ByteArray {
        val context = when (target.part) {
            Part.DEK -> "|${target.userId}|dek"
            else -> "|${target.userId}|${target.itemId}|${target.part.wire}"
        }
        return hdr + context.encodeToByteArray()
    }
}
