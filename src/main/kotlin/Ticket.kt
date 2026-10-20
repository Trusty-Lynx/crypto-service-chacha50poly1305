package de.trustylynx

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.Signature
import java.time.Instant

private const val SIGNATURE_LENGTH = 64

private val TicketJson = Json { ignoreUnknownKeys = true }

/** Felder des Guard-Tickets. `d` (deviceId) hat der Guard schon geprüft und wird hier ignoriert. */
@Serializable
private class TicketClaims(val u: String, val i: String, val p: String, val exp: Long)

/**
 * Prüft ein Guard-Ticket für das Geheimnis von [target]. Die Signatur wird über die rohen Bytes geprüft,
 * so wie sie ankommen, erst danach wird geparst.
 */
fun isValidTicket(guardPublicKey: PublicKey, ticket: ByteArray, sig: ByteArray, target: Target): Boolean {
    if (sig.size != SIGNATURE_LENGTH || !verifyEd25519(guardPublicKey, ticket, sig)) return false
    val claims = try {
        TicketJson.decodeFromString<TicketClaims>(ticket.decodeToString())
    } catch (_: IllegalArgumentException) {
        return false
    }
    return claims.exp > Instant.now().epochSecond &&
        claims.u == target.userId &&
        claims.i == target.itemId &&
        claims.p == Part.SECRET.wire
}

private fun verifyEd25519(publicKey: PublicKey, data: ByteArray, sig: ByteArray): Boolean = try {
    Signature.getInstance("Ed25519").run {
        initVerify(publicKey)
        update(data)
        verify(sig)
    }
} catch (_: GeneralSecurityException) {
    false
}
