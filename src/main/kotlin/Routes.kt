package de.trustylynx

import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.utils.io.readBuffer
import kotlinx.io.readByteArray
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

const val SERVICE_TOKEN_HEADER = "X-Service-Token"

private const val MAX_BODY_BYTES = 256 * 1024L

/** Erlaubte Zeichen für `userId` und `itemId`. Ohne `|` kann niemand die AAD verfälschen. */
private val ID_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")

private val audit = LoggerFactory.getLogger("audit")

/** Unbekannte Felder im Body werden ignoriert, nicht abgelehnt. */
private val RequestJson = Json { ignoreUnknownKeys = true }

@Serializable
data class EncryptRequest(val userId: String, val itemId: String? = null, val part: String, val c1: String) {
    override fun toString(): String = "EncryptRequest(userId=$userId, itemId=$itemId, part=$part)"
}

@Serializable
data class EncryptResponse(val c2: String) {
    override fun toString(): String = "EncryptResponse"
}

@Serializable
data class DecryptRequest(val userId: String, val itemId: String? = null, val part: String, val c2: String) {
    override fun toString(): String = "DecryptRequest(userId=$userId, itemId=$itemId, part=$part)"
}

@Serializable
data class DecryptResponse(val c1: String) {
    override fun toString(): String = "DecryptResponse"
}

@Serializable
data class HealthResponse(val status: String)

fun Route.cryptoRoutes(config: AppConfig, keys: KeyProvider) {
    val vaultToken = config.vaultServiceToken.encodeToByteArray()
    val random = SecureRandom()

    get("/health") {
        call.respond(HealthResponse("ok"))
    }

    post("/internal/encrypt") {
        call.requireServiceToken(vaultToken)
        val request = call.receiveJson<EncryptRequest>()
        val target = target(request.userId, request.itemId, request.part)
        val c1 = request.c1.decodeBase64OrNull()?.takeIf { Tlx2.isValidC1(it, target.part) } ?: throw BadRequest()
        val nonce = ByteArray(Tlx2.NONCE_LENGTH).also(random::nextBytes)
        val c2 = keys.withKey(target.userId, version = null) { key, version ->
            Tlx2.seal(key, version, nonce, c1, target)
        }
        call.respond(EncryptResponse(c2.toBase64()))
    }

    post("/internal/decrypt") {
        var request: DecryptRequest? = null
        val c1 = try {
            call.requireServiceToken(vaultToken)
            request = call.receiveJson<DecryptRequest>()
            decrypt(request, keys)
        } catch (e: Throwable) {
            audit.warn(
                "decrypt failed userId={} itemId={} part={} error={}",
                forLog(request?.userId), forLog(request?.itemId), forLog(request?.part),
                (e as? ApiException)?.code ?: INTERNAL_ERROR,
            )
            throw e
        }
        call.respond(DecryptResponse(c1.toBase64()))
    }
}

/** Reihenfolge ist Pflicht: erst Body, dann Header, erst danach den Schlüssel holen. */
private suspend fun decrypt(request: DecryptRequest, keys: KeyProvider): ByteArray {
    val target = target(request.userId, request.itemId, request.part)
    val c2 = request.c2.decodeBase64OrNull()
        ?.takeIf { it.size in Tlx2.MIN_C2_LENGTH..Tlx2.MAX_C2_LENGTH }
        ?: throw BadRequest()
    val keyVersion = Tlx2.keyVersionOf(c2)
    return keys.withKey(target.userId, keyVersion) { key, _ ->
        try {
            Tlx2.open(key, c2, target)
        } catch (_: AEADBadTagException) {
            throw IntegrityError()
        }
    }
}

/** Holt K_chacha, prüft die Antwort und überschreibt den Schlüssel nach [block] mit Nullen. */
private suspend inline fun <T> KeyProvider.withKey(
    userId: String,
    version: Int?,
    block: (key: ByteArray, version: Int) -> T,
): T {
    val derived = derive(userId, version)
    try {
        val usable = derived.key.size == Tlx2.KEY_LENGTH &&
            derived.version in 1..Tlx2.MAX_KEY_VERSION &&
            (version == null || derived.version == version)
        if (!usable) {
            throw KeyServiceException(
                "key-service derive returned ${derived.key.size} bytes for version ${derived.version}, requested $version",
            )
        }
        return block(derived.key, derived.version)
    } finally {
        derived.key.fill(0)
    }
}

private fun target(userId: String, itemId: String?, part: String): Target {
    val p = Part.entries.firstOrNull { it.wire == part } ?: throw BadRequest()
    val itemIdValid = if (p == Part.DEK) itemId == null else itemId != null && ID_PATTERN.matches(itemId)
    if (!ID_PATTERN.matches(userId) || !itemIdValid) throw BadRequest()
    return Target(userId, itemId, p)
}

private fun ApplicationCall.requireServiceToken(expected: ByteArray) {
    val provided = request.headers[SERVICE_TOKEN_HEADER]?.encodeToByteArray() ?: throw Unauthorized()
    if (!MessageDigest.isEqual(expected, provided)) throw Unauthorized()
}

private suspend inline fun <reified T> ApplicationCall.receiveJson(): T {
    val body = receiveChannel().readBuffer(MAX_BODY_BYTES + 1).readByteArray()
    if (body.size > MAX_BODY_BYTES) throw PayloadTooLarge()
    return try {
        RequestJson.decodeFromString<T>(body.decodeToString())
    } catch (_: IllegalArgumentException) {
        throw BadRequest()
    }
}

/** Nur geprüfte Zeichen ins Audit-Log, sonst `-`. */
private fun forLog(value: String?): String = value?.takeIf { ID_PATTERN.matches(it) } ?: "-"
