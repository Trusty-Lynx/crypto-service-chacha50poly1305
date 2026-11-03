package de.trustylynx

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import de.trustylynx.clients.DerivedKey
import de.trustylynx.clients.KeyProvider
import de.trustylynx.models.DecryptRequest
import de.trustylynx.models.DecryptResponse
import de.trustylynx.models.EncryptRequest
import de.trustylynx.models.EncryptResponse
import de.trustylynx.security.Part
import de.trustylynx.security.Target
import de.trustylynx.security.Tlx2
import de.trustylynx.security.Vectors
import de.trustylynx.security.base64
import de.trustylynx.security.toBase64
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import org.slf4j.LoggerFactory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private const val VAULT_TOKEN = "test-vault-token"
private const val MAX_BODY_BYTES = 256 * 1024

private fun requestBody(field: String, value: String, userId: String, itemId: String?, part: String): String {
    val item = if (itemId == null) "" else """"itemId":"$itemId","""
    return """{"userId":"$userId",$item"part":"$part","$field":"$value"}"""
}

private fun encryptBody(c1: String = Vectors.C1, userId: String = "u42", itemId: String? = "i7", part: String = "s") =
    requestBody("c1", c1, userId, itemId, part)

private fun decryptBody(c2: String = Vectors.C2, userId: String = "u42", itemId: String? = "i7", part: String = "s") =
    requestBody("c2", c2, userId, itemId, part)

private fun packageOf(size: Int, magic: Byte = 0x54, format: Byte = 0x02, alg: Byte = 0x02, version: Int = 1): String {
    val bytes = ByteArray(size)
    byteArrayOf(magic, 0x4C, 0x58, 0x32, format, alg, (version shr 8).toByte(), version.toByte())
        .copyInto(bytes)
    return bytes.toBase64()
}

private fun c1OfSize(size: Int, first: Byte = 0x01, second: Byte = 0x01): String {
    val bytes = ByteArray(size)
    bytes[0] = first
    bytes[1] = second
    return bytes.toBase64()
}

private class RecordingKeyProvider : KeyProvider {
    val requestedVersions = mutableListOf<Int?>()
    val requestedUsers = mutableListOf<String>()
    val handedOutKeys = mutableListOf<ByteArray>()
    var answer: (Int?) -> DerivedKey = { version -> DerivedKey(Vectors.K_CHACHA.copyOf(), version ?: 1) }

    override suspend fun derive(userId: String, version: Int?): DerivedKey {
        requestedUsers += userId
        requestedVersions += version
        return answer(version).also { handedOutKeys += it.key }
    }
}

private class EndpointEnv(
    private val client: HttpClient,
    val keys: RecordingKeyProvider,
    private val audit: ListAppender<ILoggingEvent>,
    private val root: ListAppender<ILoggingEvent>,
) {
    val auditLines: List<String> get() = audit.list.map { it.formattedMessage }

    val errorLogs: List<ILoggingEvent> get() = root.list.filter { it.level.levelStr == "ERROR" }

    suspend fun get(path: String): HttpResponse = client.get(path)

    suspend fun post(path: String, body: String, token: String? = VAULT_TOKEN, json: Boolean = true): HttpResponse =
        client.post(path) {
            if (token != null) header("X-Service-Token", token)
            if (json) contentType(ContentType.Application.Json)
            setBody(body)
        }

    suspend fun encrypt(body: String, token: String? = VAULT_TOKEN) = post("/internal/encrypt", body, token)

    suspend fun decrypt(body: String, token: String? = VAULT_TOKEN) = post("/internal/decrypt", body, token)

    suspend fun assertRejected(response: HttpResponse, status: HttpStatusCode, code: String, case: String = "") {
        assertEquals(status, response.status, case)
        assertEquals("""{"error":"$code"}""", response.bodyAsText(), case)
        assertEquals("application/json", response.headers["Content-Type"], case)
    }

    fun assertNoKeyRequested(case: String = "") = assertEquals(emptyList(), keys.requestedVersions, case)
}

private fun endpointTest(block: suspend EndpointEnv.() -> Unit) = testApplication {
    environment { config = MapApplicationConfig() }
    val keys = RecordingKeyProvider()
    application { configureApp(AppConfig(VAULT_TOKEN, "test-chacha-token", null), keys) }

    val audit = ListAppender<ILoggingEvent>().apply { start() }
    val auditLogger = LoggerFactory.getLogger("audit") as Logger
    auditLogger.addAppender(audit)
    val root = ListAppender<ILoggingEvent>().apply { start() }
    val rootLogger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
    rootLogger.addAppender(root)
    try {
        EndpointEnv(client, keys, audit, root).block()
    } finally {
        auditLogger.detachAppender(audit)
        rootLogger.detachAppender(root)
    }
}

class CryptoEndpointsTest {
    private val invalidTargets = mapOf(
        "unknown part" to Triple("u42", "i7", "x"),
        "s without itemId" to Triple("u42", null, "s"),
        "h without itemId" to Triple("u42", null, "h"),
        "dek with itemId" to Triple("u42", "i7", "dek"),
        "userId with a pipe" to Triple("u|42", "i7", "s"),
        "empty userId" to Triple("", "i7", "s"),
        "userId too long" to Triple("u".repeat(129), "i7", "s"),
        "itemId with a pipe" to Triple("u42", "i|7", "s"),
        "empty itemId" to Triple("u42", "", "s"),
        "itemId too long" to Triple("u42", "i".repeat(129), "s"),
    )

    @Test
    fun `health answers without a token`() = endpointTest {
        val response = get("/health")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("""{"status":"ok"}""", response.bodyAsText())
        assertEquals("application/json", response.headers["Content-Type"])
    }

    @Test
    fun `decrypt restores C1 from the test vector`() = endpointTest {
        val response = decrypt(decryptBody())
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("""{"c1":"${Vectors.C1}"}""", response.bodyAsText())
        assertEquals("application/json", response.headers["Content-Type"])
        assertEquals(listOf<Int?>(1), keys.requestedVersions)
        assertEquals(listOf("u42"), keys.requestedUsers)
        assertTrue(auditLines.isEmpty())
    }

    @Test
    fun `encrypt and decrypt round trip for every part`() = endpointTest {
        val cases = listOf(
            Triple("h", "i7", Vectors.C1),
            Triple("s", "i7", Vectors.C1),
            Triple("dek", null, Vectors.WDEK),
        )
        cases.forEach { (part, itemId, c1) ->
            val encrypted = encrypt(encryptBody(c1 = c1, itemId = itemId, part = part))
            assertEquals(HttpStatusCode.OK, encrypted.status, part)
            assertEquals("application/json", encrypted.headers["Content-Type"], part)
            val text = encrypted.bodyAsText()
            assertTrue(text.startsWith("""{"c2":"VExYMgIC"""), text)
            assertTrue(text.endsWith("\"}"), text)
            val c2 = text.removePrefix("""{"c2":"""").removeSuffix("\"}")
            assertEquals(c1.base64().size + 36, c2.base64().size, part)

            val decrypted = decrypt(decryptBody(c2 = c2, itemId = itemId, part = part))
            assertEquals(HttpStatusCode.OK, decrypted.status, part)
            assertEquals("""{"c1":"$c1"}""", decrypted.bodyAsText(), part)
        }
    }

    @Test
    fun `encrypting twice gives two different packages`() = endpointTest {
        val first = encrypt(encryptBody()).bodyAsText()
        val second = encrypt(encryptBody()).bodyAsText()
        assertNotEquals(first, second)
    }

    @Test
    fun `encrypt asks for the current key and writes its version into the header`() = endpointTest {
        keys.answer = { DerivedKey(Vectors.K_CHACHA.copyOf(), 0x0102) }
        val text = encrypt(encryptBody()).bodyAsText()
        val c2 = text.removePrefix("""{"c2":"""").removeSuffix("\"}").base64()
        assertEquals(listOf<Int?>(null), keys.requestedVersions)
        assertContentEquals(byteArrayOf(0x01, 0x02), c2.copyOfRange(6, 8))
    }

    @Test
    fun `decrypt asks for the key version from the header`() = endpointTest {
        val response = decrypt(decryptBody(c2 = packageOf(98, version = 0x0103)))
        assertRejected(response, HttpStatusCode.InternalServerError, "integrity_error")
        assertEquals(listOf<Int?>(0x0103), keys.requestedVersions)
    }

    @Test
    fun `the key is wiped after every use`() = endpointTest {
        encrypt(encryptBody())
        decrypt(decryptBody())
        decrypt(decryptBody(c2 = packageOf(98)))
        keys.answer = { DerivedKey(ByteArray(31) { 7 }, 1) }
        encrypt(encryptBody())

        assertEquals(4, keys.handedOutKeys.size)
        keys.handedOutKeys.forEach { key -> assertTrue(key.all { it == 0.toByte() }) }
    }

    @Test
    fun `a missing or wrong token is rejected`() = endpointTest {
        listOf(null, "wrong-token", "").forEach { token ->
            assertRejected(encrypt(encryptBody(), token), HttpStatusCode.Unauthorized, "unauthorized")
            assertRejected(decrypt(decryptBody(), token), HttpStatusCode.Unauthorized, "unauthorized")
        }
        assertNoKeyRequested()
    }

    @Test
    fun `the token is checked before the body`() = endpointTest {
        assertRejected(encrypt("not json", token = null), HttpStatusCode.Unauthorized, "unauthorized")
        assertRejected(decrypt("not json", token = null), HttpStatusCode.Unauthorized, "unauthorized")
        val tooLarge = " ".repeat(MAX_BODY_BYTES + 1)
        assertRejected(encrypt(tooLarge, token = null), HttpStatusCode.Unauthorized, "unauthorized")
        assertRejected(decrypt(tooLarge, token = null), HttpStatusCode.Unauthorized, "unauthorized")
    }

    @Test
    fun `a body of exactly the limit passes and one byte more is too large`() = endpointTest {
        val encryptAtLimit = encryptBody().padEnd(MAX_BODY_BYTES)
        assertEquals(HttpStatusCode.OK, encrypt(encryptAtLimit).status)
        assertRejected(encrypt(encryptAtLimit + " "), HttpStatusCode.PayloadTooLarge, "payload_too_large")

        val decryptAtLimit = decryptBody().padEnd(MAX_BODY_BYTES)
        assertEquals(HttpStatusCode.OK, decrypt(decryptAtLimit).status)
        assertRejected(decrypt(decryptAtLimit + " "), HttpStatusCode.PayloadTooLarge, "payload_too_large")
    }

    @Test
    fun `a broken body is a bad request`() = endpointTest {
        val bodies = listOf(
            "",
            "not json",
            "{}",
            "[]",
            """{"userId":"u42","itemId":"i7","part":"s"}""",
            """{"userId":42,"itemId":"i7","part":"s","c1":"${Vectors.C1}","c2":"${Vectors.C2}"}""",
        )
        bodies.forEach { body ->
            assertRejected(encrypt(body), HttpStatusCode.BadRequest, "bad_request", body)
            assertRejected(decrypt(body), HttpStatusCode.BadRequest, "bad_request", body)
        }
        assertNoKeyRequested()
    }

    @Test
    fun `unknown fields in the body are ignored`() = endpointTest {
        val encrypted = encrypt("""{"legacy":"old","userId":"u42","itemId":"i7","part":"s","c1":"${Vectors.C1}"}""")
        assertEquals(HttpStatusCode.OK, encrypted.status)
        val decrypted = decrypt("""{"legacy":"old","userId":"u42","itemId":"i7","part":"s","c2":"${Vectors.C2}"}""")
        assertEquals(HttpStatusCode.OK, decrypted.status)
    }

    @Test
    fun `a dek target may send itemId as null`() = endpointTest {
        val response = encrypt("""{"userId":"u42","itemId":null,"part":"dek","c1":"${Vectors.WDEK}"}""")
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `the content type of the request doesn't matter`() = endpointTest {
        val response = post("/internal/encrypt", encryptBody(), json = false)
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `ids of 128 allowed characters pass`() = endpointTest {
        val id = "aZ0._-".repeat(22).take(128)
        assertEquals(HttpStatusCode.OK, encrypt(encryptBody(userId = id, itemId = id)).status)
    }

    @Test
    fun `an invalid target is a bad request before any key is requested`() = endpointTest {
        invalidTargets.forEach { (case, target) ->
            val (userId, itemId, part) = target
            val c1 = if (part == "dek") Vectors.WDEK else Vectors.C1
            assertRejected(encrypt(encryptBody(c1, userId, itemId, part)), HttpStatusCode.BadRequest, "bad_request", case)
            assertRejected(decrypt(decryptBody(Vectors.C2, userId, itemId, part)), HttpStatusCode.BadRequest, "bad_request", case)
        }
        assertNoKeyRequested()
    }

    @Test
    fun `an invalid C1 is a bad request before any key is requested`() = endpointTest {
        val cases = mapOf(
            "not base64" to encryptBody(c1 = "!!!!"),
            "length not a multiple of 4" to encryptBody(c1 = Vectors.C1.dropLast(1)),
            "empty" to encryptBody(c1 = ""),
            "one byte" to encryptBody(c1 = "AQ=="),
            "wrong first byte" to encryptBody(c1 = c1OfSize(62, first = 0x02)),
            "wrong second byte" to encryptBody(c1 = c1OfSize(62, second = 0x02)),
            "padding block below the minimum" to encryptBody(c1 = c1OfSize(30 + 16)),
            "padding block not a power of two" to encryptBody(c1 = c1OfSize(30 + 33)),
            "padding block above the maximum" to encryptBody(c1 = c1OfSize(30 + 131_072)),
            "dek of the wrong size" to encryptBody(c1 = c1OfSize(30 + 64), itemId = null, part = "dek"),
            "dek with a wrong first byte" to encryptBody(c1 = c1OfSize(62, first = 0x02), itemId = null, part = "dek"),
        )
        cases.forEach { (case, body) ->
            assertRejected(encrypt(body), HttpStatusCode.BadRequest, "bad_request", case)
        }
        assertNoKeyRequested()
    }

    @Test
    fun `the smallest and largest C1 pass`() = endpointTest {
        assertEquals(HttpStatusCode.OK, encrypt(encryptBody(c1 = c1OfSize(30 + 32))).status)
        assertEquals(HttpStatusCode.OK, encrypt(encryptBody(c1 = c1OfSize(30 + 65_536))).status)
    }

    @Test
    fun `the target is checked before C1 on encrypt`() = endpointTest {
        assertRejected(encrypt(encryptBody(c1 = "!!!!", part = "x")), HttpStatusCode.BadRequest, "bad_request")
        assertNoKeyRequested()
    }

    @Test
    fun `an invalid C2 is a bad request before any key is requested`() = endpointTest {
        val cases = mapOf(
            "not base64" to "!!!!",
            "length not a multiple of 4" to Vectors.C2.dropLast(1),
            "empty" to "",
            "one byte too short" to packageOf(97),
            "one byte too long" to packageOf(65_603),
            "wrong magic" to packageOf(98, magic = 0x00),
            "wrong format version" to packageOf(98, format = 0x03),
            "unknown algorithm" to packageOf(98, alg = 0x07),
            "key version zero" to packageOf(98, version = 0),
        )
        cases.forEach { (case, c2) ->
            assertRejected(decrypt(decryptBody(c2 = c2)), HttpStatusCode.BadRequest, "bad_request", case)
        }
        assertNoKeyRequested()
    }

    @Test
    fun `a package of the other crypto service is a conflict before any key is requested`() = endpointTest {
        assertRejected(decrypt(decryptBody(c2 = Vectors.C2_AES)), HttpStatusCode.Conflict, "wrong_service")
        assertNoKeyRequested()
    }

    @Test
    fun `the target and the size are checked before the header`() = endpointTest {
        val invalidTarget = decryptBody(c2 = Vectors.C2_AES, itemId = null)
        assertRejected(decrypt(invalidTarget), HttpStatusCode.BadRequest, "bad_request")
        val tooShort = decryptBody(c2 = packageOf(97, alg = 0x01))
        assertRejected(decrypt(tooShort), HttpStatusCode.BadRequest, "bad_request")
        assertNoKeyRequested()
    }

    @Test
    fun `the smallest and largest C2 reach the key provider`() = endpointTest {
        listOf(98, 65_602).forEach { size ->
            assertRejected(decrypt(decryptBody(c2 = packageOf(size))), HttpStatusCode.InternalServerError, "integrity_error")
        }
        assertEquals(listOf<Int?>(1, 1), keys.requestedVersions)
    }

    @Test
    fun `a tampered package is an integrity error`() = endpointTest {
        val tampered = Vectors.C2.base64()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
        val response = decrypt(decryptBody(c2 = tampered.toBase64()))
        assertRejected(response, HttpStatusCode.InternalServerError, "integrity_error")
    }

    @Test
    fun `a package from another target is an integrity error`() = endpointTest {
        val bodies = listOf(
            decryptBody(itemId = "i8"),
            decryptBody(userId = "u77"),
            decryptBody(part = "h"),
        )
        bodies.forEach { body ->
            assertRejected(decrypt(body), HttpStatusCode.InternalServerError, "integrity_error", body)
        }
    }

    @Test
    fun `decrypt doesn't look at the C1 inside a package that opens`() = endpointTest {
        val notAValidC1 = ByteArray(62)
        val c2 = Tlx2.seal(Vectors.K_CHACHA, 1, ByteArray(12), notAValidC1, Target("u42", "i7", Part.SECRET))

        val response = decrypt(decryptBody(c2 = c2.toBase64()))

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("""{"c1":"${notAValidC1.toBase64()}"}""", response.bodyAsText())
    }

    @Test
    fun `a failing key provider is an internal error`() = endpointTest {
        keys.answer = { error("key service is down") }
        assertRejected(encrypt(encryptBody()), HttpStatusCode.InternalServerError, "internal_error")
        assertRejected(decrypt(decryptBody()), HttpStatusCode.InternalServerError, "internal_error")
    }

    @Test
    fun `an unusable key is an internal error`() = endpointTest {
        val unusable = listOf(
            DerivedKey(ByteArray(31), 1),
            DerivedKey(ByteArray(33), 1),
            DerivedKey(Vectors.K_CHACHA.copyOf(), 0),
            DerivedKey(Vectors.K_CHACHA.copyOf(), 0x10000),
        )
        unusable.forEach { derived ->
            keys.answer = { DerivedKey(derived.key.copyOf(), derived.version) }
            assertRejected(encrypt(encryptBody()), HttpStatusCode.InternalServerError, "internal_error")
            assertRejected(decrypt(decryptBody()), HttpStatusCode.InternalServerError, "internal_error")
        }
    }

    @Test
    fun `a key of another version than requested is an internal error on decrypt`() = endpointTest {
        keys.answer = { DerivedKey(Vectors.K_CHACHA.copyOf(), 2) }
        assertRejected(decrypt(decryptBody()), HttpStatusCode.InternalServerError, "internal_error")
    }

    @Test
    fun `an unusable key is logged with its size and version`() = endpointTest {
        keys.answer = { DerivedKey(ByteArray(31), 2) }
        encrypt(encryptBody())
        decrypt(decryptBody())

        assertEquals(
            listOf(
                "Unhandled error on POST /internal/encrypt",
                "Unhandled error on POST /internal/decrypt",
            ),
            errorLogs.map { it.formattedMessage },
        )
        assertEquals(
            listOf(
                "key-service derive returned 31 bytes for version 2, requested null",
                "key-service derive returned 31 bytes for version 2, requested 1",
            ),
            errorLogs.map { it.throwableProxy.message },
        )
    }

    @Test
    fun `expected errors aren't logged as errors`() = endpointTest {
        encrypt(encryptBody(), token = null)
        decrypt("not json")
        decrypt(decryptBody(c2 = Vectors.C2_AES))
        decrypt(decryptBody(itemId = "i8"))
        assertTrue(errorLogs.isEmpty())
    }

    @Test
    fun `every failed decrypt leaves one audit line`() = endpointTest {
        decrypt(decryptBody(), token = null)
        decrypt("not json")
        decrypt(" ".repeat(MAX_BODY_BYTES + 1))
        decrypt(decryptBody(c2 = "!!!!", itemId = "i9", part = "h"))
        decrypt(decryptBody(c2 = Vectors.C2_AES))
        decrypt(decryptBody(itemId = "i8"))
        keys.answer = { error("key service is down") }
        decrypt(decryptBody(userId = "u77"))
        keys.answer = { throw AssertionError("not even an Exception") }
        decrypt(decryptBody(userId = "u78"))

        assertEquals(
            listOf(
                "decrypt failed userId=- itemId=- part=- error=unauthorized",
                "decrypt failed userId=- itemId=- part=- error=bad_request",
                "decrypt failed userId=- itemId=- part=- error=payload_too_large",
                "decrypt failed userId=u42 itemId=i9 part=h error=bad_request",
                "decrypt failed userId=u42 itemId=i7 part=s error=wrong_service",
                "decrypt failed userId=u42 itemId=i8 part=s error=integrity_error",
                "decrypt failed userId=u77 itemId=i7 part=s error=internal_error",
                "decrypt failed userId=u78 itemId=i7 part=s error=internal_error",
            ),
            auditLines,
        )
    }

    @Test
    fun `values that aren't valid ids never reach the audit log`() = endpointTest {
        decrypt(decryptBody(userId = "evil|user", itemId = "evil item", part = "evil part"))
        decrypt(decryptBody(itemId = null))
        assertEquals(
            listOf(
                "decrypt failed userId=- itemId=- part=- error=bad_request",
                "decrypt failed userId=u42 itemId=- part=s error=bad_request",
            ),
            auditLines,
        )
    }

    @Test
    fun `a failed encrypt leaves no audit line`() = endpointTest {
        encrypt(encryptBody(), token = null)
        encrypt("not json")
        keys.answer = { error("key service is down") }
        encrypt(encryptBody())
        assertFalse(auditLines.any())
    }

    @Test
    fun `requests and responses don't show their ciphertext in toString`() {
        assertEquals("EncryptRequest(userId=u42, itemId=i7, part=s)", EncryptRequest("u42", "i7", "s", Vectors.C1).toString())
        assertEquals("EncryptResponse", EncryptResponse(Vectors.C2).toString())
        assertEquals("DecryptRequest(userId=u42, itemId=i7, part=s)", DecryptRequest("u42", "i7", "s", Vectors.C2).toString())
        assertEquals("DecryptResponse", DecryptResponse(Vectors.C1).toString())
    }
}
