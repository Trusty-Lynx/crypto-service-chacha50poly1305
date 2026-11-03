package de.trustylynx

import de.trustylynx.clients.DerivedKey
import de.trustylynx.clients.KeyProvider
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private const val VAULT_TOKEN = "test-vault-token"

private val TEST_CONFIG = AppConfig(
    vaultServiceToken = VAULT_TOKEN,
    chachaServiceToken = "test-chacha-token",
    keyServiceUrl = null,
)

class FakeKeyProvider : KeyProvider {
    var key: ByteArray = Vectors.K_CHACHA
    var activeVersion = 1
    var failure: Exception? = null
    val requestedVersions = mutableListOf<Int?>()

    override suspend fun derive(userId: String, version: Int?): DerivedKey {
        requestedVersions += version
        failure?.let { throw it }
        return DerivedKey(key.copyOf(), version ?: activeVersion)
    }
}

class CryptoTestEnv(private val client: HttpClient, val keys: FakeKeyProvider) {
    suspend fun encrypt(
        userId: String = "u42",
        itemId: String? = "i7",
        part: String = "s",
        c1: String? = Vectors.C1,
        token: String? = VAULT_TOKEN,
    ): HttpResponse = post("/internal/encrypt", token, "userId" to userId, "itemId" to itemId, "part" to part, "c1" to c1)

    suspend fun decrypt(
        userId: String = "u42",
        itemId: String? = "i7",
        part: String = "s",
        c2: String = Vectors.C2,
        token: String? = VAULT_TOKEN,
    ): HttpResponse = post("/internal/decrypt", token, "userId" to userId, "itemId" to itemId, "part" to part, "c2" to c2)

    suspend fun post(path: String, token: String?, vararg fields: Pair<String, String?>): HttpResponse =
        client.post(path) {
            if (token != null) header(SERVICE_TOKEN_HEADER, token)
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { for ((name, value) in fields) if (value != null) put(name, value) }.toString())
        }

    suspend fun get(path: String): HttpResponse = client.get(path)
}

private fun cryptoTest(block: suspend CryptoTestEnv.() -> Unit) = testApplication {
    environment { config = MapApplicationConfig() }
    val keys = FakeKeyProvider()
    application { configureApp(TEST_CONFIG, keys) }
    CryptoTestEnv(client, keys).block()
}

private fun vectorC2(change: (ByteArray) -> Unit): String = Vectors.C2.base64().also(change).toBase64()

private suspend fun HttpResponse.field(name: String): String =
    Json.parseToJsonElement(bodyAsText()).jsonObject.getValue(name).jsonPrimitive.content

private suspend fun assertError(status: HttpStatusCode, code: String, response: HttpResponse, case: String? = null) {
    assertEquals(status, response.status, case)
    assertEquals(code, response.field("error"), case)
}

class RoutesTest {

    @Test
    fun `T2 decrypt of the vector C2 returns the vector C1`() = cryptoTest {
        val response = decrypt()

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(Vectors.C1, response.field("c1"))
        assertEquals(listOf<Int?>(1), keys.requestedVersions)
    }

    @Test
    fun `T3 encrypt then decrypt returns the same C1 for h, s and dek`() = cryptoTest {
        val cases = listOf(Triple("i7", "h", Vectors.C1), Triple("i7", "s", Vectors.C1), Triple(null, "dek", Vectors.WDEK))
        for ((itemId, part, c1) in cases) {
            val encrypted = encrypt(itemId = itemId, part = part, c1 = c1)
            assertEquals(HttpStatusCode.OK, encrypted.status, part)
            val c2 = encrypted.field("c2")
            assertTrue(c2.startsWith("VExYMgIC"), part)
            assertEquals(c1.base64().size + 36, c2.base64().size, part)

            val decrypted = decrypt(itemId = itemId, part = part, c2 = c2)
            assertEquals(HttpStatusCode.OK, decrypted.status, part)
            assertEquals(c1, decrypted.field("c1"), part)
        }
        assertEquals(listOf(null, 1, null, 1, null, 1), keys.requestedVersions)
    }

    @Test
    fun `T4 encrypting the same C1 twice gives different C2`() = cryptoTest {
        assertNotEquals(encrypt().field("c2"), encrypt().field("c2"))
    }

    @Test
    fun `T5 a flipped bit gives integrity_error`() = cryptoTest {
        val size = Vectors.C2.base64().size
        // key version, nonce, ciphertext, tag
        for (index in listOf(6, 10, 30, size - 1)) {
            val c2 = vectorC2 { it[index] = (it[index].toInt() xor 1).toByte() }
            assertError(HttpStatusCode.InternalServerError, "integrity_error", decrypt(c2 = c2), "byte $index")
        }
    }

    @Test
    fun `T6 the vector C2 under another item, user or part gives integrity_error`() = cryptoTest {
        assertError(HttpStatusCode.InternalServerError, "integrity_error", decrypt(itemId = "i8"), "itemId i8")
        assertError(HttpStatusCode.InternalServerError, "integrity_error", decrypt(userId = "u77"), "userId u77")
        assertError(HttpStatusCode.InternalServerError, "integrity_error", decrypt(part = "h"), "part h")
    }

    @Test
    fun `T7 a C2 from the AES service gives wrong_service and never asks for the key`() = cryptoTest {
        assertError(HttpStatusCode.Conflict, "wrong_service", decrypt(c2 = Vectors.C2_AES))
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T8 unknown header or too short C2 is a bad request`() = cryptoTest {
        val cases = mapOf(
            "magic" to vectorC2 { it[0] = 0x55 },
            "format version 03" to vectorC2 { it[4] = 0x03 },
            "algorithm 07" to vectorC2 { it[5] = 0x07 },
            "key version 0" to vectorC2 { it[7] = 0x00 },
            "97 bytes" to Vectors.C2.base64().copyOf(97).toBase64(),
            "broken Base64" to "VExYMg!!",
        )
        for ((case, c2) in cases) {
            assertError(HttpStatusCode.BadRequest, "bad_request", decrypt(c2 = c2), case)
        }
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T9 invalid encrypt requests are bad requests`() = cryptoTest {
        val c1 = Vectors.C1.base64()
        val cases = mapOf(
            "first byte not 01" to encrypt(c1 = c1.copyOf().also { it[0] = 0x02 }.toBase64()),
            "length not a padding stage" to encrypt(c1 = (c1 + 0).toBase64()),
            "wDEK with 63 bytes" to encrypt(itemId = null, part = "dek", c1 = (Vectors.WDEK.base64() + 0).toBase64()),
            "dek with itemId" to encrypt(part = "dek", c1 = Vectors.WDEK),
            "s without itemId" to encrypt(itemId = null),
            "part x" to encrypt(part = "x"),
            "userId with |" to encrypt(userId = "u42|i7"),
            "itemId too long" to encrypt(itemId = "i".repeat(129)),
            "c1 missing" to encrypt(c1 = null),
            "c1 broken Base64" to encrypt(c1 = "AQG*"),
            "c1 without padding" to encrypt(c1 = Vectors.C1.trimEnd('=')),
        )
        for ((case, response) in cases) {
            assertError(HttpStatusCode.BadRequest, "bad_request", response, case)
        }
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T10 missing or wrong service token is unauthorized`() = cryptoTest {
        for (token in listOf(null, "wrong-token", "$VAULT_TOKEN-")) {
            assertError(HttpStatusCode.Unauthorized, "unauthorized", encrypt(token = token), "encrypt $token")
            assertError(HttpStatusCode.Unauthorized, "unauthorized", decrypt(token = token), "decrypt $token")
        }
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T11 a failing or unusable key service gives internal_error`() = cryptoTest {
        keys.failure = IllegalStateException("key-service down")
        assertError(HttpStatusCode.InternalServerError, "internal_error", encrypt())
        assertError(HttpStatusCode.InternalServerError, "internal_error", decrypt())

        keys.failure = null
        keys.key = Vectors.K_CHACHA.copyOf(31)
        assertError(HttpStatusCode.InternalServerError, "internal_error", encrypt())
        assertError(HttpStatusCode.InternalServerError, "internal_error", decrypt())
    }

    @Test
    fun `T12 decrypt asks for the key version from the header`() = cryptoTest {
        keys.activeVersion = 3
        val c2 = encrypt().field("c2")
        assertEquals(listOf<Byte>(0x00, 0x03), c2.base64().slice(6..7))

        val response = decrypt(c2 = c2)

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(listOf(null, 3), keys.requestedVersions)
    }

    @Test
    fun `unknown fields in the body are ignored`() = cryptoTest {
        val response = post(
            "/internal/decrypt", VAULT_TOKEN,
            "userId" to "u42", "itemId" to "i7", "part" to "s", "c2" to Vectors.C2, "legacy" to "x",
        )

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(Vectors.C1, response.field("c1"))
    }

    @Test
    fun `health answers without a token`() = cryptoTest {
        val response = get("/health")

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("ok", response.field("status"))
    }

    @Test
    fun `bodies over 256 KiB are rejected`() = cryptoTest {
        assertError(HttpStatusCode.PayloadTooLarge, "payload_too_large", encrypt(userId = "u".repeat(256 * 1024)))
    }
}
