package de.trustylynx

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
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private const val VAULT_TOKEN = "test-vault-token"

private val GUARD: KeyPair = newEd25519KeyPair()

/** Geht wie in Produktion über die rohen 32 Byte, damit auch der X.509-Präfix getestet ist. */
private val TEST_CONFIG = AppConfig(
    vaultServiceToken = VAULT_TOKEN,
    chachaServiceToken = "test-chacha-token",
    keyServiceUrl = null,
    guardPublicKey = guardPublicKey(GUARD.public.encoded.takeLast(32).toByteArray().toBase64()),
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

class Ticket(val ticket: String?, val sig: String?)

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
        ticket: Ticket? = null,
        token: String? = VAULT_TOKEN,
    ): HttpResponse = post(
        "/internal/decrypt", token,
        "userId" to userId, "itemId" to itemId, "part" to part, "c2" to c2,
        "ticket" to ticket?.ticket, "sig" to ticket?.sig,
    )

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

private fun newEd25519KeyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

private fun ticket(
    u: String = "u42",
    i: String = "i7",
    p: String = "s",
    exp: Long = Instant.now().epochSecond + 30,
    signer: PrivateKey = GUARD.private,
): Ticket {
    val bytes = """{"u":"$u","d":"dev-mac-01","i":"$i","p":"$p","exp":$exp}""".encodeToByteArray()
    return Ticket(bytes.toBase64(), sign(signer, bytes).toBase64())
}

private fun sign(key: PrivateKey, data: ByteArray): ByteArray = Signature.getInstance("Ed25519").run {
    initSign(key)
    update(data)
    sign()
}

/** Vektor-C2 mit [change] an einer Kopie der Bytes. */
private fun vectorC2(change: (ByteArray) -> Unit): String = Vectors.C2.base64().also(change).toBase64()

private suspend fun HttpResponse.field(name: String): String =
    Json.parseToJsonElement(bodyAsText()).jsonObject.getValue(name).jsonPrimitive.content

private suspend fun assertError(status: HttpStatusCode, code: String, response: HttpResponse, case: String? = null) {
    assertEquals(status, response.status, case)
    assertEquals(code, response.field("error"), case)
}

class RoutesTest {

    @Test
    fun `T2 decrypt of the vector C2 with a valid ticket returns the vector C1`() = cryptoTest {
        val response = decrypt(ticket = ticket())

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(Vectors.C1, response.field("c1"))
        assertEquals(listOf<Int?>(1), keys.requestedVersions)
    }

    @Test
    fun `T3 encrypt then decrypt returns the same C1 for h and dek`() = cryptoTest {
        for ((itemId, part, c1) in listOf(Triple("i7", "h", Vectors.C1), Triple(null, "dek", Vectors.WDEK))) {
            val encrypted = encrypt(itemId = itemId, part = part, c1 = c1)
            assertEquals(HttpStatusCode.OK, encrypted.status, part)
            val c2 = encrypted.field("c2")
            assertTrue(c2.startsWith("VExYMgIC"), part)
            assertEquals(c1.base64().size + 36, c2.base64().size, part)

            val decrypted = decrypt(itemId = itemId, part = part, c2 = c2)
            assertEquals(HttpStatusCode.OK, decrypted.status, part)
            assertEquals(c1, decrypted.field("c1"), part)
        }
        assertEquals(listOf(null, 1, null, 1), keys.requestedVersions)
    }

    @Test
    fun `T4 encrypting the same C1 twice gives different C2`() = cryptoTest {
        assertNotEquals(encrypt().field("c2"), encrypt().field("c2"))
    }

    @Test
    fun `T5 a flipped bit gives integrity_error`() = cryptoTest {
        val size = Vectors.C2.base64().size
        // Key-Version, Nonce, Chiffrat, Tag
        for (index in listOf(6, 10, 30, size - 1)) {
            val c2 = vectorC2 { it[index] = (it[index].toInt() xor 1).toByte() }
            assertError(HttpStatusCode.InternalServerError, "integrity_error", decrypt(c2 = c2, ticket = ticket()), "byte $index")
        }
    }

    @Test
    fun `T6 the vector C2 under another item or part gives integrity_error`() = cryptoTest {
        assertError(HttpStatusCode.InternalServerError, "integrity_error", decrypt(itemId = "i8", ticket = ticket(i = "i8")))
        assertError(HttpStatusCode.InternalServerError, "integrity_error", decrypt(part = "h"))
    }

    @Test
    fun `T7 secret without a valid ticket is forbidden and never asks for the key`() = cryptoTest {
        val valid = ticket()
        val cases = mapOf(
            "no ticket" to null,
            "no sig" to Ticket(valid.ticket, null),
            "sig from another key" to ticket(signer = newEd25519KeyPair().private),
            "sig too short" to Ticket(valid.ticket, valid.sig!!.base64().copyOf(63).toBase64()),
            "ticket changed after signing" to Ticket(ticket(u = "u43").ticket, valid.sig),
            "expired" to ticket(exp = Instant.now().epochSecond - 1),
            "ticket for i8" to ticket(i = "i8"),
            "ticket for another user" to ticket(u = "u43"),
            "ticket for part h" to ticket(p = "h"),
        )
        for ((case, ticket) in cases) {
            assertError(HttpStatusCode.Forbidden, "forbidden", decrypt(ticket = ticket), case)
        }
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T8 a C2 from the AES service gives wrong_service`() = cryptoTest {
        assertError(HttpStatusCode.Conflict, "wrong_service", decrypt(c2 = Vectors.C2_AES, ticket = ticket()))
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T9 unknown header or too short C2 is a bad request`() = cryptoTest {
        val cases = mapOf(
            "magic" to vectorC2 { it[0] = 0x55 },
            "format version 03" to vectorC2 { it[4] = 0x03 },
            "algorithm 07" to vectorC2 { it[5] = 0x07 },
            "key version 0" to vectorC2 { it[7] = 0x00 },
            "97 bytes" to Vectors.C2.base64().copyOf(97).toBase64(),
            "broken Base64" to "VExYMg!!",
        )
        for ((case, c2) in cases) {
            assertError(HttpStatusCode.BadRequest, "bad_request", decrypt(part = "h", c2 = c2), case)
        }
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T10 invalid encrypt requests are bad requests`() = cryptoTest {
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
    fun `T11 missing or wrong service token is unauthorized`() = cryptoTest {
        for (token in listOf(null, "wrong-token", "$VAULT_TOKEN-")) {
            assertError(HttpStatusCode.Unauthorized, "unauthorized", encrypt(token = token), "encrypt $token")
            assertError(HttpStatusCode.Unauthorized, "unauthorized", decrypt(part = "h", token = token), "decrypt $token")
        }
        assertEquals(emptyList(), keys.requestedVersions)
    }

    @Test
    fun `T12 a failing or unusable key service gives internal_error`() = cryptoTest {
        keys.failure = IllegalStateException("key-service down")
        assertError(HttpStatusCode.InternalServerError, "internal_error", encrypt())
        assertError(HttpStatusCode.InternalServerError, "internal_error", decrypt(ticket = ticket()))

        keys.failure = null
        keys.key = Vectors.K_CHACHA.copyOf(31)
        assertError(HttpStatusCode.InternalServerError, "internal_error", encrypt())
        assertError(HttpStatusCode.InternalServerError, "internal_error", decrypt(ticket = ticket()))
    }

    @Test
    fun `T13 decrypt asks for the key version from the header`() = cryptoTest {
        keys.activeVersion = 3
        val c2 = encrypt(part = "h").field("c2")
        assertEquals(listOf<Byte>(0x00, 0x03), c2.base64().slice(6..7))

        val response = decrypt(part = "h", c2 = c2)

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(listOf(null, 3), keys.requestedVersions)
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
