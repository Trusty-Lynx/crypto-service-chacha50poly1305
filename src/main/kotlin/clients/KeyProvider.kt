package de.trustylynx.clients

import de.trustylynx.SERVICE_TOKEN_HEADER
import de.trustylynx.models.KeyServiceException
import de.trustylynx.security.decodeBase64OrNull
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

// test vector key from the docs, only used in development mode
private const val DEV_KEY_BASE64 = "2QTTNUrVlYzUxxTvXLXKcntIYUyrgBAQc3yl+RSFZB8="

// whoever gets this has to overwrite key with zeros after use
class DerivedKey(val key: ByteArray, val version: Int)

interface KeyProvider {
    // version null means the current key
    suspend fun derive(userId: String, version: Int?): DerivedKey
}

class HttpKeyProvider(
    private val http: HttpClient,
    baseUrl: String,
    private val serviceToken: String,
) : KeyProvider {
    private val url = baseUrl.trimEnd('/') + "/internal/keys/derive"

    override suspend fun derive(userId: String, version: Int?): DerivedKey {
        val body = try {
            val response = http.post(url) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(DeriveRequest(userId = userId, alg = "chacha", version = version))
            }
            if (response.status != HttpStatusCode.OK) {
                throw KeyServiceException("key-service derive answered ${response.status.value}")
            }
            response.body<DeriveResponse>()
        } catch (e: CancellationException) {
            throw e // request got cancelled, not the key service's fault
        } catch (e: KeyServiceException) {
            throw e
        } catch (e: Exception) {
            throw KeyServiceException("key-service derive failed", e)
        }
        val key = body.key.decodeBase64OrNull() ?: throw KeyServiceException("key-service derive: invalid Base64")
        return DerivedKey(key, body.version)
    }
}

class DevKeyProvider : KeyProvider {
    override suspend fun derive(userId: String, version: Int?): DerivedKey =
        DerivedKey(DEV_KEY_BASE64.decodeBase64OrNull()!!, 1)
}

fun createKeyServiceHttpClient(): HttpClient = HttpClient(CIO) {
    expectSuccess = false
    install(ContentNegotiation) {
        // explicitNulls = false leaves version out of the request when it's null
        json(Json { ignoreUnknownKeys = true; explicitNulls = false })
    }
    install(HttpTimeout) {
        connectTimeoutMillis = 2_000
        requestTimeoutMillis = 10_000
    }
}

@Serializable
private class DeriveRequest(val userId: String, val alg: String, val version: Int?)

@Serializable
private class DeriveResponse(val key: String, val version: Int)
