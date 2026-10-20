package de.trustylynx

import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec

class AppConfig(
    val vaultServiceToken: String,
    val chachaServiceToken: String,
    /** `null` heißt: Dev-Stub statt Key-Service (nur im Dev-Modus erlaubt). */
    val keyServiceUrl: String?,
    val guardPublicKey: PublicKey,
) {
    override fun toString(): String = "AppConfig(keyServiceUrl=$keyServiceUrl)"

    companion object {
        fun fromEnv() = AppConfig(
            vaultServiceToken = env("VAULT_SERVICE_TOKEN"),
            chachaServiceToken = env("CHACHA_SERVICE_TOKEN"),
            keyServiceUrl = System.getenv("KEY_SERVICE_URL")?.takeIf { it.isNotBlank() },
            guardPublicKey = guardPublicKey(env("GUARD_PUBLIC_KEY")),
        )

        private fun env(name: String): String =
            System.getenv(name)?.takeIf { it.isNotBlank() }
                ?: error("Missing required environment variable $name")
    }
}

private const val ED25519_KEY_LENGTH = 32

/** Ed25519-Präfix für X.509 (SubjectPublicKeyInfo). Das JDK nimmt den rohen Schlüssel nur so. */
private val ED25519_X509_PREFIX = "302a300506032b6570032100".hexToByteArray()

/** Liest `GUARD_PUBLIC_KEY`: Base64 der rohen 32 Byte. */
fun guardPublicKey(base64: String): PublicKey {
    val raw = base64.decodeBase64OrNull()
    require(raw != null && raw.size == ED25519_KEY_LENGTH) {
        "GUARD_PUBLIC_KEY must be $ED25519_KEY_LENGTH bytes, Base64"
    }
    return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(ED25519_X509_PREFIX + raw))
}
