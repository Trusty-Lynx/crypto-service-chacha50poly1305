package de.trustylynx

class AppConfig(
    val vaultServiceToken: String,
    val chachaServiceToken: String,
    /** `null` heißt: Dev-Stub statt Key-Service (nur im Dev-Modus erlaubt). */
    val keyServiceUrl: String?,
) {
    override fun toString(): String = "AppConfig(keyServiceUrl=$keyServiceUrl)"

    companion object {
        fun fromEnv() = AppConfig(
            vaultServiceToken = env("VAULT_SERVICE_TOKEN"),
            chachaServiceToken = env("CHACHA_SERVICE_TOKEN"),
            keyServiceUrl = System.getenv("KEY_SERVICE_URL")?.takeIf { it.isNotBlank() },
        )

        private fun env(name: String): String =
            System.getenv(name)?.takeIf { it.isNotBlank() }
                ?: error("Missing required environment variable $name")
    }
}
