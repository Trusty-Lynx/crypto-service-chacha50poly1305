package de.trustylynx

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.netty.EngineMain
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import java.util.Base64

fun main(args: Array<String>) {
    EngineMain.main(args)
}

/** Einziger Ort, an dem Abhängigkeiten gebaut und verdrahtet werden. */
fun Application.module() {
    val config = AppConfig.fromEnv()

    val keys = when {
        config.keyServiceUrl != null -> {
            val http = createKeyServiceHttpClient()
            monitor.subscribe(ApplicationStopped) { http.close() }
            HttpKeyProvider(http, config.keyServiceUrl, config.chachaServiceToken)
        }
        developmentMode -> {
            log.warn("KEY_SERVICE_URL is empty: using the dev stub key for every user")
            DevKeyProvider()
        }
        else -> error("Missing required environment variable KEY_SERVICE_URL (only optional in development mode)")
    }

    configureApp(config, keys)
}

/** Plugins und Routen, getrennt von [module], damit Tests Fakes einsetzen können. */
fun Application.configureApp(config: AppConfig, keys: KeyProvider) {
    install(ContentNegotiation) { json() }
    configureStatusPages()
    routing {
        cryptoRoutes(config, keys)
    }
}

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

/** Standard-Base64 mit Padding, sonst `null`. */
fun String.decodeBase64OrNull(): ByteArray? {
    if (length % 4 != 0) return null
    return try {
        Base64.getDecoder().decode(this)
    } catch (_: IllegalArgumentException) {
        null
    }
}
