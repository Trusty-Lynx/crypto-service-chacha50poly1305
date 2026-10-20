# crypto-service-chacha50poly1305

Crypto-Service 2 von TrustyLynx: legt mit ChaCha20-Poly1305 eine zweite Verschlüsselungsschicht um die Pakete
aus dem Client (C1 → C2) und nimmt sie beim Lesen wieder ab. Einziger Aufrufer ist der Vault-Service.
Der Service ist zustandslos: Den Schlüssel `K_chacha` holt er bei jeder Anfrage neu vom Key-Service und überschreibt ihn danach.

Kotlin 2.4 · Ktor 3.6 · Java 21 · Krypto nur aus dem JDK

## Endpoints

| Methode | Pfad | Zweck |
|---|---|---|
| `POST` | `/internal/encrypt` | `{userId, itemId?, part, c1}` → `{c2}` |
| `POST` | `/internal/decrypt` | `{userId, itemId?, part, c2}` → `{c1}`. C2 vom AES-Service gibt `409 wrong_service` |
| `GET` | `/health` | `200 {"status":"ok"}`, ohne Token |

`part` ist `h`, `s` oder `dek` (ohne `itemId`). Beide `/internal/…`-Endpoints brauchen `X-Service-Token`.
Fehler kommen als `{"error": "<code>"}`. Felder, Paketformat und Fehlercodes:
[Crypto-Service-ChaCha.md](../documentation/anforderungen/Crypto-Service-ChaCha.md).

## Struktur

```text
src/main/kotlin/
├── Application.kt   main(), module() verdrahtet alles, configureApp() für Tests
├── Config.kt        Umgebungsvariablen
├── Tlx2.kt          Paketformat: seal/open, Header, AAD, C1-Prüfung
├── KeyProvider.kt   Key-Service-Client und Dev-Stub
├── Routes.kt        Endpoints, Prüfreihenfolge, Audit-Log
└── Errors.kt        Fehler und StatusPages
```

## Umgebungsvariablen

| Variable | Pflicht | Zweck |
|---|---|---|
| `VAULT_SERVICE_TOKEN` | ja | Token, den der Vault in `X-Service-Token` mitschickt |
| `CHACHA_SERVICE_TOKEN` | ja | eigener Token für Aufrufe beim Key-Service |
| `KEY_SERVICE_URL` | in Prod ja | z. B. `http://key-service:8080`. Leer im Dev-Modus → Stub mit dem Testschlüssel |

Fehlt eine Pflicht-Variable, startet der Service nicht.

## Starten und testen

```bash
export VAULT_SERVICE_TOKEN=dev-vault-token
export CHACHA_SERVICE_TOKEN=dev-chacha-token

./gradlew run -Pdevelopment   # ohne KEY_SERVICE_URL: Dev-Stub, Port 8080
./gradlew test
```

Im Container läuft der Service auf Port `8080`, nur im Netz `trustylynx-net` und ohne veröffentlichten Port.
