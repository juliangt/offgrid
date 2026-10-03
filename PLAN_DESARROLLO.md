# Plan de Desarrollo — Sistema de Mensajería DTN Off-Grid (Fase 1)

| | |
|---|---|
| **Documento fuente** | `prompt_maestro_de_desarrollo.md` |
| **Versión del plan** | 1.0 |
| **Fecha** | 2026-10-03 |
| **Estado** | Pendiente de aprobación |
| **Alcance** | Fase 1 completa (Módulos A–D) + preparación de Fases 2/3 |

---

## 0. Resumen ejecutivo

Se construirá un sistema de mensajería asíncrona, cifrada extremo a extremo (E2EE), que opera **sin Internet, sin satélites y sin red celular**. Los componentes:

- **Nodos fijos (Módulo A + B):** Raspberry Pi Zero 2 W con punto de acceso Wi-Fi abierto y portal cautivo, ejecutando un daemon HTTP autocontenido en Go con SQLite como buzones ciegos (*dead drops*). Alimentación solar + batería LiFePO4.
- **Mulas de datos (Módulo C):** los usuarios transportan sobres cifrados ajenos en el `IndexedDB` de su navegador móvil (capacidad 50–100 sobres) al desplazarse físicamente entre nodos, sincronizando al conectarse a cada portal.
- **Evolución (Módulo D):** el formato de sobre (`Envelope`) se diseña desde el día 1 para migrar sin reescritura a BLE L2CAP CoC (bitchat, Fase 2) y LoRa P2P SX1262 a 915 MHz con CBOR (Fase 3).

**Entregables:** configuración de red de la Pi (hostapd, dnsmasq, iptables, energía), binario Go estático con frontend embebido, SPA `index.html` única con motor criptográfico embebido, documentación de mapeo a Fases 2/3, e instrucciones paso a paso de compilación, ejecución y prueba.

**Estimación total:** 6–8 días de trabajo distribuidos en 5 sprints (§5).

---

## 1. Análisis del documento fuente: decisiones de diseño y puntos críticos

Esta sección recoge el análisis detallado del prompt maestro. Cada decisión aquí tomada es vinculante para la implementación.

### 1.1 El truco del mismo origen (same-origin) y sus consecuencias

`IndexedDB` está aislado por origen web (esquema + host + puerto). Para que la mula conserve identidad, bandeja y cola de tránsito al moverse entre nodos, **todos los nodos deben ser indistinguibles en origen**: mismo FQDN (`portal.red.local`), mismo puerto (8080) y misma IP de gateway (`10.42.0.1`).

Consecuencias operativas:

1. **Middleware de host canónico en Go:** toda petición cuyo header `Host` no sea `portal.red.local:8080` (p. ej. `10.42.0.1:8080`, o cualquier dominio "spoofeado" por el wildcard DNS) debe responder `301 → http://portal.red.local:8080/`. Así el navegador siempre acaba en el origen correcto y el almacenamiento nunca se fragmenta.
2. **Exención obligatoria:** los endpoints de detección de portal (`/generate_204`, `/hotspot-detect.html`) deben responder `302` con `Location` absoluto **independientemente del Host** (llegan con Host `connectivitycheck.gstatic.com`, `captive.apple.com`, etc. por el wildcard DNS) y **no** deben ser redirigidos primero al host canónico, o el SO no detectará el portal cautivo.
3. **Sin TLS:** no es posible un certificado válido para `portal.red.local` con la misma IP en todos los nodos (ni PKI offline sin instalación). Se usa HTTP plano. Esto es aceptable **solo porque** el contenido viaja cifrado E2EE en el cliente: el nodo (canal hostil por diseño) nunca ve texto plano, claves, remitente real ni destinatario completo. TLS añadiría un falso sentido de seguridad sin proteger nada que el cifrado de aplicación no proteja ya.
4. **Riesgo de "fragmentación accidental":** si un usuario guarda un marcador con la IP en lugar del FQDN, su sesión quedaría en un origen distinto. Mitigación: el middleware del punto 1 + mostrar siempre la URL canónica en la UI.

### 1.2 Modelo de amenazas y la limitación honesta del `dest_hint`

El prompt exige que los nodos no conozcan "el contenido, el remitente real ni la identidad completa del destinatario".

- **Contenido:** garantizado por cifrado (sender anónimo, ver §3.4).
- **Remitente:** la firma Ed25519 y el alias del remitente van **dentro del ciphertext** (sign-then-encrypt). El nodo solo ve bytes aleatorios.
- **Destinatario:** el nodo ve `dest_hint` (hash truncado de la clave pública X25519 del destinatario) para poder almacenar y servir los sobres. **Limitación documentada:** como el mismo nodo sirve el directorio público con las pubkeys, un operador malicioso *podría* recalcular los hints de los usuarios registrados y vincular sobres con alias. Es un riesgo aceptado en Fase 1 (los nodos son "curiosos pasivos", no adversarios activos); Fase 2 contempla hints rotatorios (`HKDF(pubkey, época)`). Esto se documenta explícitamente en `docs/protocolo.md` — ocultarlo sería un error de ingeniería.

Propósito real del `dest_hint`: (a) permitir a la **mula** identificar sin descifrar cuáles sobres le pertenecen (compara con el hint derivado de su propia clave) y (b) deduplicación/limpieza en el nodo.

### 1.3 Motor criptográfico: tweetnacl embebido, no WebCrypto nativo

El propio prompt ofrece la alternativa ("o una implementación embebida de `tweetnacl.js` inyectada directamente en el archivo"). **Decisión: embeber tweetnacl.js inline** como camino único de código, por tres razones:

1. La disponibilidad de `X25519`/`Ed25519` en `crypto.subtle` es irregular en navegadores móviles y **peor aún en los mini-navegadores de portal cautivo** (Android Captive Portal WebView, iOS CNA). Un solo camino de código elimina una clase entera de bugs.
2. Garantiza comportamientos idénticos entre navegadores (mismas primitivas: `crypto_box` = X25519+XSalsa20-Poly1305, `crypto_sign` = Ed25519).
3. Cumple la regla de cero dependencias externas: tweetnacl (≈25 KB minificado) va incrustado literalmente en `index.html`.

La entropía sale de `crypto.getRandomValues` (disponible en todos los WebView modernos, incluidos los cautivos).

### 1.4 El problema del mini-navegador del portal cautivo

Cuando Android/iOS detectan el portal cautivo, abren un navegador restringido cuyo perfil de almacenamiento **está aislado del navegador real** del dispositivo. Consecuencias:

- Si el usuario solo usa el mini-navegador, todo funciona *dentro de él* mientras vuelva a usarlo, pero sus datos podrían no persistir de forma confiable entre sesiones/nodos.
- **Mitigación obligatoria en la UI:** banner detectando contexto restrictivo con la instrucción "Ábrelo en tu navegador completo: `http://portal.red.local:8080`" (URL visible y copiable). El flujo recomendado al usuario: conectarse al Wi-Fi → abrir la URL en Chrome/Safari.
- Las pruebas de aceptación (§6) incluyen explícitamente ambos contextos.

### 1.5 Presupuesto de bytes: Fase 1 (JSON/Base64) vs Fase 2/3 (binario)

El prompt pide sobres con payload estándar de ~180–250 bytes, migrables a BLE/LoRa sin reescritura.

- **Fase 1 (transporte HTTP/Wi-Fi):** el sobre viaja como JSON con el payload binario codificado en Base64. El **payload lógico** (eph_pub 32 B + nonce 24 B + ciphertext con MAC) se mantiene ≤ 256 bytes cumpliendo el objetivo; la inflación Base64/JSON es irrelevante sobre Wi-Fi.
- **Fase 3 (LoRa 222 B de MTU):** el mismo sobre en CBOR (eph 32 + nonce 24 + MAC 16 + cabeceras) excede la MTU si el texto plano usa los 128 B completos con firma y alias dentro. **Decisión:** fragmentación en 2 tramas estilo bitchat (cabecera de 1 B: `win_id` 4 bits + `idx` 2 bits + `total` 2 bits), documentada en el Módulo D. Alternativa "mensaje corto" (≤ 48 B) en una sola trama: se documenta el cálculo exacto en `docs/protocolo.md`.
- **Fase 2 (BLE L2CAP CoC):** MTU negociable (≥ 512 B típico) → el sobre binario CBOR cabe entero; se reserva el campo `hop_count` (≤ 7) que en Fase 1 vale siempre 0 y viaja implícito (ausente) en el JSON.

### 1.6 Raspberry Pi OS Bookworm: NetworkManager vs hostapd clásico

Las imágenes actuales de Raspberry Pi OS Lite (Bookworm) usan **NetworkManager** por defecto, que entra en conflicto con `hostapd` + `dnsmasq` clásicos (y su modo AP vía wpa_supplicant no soporta `ap_isolate`). **Decisión:**

- Deshabilitar NetworkManager en el provisionamiento y usar la pila clásica **ifupdown + hostapd + dnsmasq + iptables (capa nft)**, que es exactamente la que exigen los entregables del Módulo A.
- El script de provisioning detecta el escenario (Bookworm/NM vs legado/dhcpcd) y actúa en consecuencia, con verificación de resultado en cada paso.

### 1.7 Decisiones de protocolo consolidadas

| Parámetro | Valor | Justificación |
|---|---|---|
| Cifrado | X25519 + XSalsa20-Poly1305 (`crypto_box`, efímero por mensaje) | Aislamiento del remitente + confidencialidad; primitivas estándar bitchat |
| Firma/identidad | Ed25519 (`crypto_sign`) | Identidad del remitente verificable solo por el destinatario |
| Orden criptográfico | **Sign-then-encrypt** (firma y alias DENTRO del ciphertext) | Anonimato del remitente frente a nodos y mulas |
| `dest_hint` | Primeros 8 B de `SHA-256(X25519_pub destinatario)` en hex (16 chars) | Routing ciego + auto-identificación de la mula; limitación documentada en §1.2 |
| `id` del sobre | `SHA-256(JSON canónico de v‖dest_hint‖created_at‖ttl‖payload)` en hex (64 chars) | Deduplicación global entre nodos (`INSERT OR IGNORE`) — lo computa el cliente |
| Límite de texto plano | 128 bytes (contador visible en la UI) | Alineación con el presupuesto de Fase 2/3 |
| TTL por defecto | 604 800 s (7 días); mín 3600; máx 2 592 000 (30 días) | Caducidad de sobres en buzones con almacenamiento limitado |
| Capacidad mula (`transit_queue`) | 100 sobres, expulsión FIFO por `created_at` | Dentro del rango 50–100 exigido |
| Límite por sync | `limit` por defecto 50, máx 200; push máx 100 sobres; body ≤ 1 MiB; `known_ids` máx 500 | Protección del nodo abierto (abuso/llenado) |
| Directorio | máx 500 entradas en GET; alias `^[A-Za-z0-9_.-]{1,24}$` | Saneamiento en cliente y servidor |

---

## 2. Arquitectura del sistema

```
        ┌─────────────────────────┐          ┌─────────────────────────┐
        │   NODO A (Pi Zero 2 W)  │          │   NODO B (Pi Zero 2 W)  │
        │  SSID: Red-Comunitaria  │          │  SSID: Red-Comunitaria  │
        │  ch.6  GW 10.42.0.1     │          │  ch.6  GW 10.42.0.1     │
        │  portal.red.local:8080  │          │  portal.red.local:8080  │
        │  ┌───────────────────┐  │          │  ┌───────────────────┐  │
        │  │ hostapd (AP abie… │  │          │  │  (idéntico)       │  │
        │  │ dnsmasq (DHCP+DNS │  │          │  │                   │  │
        │  │  wildcard→10.42.0.│  │          │  │                   │  │
        │  │ iptables 80→8080  │  │          │  └───────────────────┘  │
        │  │ dtn-node (Go+SQLi │  │          │  ┌───────────────────┐  │
        │  │  + index.html emb)│  │          │  │ dtn-node (Go+SQLi │  │
        │  └───────────────────┘  │          │  └───────────────────┘  │
        └───────────△─────────────┘          └───────────△─────────────┘
                    │ Wi-Fi (200 m)                      │ Wi-Fi
                    ▼                                    ▼
        ┌─────────────────────────────────────────────────────────┐
        │           MULA (navegador móvil del usuario)            │
        │  http://portal.red.local:8080  ← MISMO ORIGEN SIEMPRE   │
        │  IndexedDB «dtn_local_store»:                           │
        │   · identity  (X25519 + Ed25519 + alias)                │
        │   · inbox     (mensajes descifrados propios)            │
        │   · transit_queue (≤100 sobres ajenos que transporta)   │
        │  POST /api/v1/sync al cargar:                           │
        │   push(transit_queue) + known_ids → pull(≤limit)         │
        │   mios(dest_hint==mio)→descifrar→inbox ; resto→transit   │
        └─────────────────────────────────────────────────────────┘
```

**Flujo de un mensaje (E2E):**

1. Alice se registra una vez (alias + par de claves generado en su dispositivo; las privadas jamás salen de `IndexedDB`).
2. Alice obtiene el directorio del nodo, elige a Bob, escribe ≤128 B. Su cliente: firma (Ed25519) → empaqueta `{msg, alias, ed_pub, sig, ts}` → cifra con X25519 efímero hacia la pubkey de Bob → construye el sobre con `dest_hint` de Bob → `id = SHA-256(canónico)`.
3. El sobre entra al nodo A vía `POST /api/v1/sync` (push). El nodo solo ve bytes aleatorios y un hint.
4. Cualquier usuario que sincronice con el nodo A (incluida Alice) se lleva el sobre en `pull` si no lo conoce → lo carga en su `transit_queue` (mula).
5. Ese usuario camina hasta el nodo B y sincroniza: el sobre se vacía (push) en el nodo B.
6. Bob sincroniza con el nodo B, detecta `dest_hint` propio, descifra (X25519 ECDH → `crypto_box.open`), verifica la firma Ed25519 de Alice y el mensaje pasa a su `inbox`.

---

## 3. Especificación del protocolo (resumen ejecutivo)

> La especificación completa y normativa vive en `docs/protocolo.md` (Sprint 0). Este resumen es vinculante.

### 3.1 Envelope (Fase 1, JSON)

```json
{
  "v": 1,
  "id": "b6c1…64-hex…",
  "dest_hint": "9f3ab02c1d77e4c1",
  "created_at": 1759500000,
  "ttl": 604800,
  "payload": "BASE64( eph_pub(32B) ‖ nonce(24B) ‖ box( inner_json, MAC=16B ) )"
}
```

`inner_json` (visible solo tras descifrar): `{"m": "texto ≤128B", "a": "alias", "k": "ed25519_pub_b64", "s": "firma_b64_sobre_json_sin_s", "t": 1759500000}`.

### 3.2 Tablas SQLite (`node_storage.db`)

```sql
CREATE TABLE envelopes (
  id        TEXT PRIMARY KEY,
  dest_hint TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ttl       INTEGER NOT NULL,
  payload   TEXT NOT NULL
);
CREATE INDEX idx_envelopes_dest_hint ON envelopes(dest_hint);
CREATE INDEX idx_envelopes_expiry    ON envelopes(created_at, ttl);

CREATE TABLE directory (
  pubkey    TEXT PRIMARY KEY,   -- ed25519 (identidad)
  x25519    TEXT NOT NULL,      -- pubkey de cifrado
  alias     TEXT NOT NULL,
  last_seen INTEGER NOT NULL
);
```

### 3.3 API (superficie exacta exigida por el prompt)

| Método y ruta | Comportamiento |
|---|---|
| `GET /` | Sirve `index.html` embebido (`embed.FS`). Host no canónico → `301` a `portal.red.local:8080` |
| `GET /generate_204` | `302 → http://portal.red.local:8080/` (Android; **nunca** responder 204 aquí) |
| `GET /hotspot-detect.html` | `302 → http://portal.red.local:8080/` (iOS) |
| `GET /api/v1/directory` | Lista `alias+pubkey+x25519+last_seen` (≤500, por `last_seen DESC`) |
| `POST /api/v1/directory` | Upsert de usuario; `last_seen=now` |
| `POST /api/v1/sync` | Entrada `{known_ids[], push_envelopes[], limit}` → `INSERT OR IGNORE` push; SELECT sobres vigentes (`created_at+ttl ≥ now`) no incluidos en `known_ids`, por `created_at DESC` `LIMIT limit` → `{status:"ok", pull_envelopes[]}` |

Worker de limpieza: goroutine + `time.Ticker` cada 15 min: `DELETE FROM envelopes WHERE created_at + ttl < now`.

### 3.4 Mapeo a Fase 2/3 (Módulo D, documentación embebida en el código)

- **BLE (bitchat, Fase 2):** doc-comment en el tipo Go `Envelope` y en el equivalente JS con la tabla JSON→CBOR, el layout de trama L2CAP CoC y la semántica `hop_count ≤ 7` (campo reservado, 0 en Fase 1).
- **LoRa (SX1262, Fase 3):** cálculo de tamaño CBOR, presupuesto de 222 B/trama y el formato de fragmento de 1 B (`win_id|idx|total`) para mensajes de 2 tramas.

---

## 4. Estructura del repositorio

```
offgrid/
├── prompt_maestro_de_desarrollo.md      # fuente (no tocar)
├── PLAN_DESARROLLO.md                   # este documento
├── README.md                            # visión general + guía rápida
├── docs/
│   ├── protocolo.md                     # spec normativa del Envelope (Sprint 0)
│   ├── COMPILACION.md                   # build/run/test paso a paso (Sprint 4)
│   └── hardware.md                      # montaje solar/LiFePO4 + provisionamiento
├── node/                                # Módulo B — daemon Go
│   ├── go.mod                           # module offgrid/dtn-node (Go ≥1.22)
│   ├── main.go                          # arranque, flags, señales
│   ├── internal/
│   │   ├── storage/storage.go           # SQLite (modernc.org/sqlite, WAL, busy_timeout)
│   │   ├── api/handlers.go              # endpoints + middleware host canónico + límites
│   │   ├── api/middleware.go
│   │   ├── cleanup/cleanup.go           # ticker 15 min
│   │   └── envelope/envelope.go         # tipo Envelope + validación + doc Fase 2/3
│   ├── web/index.html                   # Módulo C (fuente de la SPA, embebida)
│   ├── build.sh                         # cross-compile linux/arm64 + linux/arm
│   └── storage_test.go / api_test.go …  # tests unitarios
├── raspberry/                           # Módulo A — infraestructura
│   ├── hostapd/hostapd.conf             # → /etc/hostapd/hostapd.conf
│   ├── dnsmasq/dnsmasq.conf             # → /etc/dnsmasq.conf
│   ├── firewall/iptables.sh             # REDIRECT 80→8080, aislamiento clientes
│   ├── power/                           # config.txt (HDMI/LEDs/BT), dtn-power.service
│   ├── systemd/dtn-node.service         # daemon en /opt/dtn-node
│   └── provision.sh                     # provisioning idempotente paso a paso
└── tests/
    ├── crypto_roundtrip.mjs             # tweetnacl: cifrar/firmar/verificar/descifrar
    └── sync_e2e.sh                      # curl: dos clientes + mula contra instancia local
```

---

## 5. Plan de implementación por sprints

> Orden elegido para poder desarrollar y probar **sin hardware** hasta el Sprint 3: primero el backend (probable con `curl` en localhost), luego el frontend (probable contra el backend local), después la infraestructura de Pi.

### Sprint 0 — Protocolo y andamiaje (0,5 día)

| # | Tarea |
|---|---|
| 0.1 | `git init`, `.gitignore`, estructura de carpetas del §4, `README.md` mínimo |
| 0.2 | `docs/protocolo.md`: spec normativa del Envelope — campos, derivaciones (`id`, `dest_hint`), orden sign-then-encrypt, tabla de límites del §1.7, cálculo de bytes Fase 1/2/3, formato de fragmento LoRa, layout L2CAP y semántica `hop_count` |
| 0.3 | Redacción del modelo de amenazas (§1.2) con la limitación del `dest_hint` como riesgo aceptado |

**Verificación:** el documento permite implementar Módulos B y C sin decisiones pendientes.

### Sprint 1 — Módulo B: daemon Go (1,5 días)

| # | Tarea | Detalles clave |
|---|---|---|
| 1.1 | Módulo Go + `internal/envelope` | Tipo `Envelope` con validación (tamaños, rangos TTL, hex/base64 bien formados) y doc-comments de mapeo Fase 2/3 (Módulo D, parte 1) |
| 1.2 | `internal/storage` | `modernc.org/sqlite` (puro Go, sin CGO), pragmas `journal_mode=WAL`, `busy_timeout=5000`, esquema del §3.2, `SetMaxOpenConns(1)` (serializa escrituras; carga trivial para una Zero 2 W) |
| 1.3 | `internal/api` | Endpoints del §3.3 exactos; middleware host canónico con exención de endpoints cautivos (§1.1); límites: body ≤1 MiB, push ≤100, `limit` ≤200, `known_ids` ≤500, saneamiento de alias |
| 1.4 | `internal/cleanup` | Ticker 15 min + ejecución al arranque |
| 1.5 | `main.go` + `embed.FS` | Flags (`-addr`, `-db`), sirvió `web/index.html` (placeholder mínimo en este sprint), graceful shutdown |
| 1.6 | Tests unitarios | Dedup `INSERT OR IGNORE`, exclusión por `known_ids`, expiración TTL en el SELECT y en el cleaner, redirección canónica, límites, `302` correcto de `/generate_204` (no 204) |
| 1.7 | `build.sh` | `GOOS=linux GOARCH=arm64` (Zero 2 W, primario) y `GOARCH=arm` (respaldo 32 bits), binario estático |

**Verificación:** `go test ./...` verde; `curl` contra `localhost:8080` ejercita el ciclo push→pull→limpieza completo.

### Sprint 2 — Módulo C: SPA + motor criptográfico (2 días)

| # | Tarea | Detalles clave |
|---|---|---|
| 2.1 | Esqueleto `web/index.html` | Archivo único, HTML+CSS+JS inline, tipografía del sistema (cero assets externos), responsive, etiquetas en español |
| 2.2 | tweetnacl embebido | Fuente completa inline + helpers base64/hex; sin `eval` |
| 2.3 | Capa `IndexedDB` | `dtn_local_store` v1: `identity` (singleton), `inbox`, `transit_queue`; migraciones por versión |
| 2.4 | Identidad | Registro de alias → generación de pares X25519/Ed25519 → `POST /api/v1/directory`; **respaldo manual** de la semilla (texto copiable + importación) para sobrevivir a limpieza del navegador |
| 2.5 | Cifrado/descifrado | Construcción de sobre según §3.1 (firma → cifrado → hint → id); descifrado con verificación de firma; rechazo silencioso de sobres corruptos |
| 2.6 | Motor de mula | Sync al cargar + botón manual: push `transit_queue` + `known_ids` (inbox ∪ transit ∪ vistos) → pull → clasificar: propios→descifrar→`inbox`; ajenos→`transit_queue` con FIFO≤100 |
| 2.7 | UI completa | Pantalla registro / selector de destinatario (directorio) / composición con contador 128 B / bandeja con remitente y hora / panel de telemetría *"Sobres ajenos en tránsito: X / Capacidad: 100"* + estado de última sync / banner "ábrelo en tu navegador completo" (§1.4) |
| 2.8 | `tests/crypto_roundtrip.mjs` | Round-trip determinista en Node: dos identidades, envío, transporte, recepción, verificación |

**Verificación:** en el navegador de desarrollo contra `go run .`: Alice→nodo→(segunda pestaña con perfil limpio como mula)→nodo simulado→Bob descifra. Round-trip Node verde.

### Sprint 3 — Módulo A: infraestructura Raspberry Pi (1 día)

| # | Tarea | Detalles clave |
|---|---|---|
| 3.1 | `hostapd.conf` | AP abierto, SSID `Red-Comunitaria`, canal 6, `ap_isolate=1`, `wlan0`, país configurable |
| 3.2 | `dnsmasq.conf` | DHCP `10.42.0.50–250` (12 h), opciones 3 y 6 → `10.42.0.1`, `address=/#/10.42.0.1`, `address=/portal.red.local/10.42.0.1`, `bind-interfaces`, `no-resolv` |
| 3.3 | `firewall/iptables.sh` | `REDIRECT 80→8080` en `wlan0` (PREROUTING), política FORWARD DROP (aislamiento cliente-a-cliente que refuerza `ap_isolate`), persistencia |
| 3.4 | `power/` | `config.txt`: `dtoverlay=disable-bt`, LEDs off (`act_led_trigger=none`, `act_led_activelow=on`…), `dtparam=audio=off`, HDMI apagado (`hdmi_blanking=2` + servicio oneshot `vcgencmd display_power 0`), governor `powersave`; nota de dimensionado solar (~1 W continuo) |
| 3.5 | `provision.sh` | Idempotente: detecta Bookworm/NM (lo deshabilita) vs legado; IP estática `10.42.0.1/24` en `wlan0`; instala configs; `dtn-node.service` con el binario en `/opt/dtn-node`; verificación por paso |
| 3.6 | `systemd/dtn-node.service` | `After=network-online.target`, `Restart=always`, `WatchdogSec`, usuario sin privilegios + permisos del directorio de datos |

**Verificación en hardware (o VM):** el teléfono ve el portal cautivo automáticamente al conectarse; `http://portal.red.local:8080` responde; un segundo dispositivo no puede hablar con el primero; tras reinicio de la Pi todo se restaura solo.

### Sprint 4 — Integración E2E, Módulo D final y documentación (1,5 días)

| # | Tarea |
|---|---|
| 4.1 | Prueba física de dos nodos: mensaje Alice→Bob transportado por una mula que camina entre ambos; verificación de persistencia de `IndexedDB` entre nodos (mismo origen) |
| 4.2 | Prueba en mini-navegador cautivo (Android e iOS) y con el banner de navegador completo |
| 4.3 | `tests/sync_e2e.sh` reproducible sin hardware (dos instancias + `/etc/hosts`) |
| 4.4 | Completar doc-comments de Mapeo Fase 2/3 en Go y JS (Módulo D, parte 2) y su resumen en `docs/protocolo.md` |
| 4.5 | `docs/COMPILACION.md`: compilación, despliegue, ejecución y pruebas **paso a paso**; `docs/hardware.md` |
| 4.6 | Hardening final: revisión de límites, sanitizer de entradas, tamaño del binario, arranque en frío |

**Verificación:** checklist de aceptación del §8 completo.

---

## 6. Estrategia de pruebas

| Nivel | Alcance | Herramienta |
|---|---|---|
| Unitario (Go) | Storage, dedup, TTL, exclusión `known_ids`, middleware, límites, endpoints cautivos | `go test ./...` |
| Unitario (JS) | Round-trip criptográfico, derivación `id`/`dest_hint`, FIFO de `transit_queue` | Node + tweetnacl (`tests/crypto_roundtrip.mjs`) |
| Integración (sin hardware) | Ciclo push→pull→limpieza; simulación de mula con dos "clientes" | `curl` (`tests/sync_e2e.sh`) |
| Navegador | Flujo completo Alice→mula→Bob; UI responsive; almacenamiento persistente | DevTools + dos perfiles de navegador |
| Hardware | Portal cautivo auto-detectado (Android/iOS), aislamiento de clientes, mismo origen entre 2 nodos, arranque en frío, consumo energético | Pi Zero 2 W ×2 + teléfono real |
| Adversarial local | Sobres corruptos, ids duplicados, TTL vencidos, body sobredimensionado | Tests Go + curl |

---

## 7. Riesgos y mitigaciones

| Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|
| Mini-navegador cautivo con almacenamiento aislado/no persistente | Alta | Medio | Banner "abrir en navegador completo"; flujo documentado; pruebas en ambos contextos (§1.4) |
| Nodo malicioso vincula `dest_hint`↔alias vía directorio | Media | Medio | Documentado como riesgo aceptado; roadmap: hints rotatorios en Fase 2 (§1.2) |
| Pérdida de identidad al borrar datos del navegador | Media | Alto | Respaldo/importación manual de semilla (tarea 2.4) |
| `X25519`/`Ed25519` inconsistentes en WebCrypto móvil | Alta | Alto | tweetnacl embebido, camino único (§1.3) |
| NetworkManager (Bookworm) rompe hostapd/dnsmasq | Alta | Alto | `provision.sh` lo detecta y deshabilita (§1.6) |
| Usuario entra por IP y fragmenta su origen | Media | Medio | Middleware de host canónico (§1.1) |
| Sobre LoRa > 222 B en Fase 3 | Cierta | Bajo (futuro) | Fragmentación bitchat decidida y documentada (§1.5) |
| Corrupción/escritura de SD por WAL | Baja | Medio | WAL + `MaxOpenConns(1)`; journal volátil opcional; SD de calidad industrial |
| Llenado del nodo por abuso (AP abierto) | Media | Medio | Límites por petición, TTL máx 30 días, cleaner 15 min, tope de sobres por nodo (hardening 4.6) |

---

## 8. Trazabilidad de criterios de aceptación

| Criterio del prompt maestro | Cubierto por |
|---|---|
| `/etc/hostapd/hostapd.conf` (AP abierto, canal 6, `ap_isolate=1`) | 3.1 |
| `/etc/dnsmasq.conf` (DHCP 50–250, GW/DNS 10.42.0.1, wildcards) | 3.2 |
| `iptables` (80→8080, `/generate_204`, `/hotspot-detect.html`) | 3.3 + 1.3 (endpoints cautivos en Go) |
| Optimización de energía (HDMI, LEDs, solar/LiFePO4) | 3.4 |
| SQLite: tablas, columnas e índices exactos | 1.2, 3.2(spec §3.2) |
| Endpoints API exactos (`GET /`, cautivos, directory GET/POST, sync) | 1.3, 1.5, 1.6 |
| Worker de limpieza 15 min | 1.4 |
| `embed.FS` con `index.html` único | 1.5 |
| X25519+Ed25519 client-side, servidor sin claves | 2.2–2.5 |
| `dtn_local_store`: identity / inbox / transit_queue (50–100) | 2.3, 2.6 |
| Sync automático al cargar + clasificación propios/ajenos | 2.6 |
| UI: registro, directorio, redacción, bandeja, telemetría de la mula | 2.7 |
| Mapeo bitchat L2CAP (`hop_count ≤ 7`) y LoRa CBOR ≤ 222 B | 0.2, 1.1, 4.4 |
| Código completo sin placeholders `// TODO` | Definition of Done por tarea |
| Instrucciones paso a paso de compilación/ejecución/prueba | 4.5 (`docs/COMPILACION.md`) |

**Definition of Done (cada tarea):** código final sin TODOs, tests asociados en verde, revisado con `gofmt`/`go vet` (Go) y probado en el navegador objetivo (JS).

---

## 9. Estimación y orden de ejecución

| Sprint | Contenido | Duración | Dependencia |
|---|---|---|---|
| 0 | Protocolo + andamiaje | 0,5 d | — |
| 1 | Backend Go (Módulo B) | 1,5 d | 0 |
| 2 | SPA + cripto (Módulo C) | 2 d | 1 |
| 3 | Infraestructura Pi (Módulo A) | 1 d | 1 (binario) |
| 4 | Integración E2E + docs (Módulo D) | 1,5 d | 2, 3 |
| **Total** | | **6,5 d** | |

Los sprints 2 y 3 pueden solaparse (el 3 solo necesita el binario del 1). Sin hardware disponible, el 3 se entrega con provisionamiento verificado en imagen Raspberry Pi OS Bookworm Lite en VM/SD y la prueba física queda como checklist listo para ejecutar.

---

## 10. Fuera de alcance (puntero a Fases 2/3)

- **Fase 2 (BLE):** app Capacitor/Ionic con canal L2CAP CoC, `hop_count`, gossip mesh entre teléfonos sin nodo.
- **Fase 3 (LoRa):** bridge SX1262 915 MHz, CBOR, fragmentación, repetidor solar autónomo.
- Hints rotatorios (privacidad reforzada), ratchet de cifrado, PWA/service worker, i18n, QR de identidad.
- Todo lo anterior ya tiene anclas de diseño en `docs/protocolo.md` (Módulo D) para no reescribir el Envelope.
