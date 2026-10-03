# Prompt Maestro para Desarrollo: Sistema de Mensajería DTN Off-Grid (Fase 1 + Hoja de Ruta Fase 2/3)

---

## 1. Contexto y Rol del Asistente
Actúa como un **Ingeniero de Software Senior en Sistemas Distribuidos, Redes Embebidas y Criptografía Aplicada**. Tu objetivo es generar el código, configuraciones de infraestructura y arquitectura técnica para un **sistema de mensajería asíncrono, desconectado (off-grid), descentralizado y tolerante a demoras (DTN / Store-and-Forward)**.

El sistema debe operar sin acceso a Internet, satélites ni redes celulares. Utiliza puntos de acceso Wi-Fi fijos en **Raspberry Pi Zero 2 W** (con portal cautivo) como buzones ciegos (*dead drops*), y aprovecha a los usuarios que se desplazan físicamente entre zonas como **mulas de datos (*sneakernet*)** utilizando únicamente el navegador web móvil y `IndexedDB`.

---

## 2. Pautas Estrictas de Diseño

1. **Cero Dependencia de Internet:** No se admiten CDNs externas, llamadas a APIs en la nube, ni librerías que requieran resolución DNS pública. Todo asset, script o fuente debe ser servido localmente desde la Raspberry Pi.
2. **Cero Confianza en la Infraestructura (Zero-Trust Intermediaries):** Los nodos fijos (Raspberry Pi) y los celulares de tránsito son canales ciegos y no confiables. No deben conocer el contenido, el remitente real ni la identidad completa del destinatario.
3. **Persistencia Cross-Node (Mismo Origen Web):** Todas las Raspberry Pi deben forzar el mismo FQDN virtual local (`http://portal.red.local:8080`) y la misma IP de gateway (`10.42.0.1`) para garantizar que `IndexedDB` mantenga el mismo origen lógico cuando el usuario transite de un nodo a otro.
4. **Formato Compatible con Protocolo bitchat / Nostr:** Los mensajes deben serializarse como eventos/sobres atómicos e independientes (máximo ~180-250 bytes en payload estándar) para permitir su migración futura directa a **BLE L2CAP CoC** y paquetes **LoRa P2P (SX1262)** sin reescribir la estructura de datos.

---

## 3. Entregables Requeridos

### Módulo A: Configuración de Red en Raspberry Pi OS Lite
Genera los archivos de configuración y comandos de provisioning para Linux:
* **`/etc/hostapd/hostapd.conf`**: Configuración de `wlan0` como Access Point abierto (`SSID: Red-Comunitaria`, canal 6, `ap_isolate=1`).
* **`/etc/dnsmasq.conf`**: Servidor DHCP en rango `10.42.0.50` a `10.42.0.250`, asignación de DNS/Gateway `10.42.0.1` y wildcard DNS spoofing (`address=/#/10.42.0.1` y `address=/portal.red.local/10.42.0.1`).
* **Reglas de Firewall (`iptables`)**: Script bash con redirección del puerto 80 al 8080 en `wlan0` y captura de endpoints de comprobación de conectividad de Android (`/generate_204`) e iOS (`/hotspot-detect.html`).
* **Optimizaciones de energía para Raspberry Pi Zero 2 W**: Desactivación de salida HDMI y LEDs de actividad para funcionamiento con panel solar y batería LiFePO4.

---

### Módulo B: Backend Daemon del Nodo (Go)
Desarrolla un servidor HTTP autocontenido en **Go** compilable estáticamente (`CGO_ENABLED=1` o driver SQLite embebido puro en Go como `modernc.org/sqlite`):
1. **Base de Datos SQLite (`node_storage.db`):**
   * Tabla `envelopes`: `id` (TEXT PRIMARY KEY), `dest_hint` (TEXT), `created_at` (INTEGER), `ttl` (INTEGER), `payload` (TEXT).
   * Tabla `directory`: `pubkey` (TEXT PRIMARY KEY), `alias` (TEXT), `last_seen` (INTEGER).
   * Índices en `dest_hint` y `(created_at, ttl)`.
2. **Endpoints de la API:**
   * `GET /`: Servir el archivo `index.html` estático embebido (vía `embed.FS`).
   * `GET /generate_204`, `GET /hotspot-detect.html`: Responder con redirect HTTP 302 hacia `http://portal.red.local:8080/`.
   * `GET /api/v1/directory`: Retornar lista de usuarios conocidos (alias + pubkey + last_seen).
   * `POST /api/v1/directory`: Registrar o refrescar usuario en el nodo.
   * `POST /api/v1/sync`: 
     * **Entrada JSON:** `{ "known_ids": [...], "push_envelopes": [...], "limit": 50 }`.
     * **Acción:** `INSERT OR IGNORE` de los `push_envelopes`. Consulta de hasta `limit` sobres vigentes no presentes en `known_ids`.
     * **Salida JSON:** `{ "status": "ok", "pull_envelopes": [...] }`.
3. **Worker de Limpieza:** Goroutine con `time.Ticker` que elimine cada 15 minutos sobres con `created_at + ttl < now()`.

---

### Módulo C: Frontend SPA Web + Motor Criptográfico (Vanilla JS / Web Crypto)
Genera un archivo único `index.html` (HTML + CSS inline + JS) que opere como la interfaz del usuario en el portal cautivo:
1. **Manejo Criptográfico (E2EE Client-Side):**
   * Uso de `window.crypto.subtle` (o una implementación embebida de `tweetnacl.js` inyectada directamente en el archivo) para par de claves **X25519** (cifrado) y **Ed25519** (firma/identidad).
   * El servidor jamás tiene acceso a las claves privadas.
2. **Almacenamiento Local (`IndexedDB`):**
   * Base de datos `dtn_local_store` con los almacenes:
     * `identity`: Claves del usuario y alias.
     * `inbox`: Mensajes descifrados con éxito destinados al usuario actual.
     * `transit_queue`: **Buffer de la Mula.** Sobres ajenos en tránsito (máximo 50-100 sobres).
3. **Flujo de Intercambio Automático (Mula de Datos):**
   * Al cargar la página, ejecutar `POST /api/v1/sync`:
     * Enviar los sobres acumulados en `transit_queue` y la lista de IDs conocidos.
     * Recibir `pull_envelopes`. Si un sobre coincide con el `dest_hint` del usuario, intentar descifrar y mover a `inbox`; si no coincide, almacenarlo en `transit_queue` para transportarlo al próximo nodo.
4. **Interfaz de Usuario (UI Minimalista Responsive):**
   * Pantalla de registro de alias e inicialización de identidad criptográfica.
   * Selector de destinatario mediante el directorio público del nodo.
   * Campo de redacción y envío de mensajes.
   * Bandeja de entrada con mensajes descifrados.
   * Panel de telemetría de la mula: *"Sobres ajenos en tránsito transportados: X / Capacidad: Y"*.

---

### Módulo D: Interfaces de Abstracción para Fase 2 (BLE) y Fase 3 (LoRa)
Documenta en el código cómo el sobre universal (`Envelope`) debe ser mapeado:
1. **Alineación con bitchat (Fase 2):** Estructura del canal de datos binario L2CAP CoC y control de saltos (`hop_count <= 7`) para Capacitor/Ionic.
2. **Alineación con LoRa P2P SX1262 (Fase 3):** Empaquetado binario (CBOR) que mantenga el payload por debajo de la MTU de 222 bytes por trama de radiofrecuencia a 915 MHz.

---

## 4. Criterios de Aceptación
* El código debe estar completamente escrito, listo para producción (sin placeholders estilo `// TODO: implementar aquí`).
* Debe incluir instrucciones precisas de compilación, ejecución y prueba paso a paso.