# Mensajería P2P Segura con Identidad DNIe

> **Chat descentralizado, cifrado de extremo a extremo y autenticado criptográficamente mediante el Documento Nacional de Identidad electrónico (DNIe) español.**

Esta aplicación es una prueba de concepto (PoC) que demuestra cómo elevar la confianza en las comunicaciones digitales vinculando la identidad de red directamente a una tarjeta inteligente gubernamental. Combina una interfaz de terminal moderna (TUI) con criptografía de curva elíptica y almacenamiento local cifrado.


## Características Principales

  * **Identidad Verificada:** Uso de certificados X.509 del DNIe para autenticar el *handshake* inicial. Sabes con certeza con quién hablas (Certificado verificado por la AC Raíz de la Dirección General de la Policía).
  * **Arquitectura Híbrida de Seguridad:**
      * **QUIC/TLS 1.3:** Transporte fiable y cifrado base mediante el protocolo QUIC (usando `aioquic`).
      * **Noise IK sobre QUIC:** Autenticación de identidad DNIe mediante el patrón `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
      * **Cifrado WireGuard-style:** Doble capa de cifrado ChaCha20-Poly1305 en la capa de aplicación, independiente de TLS.
  * **PFS (Perfect Forward Secrecy):** Las claves de sesión son efímeras; si te robasen una clave de sesión mañana, no podrán descifrar los chats de hoy.
  * **Anti-Replay:** Protección contra ataques de repetición mediante ventana deslizante de 64 bits (estilo WireGuard).
  * **Privacidad en Reposo:** La base de datos local (SQLite) guarda los datos cifrados completamente usando una clave derivada (`HKDF`) de una firma digital única del DNIe. Sin la tarjeta física, los datos son ilegibles.
  * **P2P & Roaming:** Arquitectura sin servidor central. Soporta cambios de IP (WiFi/Ethernet) sin interrumpir la sesión criptográfica.
  * **Interfaz TUI Moderna:** Desarrollada con `Textual`, ofrece soporte para ratón, scroll y redimensionado en la terminal.

-----

## Requisitos Previos

### Hardware

  * **Lector de Tarjetas Inteligentes** compatible con PC/SC.
  * **DNI electrónico (DNIe)** válido y con los certificados activos.

### Software

1.  **Python 3.12+**
2.  **Drivers del DNIe:**
      * **Linux (Debian/Ubuntu):**
        ```bash
        sudo apt install opensc pcscd
        ```
      * **Windows/Mac:** Instalar `opensc` desde [OpenSC](https://github.com/OpenSC/OpenSC/wiki).

-----

## Instalación

1.  **Clonar el repositorio:**

    ```bash
    git clone https://github.com/tu-usuario/secure-dnie-messaging.git
    cd secure-dnie-messaging
    ```

2.  **Crear entorno virtual e instalar dependencias:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # O venv\Scripts\activate en Windows
    pip install -r requirements.txt
    ```

3.  **Configurar Certificados:**
    Para validar la cadena de confianza, debes colocar los certificados raíz de la policía en la carpeta `certs/`.

      * El programa busca archivos `.crt` o `.pem` en `certs/`.
      * *Nota:* Se incluyen algunos por defecto, pero se recomienda actualizarlos desde la web oficial del DNIe.

4.  **Configurar Firewall (Windows):**
    En Windows, debes añadir una regla en el firewall para permitir conexiones entrantes UDP en el puerto que uses (por defecto 443):

    ```powershell
    # Ejecutar como Administrador en PowerShell
    New-NetFirewallRule -DisplayName "DNIe Messaging" -Direction Inbound -Protocol UDP -LocalPort 443 -Action Allow
    ```

    O desde el Panel de Control: *Firewall de Windows > Configuración avanzada > Reglas de entrada > Nueva regla > Puerto > UDP > 443*.

-----

## Uso

### Ejecución Normal (Requiere DNIe)

Conecta tu lector e inserta tu DNIe antes de ejecutar:

```bash
python src/main.py
```

*Si usas Linux y el puerto por defecto (443), necesitarás `sudo` o cambiar el puerto con `-p`.*

### Opciones de Línea de Comandos

| Argumento | Descripción |
| :--- | :--- |
| `-p`, `--port` | Puerto QUIC/UDP para escuchar (Por defecto: 443). |
| `-b`, `--bind` | Dirección IP de escucha (Por defecto: 0.0.0.0). |
| `-d`, `--data` | Directorio para la base de datos cifrada (Por defecto: `./data`). |
| `--mock` | **Modo Desarrollo:** Simula un DNIe virtual (Útil para probar la UI sin lector). |

-----

## Arquitectura del Sistema

El proyecto implementa una arquitectura de seguridad en capas:

```
┌─────────────────────────────────────────────────────────┐
│                    Aplicación (TUI)                     │
├─────────────────────────────────────────────────────────┤
│        Cifrado ChaCha20-Poly1305 (WireGuard-style)      │  ← Capa 3: Cifrado App
├─────────────────────────────────────────────────────────┤
│              Noise IK (Autenticación DNIe)              │  ← Capa 2: Identidad
├─────────────────────────────────────────────────────────┤
│                   QUIC / TLS 1.3                        │  ← Capa 1: Transporte
└─────────────────────────────────────────────────────────┘
```

### Módulos

1.  **`smartcard_dnie.py`**: Capa de abstracción sobre `PKCS#11`. Maneja la comunicación a bajo nivel con el chip del DNIe, extracción de certificados y firmas RSA-SHA256 dentro de la tarjeta.
2.  **`protocol.py`**: Máquina de estados del protocolo **Noise IK**. Gestiona el intercambio de claves Diffie-Hellman (X25519), cifrado ChaCha20-Poly1305 y protección anti-replay.
3.  **`network.py`**: Motor asíncrono sobre `asyncio` y `aioquic`. Gestiona conexiones QUIC/TLS 1.3, handshake Noise IK sobre streams QUIC, y descubrimiento de pares mediante mDNS/Zeroconf.
4.  **`storage.py`**: Capa de persistencia con `aiosqlite`. Utiliza cifrado simétrico para asegurar que nada se escriba en disco en texto plano.
5.  **`tui.py`**: Interfaz gráfica de terminal con `Textual`. Separa la lógica de presentación del núcleo criptográfico.

### Flujo de Seguridad

1.  **Descubrimiento:** Los peers se anuncian y descubren mediante mDNS (`_dni-im._udp.local.`).
2.  **Conexión QUIC:** Se establece un túnel QUIC con TLS 1.3 (certificados autofirmados).
3.  **Handshake Noise IK:** Sobre el Stream 0 de QUIC, se realiza el handshake Noise que:
    - Intercambia claves efímeras X25519.
    - Autentica la identidad mediante certificados DNIe firmados por la DGP.
    - Deriva claves de sesión ChaCha20-Poly1305.
4.  **Mensajería Cifrada:** Los mensajes se cifran con ChaCha20-Poly1305 *antes* de enviarlos por QUIC, proporcionando cifrado end-to-end independiente del transporte.

-----

## Aviso Legal y Seguridad

Esta aplicación es un proyecto educativo y de investigación. Aunque utiliza primitivas criptográficas robustas (`cryptography.io`, `aioquic`), **no ha sido auditada por terceros**.

  * No utilices este software para comunicaciones críticas sin una revisión previa.
  * El DNIe es un documento oficial; asegúrate de no compartir tu PIN con nadie. La aplicación nunca almacena ni transmite el PIN fuera de la memoria del proceso local.

-----
