"""
Punto de Entrada Principal (Main Entry Point)
---------------------------------------------
Este módulo orquesta la inicialización de la aplicación de mensajería segura.
Sus responsabilidades incluyen:
1. Gestionar los argumentos de línea de comandos.
2. Ejecutar la fase de autenticación con tarjeta inteligente (DNIe).
3. Derivar claves criptográficas seguras para el almacenamiento local.
4. Inicializar la base de datos, la red y la interfaz de usuario (TUI).
5. Gestionar el cierre limpio de recursos (sockets, DB, mDNS).
"""

import sys
import asyncio
import argparse
import os
from zeroize import zeroize1
from network import UDPProtocol, SessionManager, DiscoveryService
from storage import Storage
from tui import MessengerTUI, DNIeLoginApp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Configuración de Argumentos ---
parser = argparse.ArgumentParser(description="DNIe Secure Messenger")
parser.add_argument('-p', '--port', type=int, default=443, help="Puerto UDP para escuchar conexiones (Default: 443)")
parser.add_argument('-b', '--bind', type=str, default="0.0.0.0", help="Dirección IP de escucha (Default: 0.0.0.0 para todas las interfaces)")
parser.add_argument('-d', '--data', type=str, default="data", help="Directorio para almacenar la base de datos cifrada")
parser.add_argument('--mock', type=str, help="Modo de prueba: Simula un DNIe con el nombre de usuario dado (Ej: --mock User1)")
args = parser.parse_args()

def ensure_cert_structure():
    """
    Verifica y crea la estructura de directorios necesaria para los certificados.
    
    Crea la carpeta 'certs/' si no existe y añade un archivo de instrucciones.
    Esto es vital para que la validación de la cadena de confianza del DNIe funcione.
    """
    if not os.path.exists('certs'):
        os.makedirs('certs')
        with open('certs/README.txt', 'w') as f:
            f.write("Coloca aqui los certificados CA (Root e Intermedios) del DNIe en formato .pem o .crt\n")

def derive_storage_key(signature_bytes):
    """
    Deriva una clave simétrica robusta a partir de una firma digital.

    Utiliza HKDF (HMAC-based Key Derivation Function) para transformar la firma
    RSA de alta entropía generada por el DNIe en una clave de 32 bytes
    apta para cifrado simétrico AES/Fernet.

    Args:
        signature_bytes (bytes): La firma digital cruda generada por la tarjeta.

    Returns:
        bytearray: Una clave de 32 bytes (mutable para poder zeroizar).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None, # No usamos salt porque la fuente (firma RSA) ya tiene alta entropía
        info=b'DNIe-Storage-Encryption-Key', # Contexto para la derivación
    )
    return bytearray(hkdf.derive(signature_bytes))

async def main_async(identity_data):
    """
    Bucle principal asíncrono de la aplicación.

    Args:
        identity_data (tuple): Contiene (user_id, pruebas_identidad, firma_storage, clave_privada_estatica).
    """
    user_id, proofs, storage_signature, local_static_key = identity_data
    
    print("🔐 Derivando clave de almacenamiento desde la firma DNIe...")
    storage_key = derive_storage_key(storage_signature)
    
    # Inicialización del almacenamiento cifrado
    storage = Storage(key_bytes=storage_key, data_dir=args.data)
    await storage.init()
    
    # Gestor de sesiones criptográficas Noise
    sessions = SessionManager(local_static_key, storage, local_proofs=proofs)
    
    # Inicialización del protocolo de red
    # Usamos un callback lambda simple para logs antes de que la UI arranque
    proto = UDPProtocol(sessions, lambda a,m: None, lambda t: print(f"LOG: {t}"), on_ack_received=None)
    
    loop = asyncio.get_running_loop()
    transport = None
    discovery = None

    try:
        print(f"🔌 Vinculando socket UDP a {args.bind}:{args.port}...")
        # Creamos el endpoint UDP
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto,
            local_addr=(args.bind, args.port)
        )
    except Exception as e:
        print(f"❌ Error de Socket: {e}")
        print("💡 Consejo: Si usas el puerto 443 en Linux, necesitas permisos de root (sudo). O usa -p 5000.")
        return

    try:
        # Extraemos bytes de la clave pública para anunciarlos en la red
        pub_bytes = local_static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Servicio de descubrimiento (mDNS / Zeroconf)
        discovery = DiscoveryService(args.port, pub_bytes, lambda n,i,p,pr: None)
        
        # Vinculación cruzada: El descubrimiento necesita acceder al protocolo para actualizar rutas
        discovery.set_protocol(proto) 
        
        # Lanzamos la Interfaz de Usuario (TUI)
        app = MessengerTUI(proto, discovery, storage, user_id=user_id, bind_ip=args.bind)
        await app.run_async()
        
    finally:
        # --- Bloque de Cierre Limpio ---
        print("\n🛑 Cerrando aplicación y liberando recursos...")
        
        # 1. Borrar de forma segura todas las sesiones criptográficas
        if sessions:
            sessions.zeroize_all_sessions()
            print("🔒 Sesiones criptográficas borradas de forma segura.")
        
        # 2. Cerrar conexión a base de datos (incluye borrado de clave)
        await storage.close()

        if proto:
            # 3. Enviar mensaje de "Desconexión" cifrado a los pares activos
            await proto.broadcast_disconnect()

        if discovery:
            # 4. Detener anuncios mDNS y salir del grupo multicast
            await discovery.stop()
            
        if transport: 
            transport.close()
        
        # 5. Borrar la clave de almacenamiento derivada (ya es bytearray)
        if storage_key:
            try:
                zeroize1(storage_key)
                print("🔒 Clave de almacenamiento derivada borrada.")
            except Exception:
                pass
            
        print("👋 Bye! (Ejecución finalizada)")

def perform_dnie_binding_gui():
    """
    Ejecuta la interfaz gráfica de inicio de sesión (Login).

    Esta función bloquea la ejecución hasta que el usuario se autentica correctamente
    con su DNIe o cancela la operación.

    Returns:
        tuple: (user_id, proofs, storage_signature, key_priv)
               Contiene las credenciales necesarias para iniciar la red y el almacenamiento.
    """
    
    print("✨ Generando par de claves de identidad efímera (Curve25519) en memoria RAM...")
    # Generamos la clave privada que se usará para el protocolo Noise.
    # Esta clave NO se guarda en disco, vive solo durante la ejecución.
    key_priv = x25519.X25519PrivateKey.generate()

    # Modo Mock para desarrollo sin tarjeta física
    if args.mock:
        print(f"⚠️ MODO MOCK ACTIVADO: Simulando identidad '{args.mock}'")
        mock_sig = b'\x00' * 256 
        return (args.mock, {'cert': '00', 'sig': '00'}, mock_sig, key_priv)

    # Obtenemos la clave pública para que el DNIe la firme
    key_pub_bytes = key_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Lanzamos la mini-app de Login
    login_app = DNIeLoginApp(key_to_sign_bytes=key_pub_bytes)
    result = login_app.run() 
    
    if result:
        # result es una tupla: (user_id, proofs, storage_signature)
        return (result[0], result[1], result[2], key_priv)
    else:
        print("Login cancelado por el usuario o error de tarjeta.")
        sys.exit(0)

if __name__ == "__main__":
    ensure_cert_structure()
    
    # Fase 1: Identidad (Login Gráfico y vinculación con Hardware)
    identity_data = perform_dnie_binding_gui()
    
    # Fase 2: Chat (App Principal con bucle de eventos)
    try:
        asyncio.run(main_async(identity_data))
    except KeyboardInterrupt:
        pass
    finally:
        # Limpieza final de descriptores de archivo estándar
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except: pass
        os._exit(0)