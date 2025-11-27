import sys
import asyncio
import argparse
import os
from network import UDPProtocol, SessionManager, DiscoveryService
from storage import Storage
from tui import MessengerTUI, DNIeLoginApp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Configuración estándar de argumentos de línea de comandos
parser = argparse.ArgumentParser(description="DNIe Secure Messenger")
parser.add_argument('-p', '--port', type=int, default=443, help="Puerto UDP (Default: 443)")
parser.add_argument('-b', '--bind', type=str, default="0.0.0.0", help="IP de escucha (Default: 0.0.0.0)")
parser.add_argument('-d', '--data', type=str, default="data", help="Carpeta de datos (Default: 'data')")
parser.add_argument('--mock', type=str, help="Simular DNIe para pruebas (Ej: --mock User1)")
args = parser.parse_args()

def ensure_cert_structure():
    """
    Asegura que exista la estructura de directorios necesaria para certificados.
    
    Cómo lo hace:
    Verifica si existe la carpeta 'certs'. Si no, la crea y añade un archivo README
    con instrucciones para el usuario.
    """
    if not os.path.exists('certs'):
        os.makedirs('certs')
        with open('certs/README.txt', 'w') as f:
            f.write("Coloca aqui los certificados CA (Root e Intermedios) del DNIe en formato .pem o .crt\n")

def derive_storage_key(signature_bytes):
    """
    Deriva una clave simétrica criptográficamente fuerte a partir de la firma del DNIe.
    
    Cómo lo hace:
    Usa HKDF (SHA256) tomando la firma digital (bytes) generada por la tarjeta
    como material de entrada para producir una clave de 32 bytes apta para AES.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'DNIe-Storage-Encryption-Key',
    )
    return hkdf.derive(signature_bytes)

async def main_async(identity_data):
    """
    Función principal asíncrona que inicia el backend y la interfaz de usuario.
    
    Cómo lo hace:
    1. Desempaqueta los datos de identidad obtenidos del login.
    2. Deriva la clave de almacenamiento y carga la base de datos cifrada.
    3. Inicializa el gestor de sesiones y el protocolo UDP.
    4. Vincula el socket UDP al puerto especificado.
    5. Inicia el servicio de descubrimiento mDNS.
    6. Lanza la aplicación TUI (Textual) y espera a que termine.
    7. Realiza el cierre limpio (guardado de datos, desconexión de red) al salir.
    """
    user_id, proofs, storage_signature, local_static_key = identity_data
    
    print("🔐 Derivando clave de almacenamiento desde la firma DNIe...")
    storage_key = derive_storage_key(storage_signature)
    
    storage = Storage(key_bytes=storage_key, data_dir=args.data)
    await storage.init()
    
    sessions = SessionManager(local_static_key, storage, local_proofs=proofs)
    
    # Callback de log simple para consola antes de que arranque la TUI
    proto = UDPProtocol(sessions, lambda a,m: None, lambda t: print(f"LOG: {t}"), on_ack_received=None)
    
    loop = asyncio.get_running_loop()
    transport = None
    discovery = None

    try:
        print(f"🔌 Vinculando socket a {args.bind}:{args.port}...")
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto,
            local_addr=(args.bind, args.port)
        )
    except Exception as e:
        print(f"❌ Error de Socket: {e}")
        print("💡 Consejo: Si el puerto 443 requiere permisos de root, prueba con un puerto alto: -p 5000")
        return

    try:
        pub_bytes = local_static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        discovery = DiscoveryService(args.port, pub_bytes, lambda n,i,p,pr: None)
        
        # Conectar protocolo al descubrimiento para soportar Roaming
        discovery.set_protocol(proto) 
        
        app = MessengerTUI(proto, discovery, storage, user_id=user_id, bind_ip=args.bind)
        await app.run_async()
        
    finally:
        print("\n🛑 Cerrando aplicación...")
        # 0. Guardamos datos cifrados finales
        await storage.close()

        if proto:
            # 1. Enviamos el "Adiós" cifrado a la red
            await proto.broadcast_disconnect()

        if discovery:
            # 2. Detenemos anuncios mDNS
            await discovery.stop()
            
        if transport: transport.close()
        print("👋 Bye!")

def perform_dnie_binding_gui():
    """
    Gestiona la fase de Login / Autenticación antes de entrar al chat.
    
    Cómo lo hace:
    1. Genera una clave privada efímera en memoria para la sesión.
    2. Si está en modo mock, devuelve datos falsos para pruebas.
    3. Si no, lanza la aplicación 'DNIeLoginApp' para pedir PIN e interactuar con la tarjeta.
    4. Retorna las credenciales firmadas y la firma de almacenamiento.
    """
    
    print("✨ Generando clave de identidad efímera en memoria...")
    key_priv = x25519.X25519PrivateKey.generate()

    if args.mock:
        mock_sig = b'\x00' * 256 
        return (args.mock, {'cert': '00', 'sig': '00'}, mock_sig, key_priv)

    key_pub_bytes = key_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    login_app = DNIeLoginApp(key_to_sign_bytes=key_pub_bytes)
    result = login_app.run() 
    
    if result:
        # result es (user_id, proofs, storage_signature)
        return (result[0], result[1], result[2], key_priv)
    else:
        print("Login cancelado por el usuario.")
        sys.exit(0)

if __name__ == "__main__":
    ensure_cert_structure()
    
    # Fase 1: Identidad (Login Gráfico y Generación de Claves RAM)
    identity_data = perform_dnie_binding_gui()
    
    # Fase 2: Chat (App Principal)
    try:
        asyncio.run(main_async(identity_data))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except: pass
        os._exit(0)