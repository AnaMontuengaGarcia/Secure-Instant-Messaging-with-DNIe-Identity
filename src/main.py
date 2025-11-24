import sys
import asyncio
import argparse
import os
from network import UDPProtocol, SessionManager, DiscoveryService
from storage import Storage
from tui import MessengerTUI, DNIeLoginApp
from cryptography.hazmat.primitives import serialization
# Importamos librería para generación de claves en memoria
from cryptography.hazmat.primitives.asymmetric import x25519

# Configuración estándar de argumentos
parser = argparse.ArgumentParser(description="DNIe Secure Messenger")
parser.add_argument('-p', '--port', type=int, default=443, help="Puerto UDP (Default: 443)")
parser.add_argument('-b', '--bind', type=str, default="0.0.0.0", help="IP de escucha (Default: 0.0.0.0)")
parser.add_argument('-d', '--data', type=str, default="data", help="Carpeta de datos (Default: 'data')")
parser.add_argument('--mock', type=str, help="Simular DNIe para pruebas (Ej: --mock User1)")
args = parser.parse_args()

def ensure_cert_structure():
    """Asegura que existen las carpetas para la CA"""
    if not os.path.exists('certs'):
        os.makedirs('certs')
        with open('certs/README.txt', 'w') as f:
            f.write("Coloca aqui los certificados CA (Root e Intermedios) del DNIe en formato .pem o .crt\n")

async def main_async(dnie_identity_data):
    # Desempaquetamos los 3 elementos: ID, Pruebas y la Clave Privada en memoria
    user_id, proofs, local_static_key = dnie_identity_data
    
    # Inicializamos el storage para contactos y mensajes
    storage = Storage(data_dir=args.data)
    await storage.init()
    
    # Ya no cargamos la clave del disco. Usamos la que viene de memoria.
    
    sessions = SessionManager(local_static_key, storage, local_proofs=proofs)
    # Callback de log simple para la consola
    proto = UDPProtocol(sessions, lambda a,m: None, lambda t: print(f"LOG: {t}"))
    
    loop = asyncio.get_running_loop()
    transport = None
    discovery = None

    try:
        print(f"🔌 Binding socket to {args.bind}:{args.port}...")
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto,
            local_addr=(args.bind, args.port)
        )
    except Exception as e:
        print(f"❌ Socket error: {e}")
        print("💡 Consejo: Si el puerto 443 requiere permisos de root, prueba con un puerto alto: -p 5000")
        return

    try:
        pub_bytes = local_static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Iniciamos el servicio de descubrimiento (mDNS) en el puerto correcto
        discovery = DiscoveryService(args.port, pub_bytes, lambda n,i,p,pr: None)
        
        # Lanzamos la interfaz de Chat (TUI)
        app = MessengerTUI(proto, discovery, storage, user_id=user_id, bind_ip=args.bind)
        await app.run_async()
        
    finally:
        print("\n🛑 Closing application...")
        if proto:
            # Enviamos el "Adiós" a todos antes de cerrar el socket
            await proto.broadcast_disconnect()

        if discovery: await discovery.stop()
        if transport: transport.close()
        print("👋 Bye!")

def perform_dnie_binding_gui():
    """Realiza el binding usando la interfaz gráfica Textual (Login)"""
    
    # 1. Generamos la clave estática EN MEMORIA (Efímera, solo dura lo que el proceso)
    # No se guarda en disco en ningún momento.
    print("✨ Generating ephemeral identity key in memory...")
    key_priv = x25519.X25519PrivateKey.generate()

    # Si se usa el modo --mock
    if args.mock:
        return (args.mock, {'cert': '00', 'sig': '00'}, key_priv)

    key_pub_bytes = key_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # 2. Lanzar la App de Login dedicada
    login_app = DNIeLoginApp(key_to_sign_bytes=key_pub_bytes)
    result = login_app.run() # Bloquea hasta que la App se cierra (exit)
    
    # 3. Procesar resultado del login
    if result:
        # result es (user_id, proofs)
        # Devolvemos también la clave privada en memoria para que la use main_async
        return (result[0], result[1], key_priv)
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