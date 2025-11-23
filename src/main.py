import sys
import asyncio
import argparse
import os
from network import UDPProtocol, SessionManager, DiscoveryService
from storage import Storage
from tui import MessengerTUI, DNIeLoginApp
from cryptography.hazmat.primitives import serialization

# Configuración estándar de argumentos
# Se han añadido alias cortos (-p, -b, -d) para mayor comodidad
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
    user_id, proofs = dnie_identity_data
    
    # Inicializamos el storage usando la carpeta definida en los argumentos
    storage = Storage(data_dir=args.data)
    await storage.init()
    local_static_key = await storage.get_static_key()
    
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
        if discovery: await discovery.stop()
        if transport: transport.close()
        print("👋 Bye!")

def perform_dnie_binding_gui():
    """Realiza el binding usando la interfaz gráfica Textual (Login)"""
    
    # Si se usa el modo --mock, saltamos la pantalla de login real
    if args.mock:
        return (args.mock, {'cert': '00', 'sig': '00'})

    # 1. Preparar clave estática (necesaria para que el DNIe la firme)
    temp_storage = Storage(data_dir=args.data)
    
    async def get_key_bytes():
        if not os.path.exists(temp_storage.data_dir): os.makedirs(temp_storage.data_dir)
        return await temp_storage.get_static_key()

    try:
        key_priv = asyncio.run(get_key_bytes())
    except Exception as e:
        print(f"Error accessing storage: {e}")
        sys.exit(1)

    key_pub_bytes = key_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # 2. Lanzar la App de Login dedicada
    login_app = DNIeLoginApp(key_to_sign_bytes=key_pub_bytes)
    result = login_app.run() # Bloquea hasta que la App se cierra (exit)
    
    # 3. Procesar resultado del login
    if result:
        return result
    else:
        # Si el usuario cerró la ventana o canceló
        print("Login cancelado por el usuario.")
        sys.exit(0)

if __name__ == "__main__":
    ensure_cert_structure()
    # Fase 1: Identidad (Login Gráfico)
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