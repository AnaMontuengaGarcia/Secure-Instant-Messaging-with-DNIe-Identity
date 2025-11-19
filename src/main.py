import sys
import asyncio
import argparse
import os
from network import UDPProtocol, SessionManager, DiscoveryService
from storage import Storage
from tui import MessengerTUI
from cryptography.hazmat.primitives import serialization

# Configuración estándar
parser = argparse.ArgumentParser(description="DNIe Secure Messenger")
parser.add_argument('--port', type=int, default=443, help="Puerto UDP (Default: 443)")
parser.add_argument('--bind', type=str, default="0.0.0.0", help="IP de escucha (Default: Todas)")
parser.add_argument('--data', type=str, default="data", help="Carpeta de datos")
parser.add_argument('--mock', type=str, help="Simular DNIe (Solo para pruebas)")
args = parser.parse_args()

async def main_async(dnie_user_id):
    # 1. Inicializar
    storage = Storage(data_dir=args.data)
    await storage.init()
    local_static_key = await storage.get_static_key()
    
    sessions = SessionManager(local_static_key, storage)
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
    except PermissionError:
        print(f"❌ Error: Permiso denegado en puerto {args.port}. Usa 'sudo'.")
        return
    except OSError as e:
        print(f"❌ Error de red: {e}")
        return

    # Bloque Try/Finally para asegurar limpieza
    try:
        pub_bytes = local_static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        discovery = DiscoveryService(args.port, pub_bytes, lambda n,i,p,pr: None)

        # Iniciar TUI
        app = MessengerTUI(proto, discovery, storage, user_id=dnie_user_id, bind_ip=args.bind)
        await app.run_async()
        
    except asyncio.CancelledError:
        # Captura la cancelación limpia de asyncio
        pass
    finally:
        # LIMPIEZA CRÍTICA: Detener threads antes de salir
        print("\n🧹 Cleaning up network resources...")
        if discovery:
            await discovery.stop()
        if transport:
            transport.close()
        print("👋 Bye!")

def authenticate_dnie():
    if args.mock:
        return args.mock

    from smartcard_dnie import DNIeCard
    from getpass import getpass
    
    print("🔐 DNIe Authentication Required")
    print("Insert DNIe and press Enter...")
    input()
    
    card = DNIeCard()
    try:
        card.connect()
        serial = card.get_serial_hash()
        print(f"✅ Card Detected: {serial[:8]}...")
        
        pin = getpass("Enter DNIe PIN: ")
        try:
            card.authenticate(pin) 
            print("✅ Authentication Successful...")
            return serial[:8] 
        finally:
            card.disconnect()
            
    except Exception as e:
        print(f"❌ Authentication Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    user_id = authenticate_dnie()
    try:
        asyncio.run(main_async(user_id))
    except KeyboardInterrupt:
        pass
    finally:
        # CORRECCIÓN: Forzar salida del sistema para evitar errores de threading 
        # durante el shutdown del intérprete de Python.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except:
            pass
        os._exit(0)