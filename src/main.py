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
parser.add_argument('--bind', type=str, default="0.0.0.0", help="IP de escucha")
parser.add_argument('--data', type=str, default="data", help="Carpeta de datos")
parser.add_argument('--mock', type=str, help="Simular DNIe")
args = parser.parse_args()

async def main_async(dnie_identity_data):
    # dnie_identity_data es una tupla: (user_id, proofs_dict)
    user_id, proofs = dnie_identity_data
    
    storage = Storage(data_dir=args.data)
    await storage.init()
    local_static_key = await storage.get_static_key()
    
    # Pasamos las pruebas (cert+firma) al SessionManager
    sessions = SessionManager(local_static_key, storage, local_proofs=proofs)
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
        return

    try:
        pub_bytes = local_static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        discovery = DiscoveryService(args.port, pub_bytes, lambda n,i,p,pr: None)
        
        # Pasamos los proofs (que incluyen el nombre real del DNIe) como ID si queremos
        app = MessengerTUI(proto, discovery, storage, user_id=user_id, bind_ip=args.bind)
        await app.run_async()
        
    finally:
        if discovery: await discovery.stop()
        if transport: transport.close()
        print("👋 Bye!")

def perform_dnie_binding():
    if args.mock:
        return (args.mock, {'cert': '00', 'sig': '00'}) # Mock sin seguridad real

    from smartcard_dnie import DNIeCard
    from getpass import getpass
    from storage import Storage
    
    # Necesitamos la clave antes de arrancar la red para firmarla
    # Esto es un poco "huevo y gallina", instanciamos storage temporalmente
    temp_storage = Storage(data_dir=args.data)
    # Nota: asyncio.run no se puede llamar aquí fácilmente si ya estamos en main.
    # Hacemos una carga síncrona sucia o asumimos que identity.key existe/se crea.
    # Para simplificar, asumimos que Storage.get_static_key puede correr síncrono o lo forzamos.
    # Pero Storage es async. 
    # Solución: Ejecutar un mini-loop solo para obtener la clave.
    
    async def get_key_bytes():
        if not os.path.exists(temp_storage.data_dir): os.makedirs(temp_storage.data_dir)
        return await temp_storage.get_static_key()

    key_priv = asyncio.run(get_key_bytes())
    key_pub_bytes = key_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    print("🔐 DNIe Binding Ceremony")
    print("Insert DNIe to SIGN your network identity...")
    input("Press Enter...")
    
    card = DNIeCard()
    try:
        card.connect()
        pin = getpass("Enter DNIe PIN: ")
        card.authenticate(pin)
        
        print("📜 Reading Certificate...")
        cert_der = card.get_certificate()
        
        print("✍️  Signing Network Identity (X25519 Key)...")
        signature = card.sign_data(key_pub_bytes)
        
        print("✅ Identity Bound Successfully!")
        
        proofs = {
            'cert': cert_der.hex(),
            'sig': signature.hex()
        }
        # Usamos parte del hash del certificado como ID visual temporal
        user_id = card.get_serial_hash()[:8]
        
        return (user_id, proofs)
        
    except Exception as e:
        print(f"❌ Binding Failed: {e}")
        sys.exit(1)
    finally:
        card.disconnect()

if __name__ == "__main__":
    identity_data = perform_dnie_binding()
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