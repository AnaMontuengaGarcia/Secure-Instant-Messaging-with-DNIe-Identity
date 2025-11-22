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

def ensure_cert_structure():
    """Asegura que existen las carpetas para la CA"""
    if not os.path.exists('certs'):
        os.makedirs('certs')
        with open('certs/README.txt', 'w') as f:
            f.write("Coloca aqui los certificados CA (Root e Intermedios) del DNIe en formato .pem o .crt\n")
            f.write("Ejemplo: AC_RAIZ_DNIE_2.pem, AC_DNIE_004.crt, etc.")

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

    print("🔐 DNIe Binding Ceremony")
    
    while True:
        print("\n👉 Insert DNIe to SIGN your network identity.")
        user_input = input("Press [Enter] to connect or type 'q' to quit... ").strip().lower()
        
        if user_input == 'q':
            print("Exiting...")
            sys.exit(0)

        card = DNIeCard()
        try:
            print("⏳ Connecting to smart card...")
            card.connect()
            
            # Si conecta, intentar autenticación
            try:
                pin = getpass("Enter DNIe PIN: ")
                card.authenticate(pin)
            except Exception as auth_err:
                print(f"❌ Authentication Failed: {auth_err}")
                print("⚠️  Please try again.")
                continue # Volver al inicio del bucle

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
            print(f"⚠️ Card Error: {e}")
            print("Make sure the reader is connected and the card is inserted correctly.")
            # El bucle continúa automáticamente pidiendo "Press Enter"
        finally:
            card.disconnect()

if __name__ == "__main__":
    ensure_cert_structure()
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