import sys
import asyncio
import argparse
from smartcard_dnie import DNIeCard, DNIeCardError
from network import UDPProtocol, SessionManager, DiscoveryService, PORT
from storage import Storage
from tui import MessengerTUI
from getpass import getpass
from cryptography.hazmat.primitives import serialization

async def main_async(dnie_user_id):
    # 1. Inicializar Base de Datos y Claves
    storage = Storage()
    await storage.init()
    local_static_key = await storage.get_static_key()
    
    # 2. Inicializar Gestor de Sesiones (Noise)
    sessions = SessionManager(local_static_key, storage)
    
    # 3. Inicializar Transporte UDP
    proto = UDPProtocol(sessions, lambda a,m: None, lambda t: print(f"LOG: {t}"))
    
    loop = asyncio.get_running_loop()
    
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto,
            local_addr=('0.0.0.0', PORT)
        )
    except PermissionError:
        print(f"❌ Error: Permission denied binding to port {PORT}.")
        print("   Linux/Mac: Run with 'sudo'.")
        print("   Windows: Ensure Administrator terminal.")
        return

    # 4. Iniciar mDNS Discovery (CORREGIDO: Async)
    pub_bytes = local_static_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    discovery = DiscoveryService(PORT, pub_bytes, lambda n,i,p: None)
    # AWAIT IMPORTANTE AQUÍ:
    await discovery.start(username=f"User-{dnie_user_id}")

    # 5. Arrancar TUI
    app = MessengerTUI(proto, discovery, storage)
    await app.run_async()
    
    # Cleanup (CORREGIDO: Async)
    await discovery.stop()
    transport.close()

def authenticate_dnie():
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
            print("✅ Authentication Successful. Unlocking Network...")
            return serial[:8] 
        finally:
            card.disconnect()
            
    except Exception as e:
        print(f"❌ Authentication Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # 1. Autenticación Hardware Bloqueante
    user_id = authenticate_dnie()
    
    # 2. Iniciar Loop Asíncrono
    try:
        asyncio.run(main_async(user_id))
    except KeyboardInterrupt:
        pass