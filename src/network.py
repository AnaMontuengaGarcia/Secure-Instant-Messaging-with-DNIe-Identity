import asyncio
import socket
import struct
import logging
import json
import time
# Importamos las versiones asíncronas de Zeroconf
from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from protocol import NoiseIKState

# Configuración de red
PORT = 443 
MDNS_TYPE = "_dni-im._udp.local."

class SessionManager:
    """Gestiona las sesiones criptográficas activas."""
    def __init__(self, local_static_key, db):
        self.local_static_key = local_static_key
        self.sessions = {} 
        self.db = db
        self.transport = None

    def get_session(self, addr):
        return self.sessions.get(addr)

    def create_initiator_session(self, addr, remote_pub_key):
        session = NoiseIKState(self.local_static_key, remote_pub_key, initiator=True)
        session.initialize()
        self.sessions[addr] = session
        return session

    def create_responder_session(self, addr):
        session = NoiseIKState(self.local_static_key, initiator=False)
        session.initialize()
        self.sessions[addr] = session
        return session

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, session_manager, on_message_received, on_log):
        self.sessions = session_manager
        self.on_message = on_message_received
        self.on_log = on_log
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.sessions.transport = transport
        self.on_log(f"✅ UDP Listening on port {PORT}")

    def datagram_received(self, data, addr):
        if len(data) < 1: return

        packet_type = data[0]
        payload = data[1:]

        try:
            if packet_type == 0x01: # Handshake Init (I->R)
                self.handle_handshake_init(payload, addr)
            elif packet_type == 0x02: # Handshake Resp (R->I)
                self.handle_handshake_resp(payload, addr)
            elif packet_type == 0x03: # Data Packet
                self.handle_data(payload, addr)
            else:
                self.on_log(f"⚠️ Unknown packet type {packet_type} from {addr}")
        except Exception as e:
            self.on_log(f"❌ Error processing packet from {addr}: {e}")

    def handle_handshake_init(self, data, addr):
        self.on_log(f"🔄 Handshake Init received from {addr}")
        session = self.sessions.create_responder_session(addr)
        try:
            remote_pub = session.consume_handshake_message(data)
            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Response sent to {addr}")
            asyncio.create_task(self.sessions.db.register_contact(addr[0], remote_pub))
        except Exception as e:
            self.on_log(f"❌ Handshake failed: {e}")
            if addr in self.sessions.sessions:
                del self.sessions.sessions[addr]

    def handle_handshake_resp(self, data, addr):
        session = self.sessions.get_session(addr)
        if not session: return
        try:
            session.consume_handshake_response(data)
            self.on_log(f"🔒 Secure Session established with {addr}")
        except Exception as e:
            self.on_log(f"❌ Handshake completion failed: {e}")

    def handle_data(self, data, addr):
        session = self.sessions.get_session(addr)
        if not session:
            self.on_log(f"⚠️ Data received from unknown session {addr}")
            return
        try:
            plaintext = session.decrypt_message(data)
            msg_struct = json.loads(plaintext.decode('utf-8'))
            self.on_message(addr, msg_struct)
        except Exception as e:
            self.on_log(f"❌ Decryption failed: {e}")

    def send_message(self, addr, content):
        session = self.sessions.get_session(addr)
        if not session:
            remote_pub = self.sessions.db.get_pubkey_by_ip(addr[0])
            if not remote_pub:
                self.on_log(f"❌ Cannot send: No public key for {addr}")
                return
            session = self.sessions.create_initiator_session(addr, remote_pub)
            hs_msg = session.create_handshake_message()
            self.transport.sendto(b'\x01' + hs_msg, addr)
            self.on_log(f"🔄 Initiating handshake with {addr}")
            return

        try:
            msg_struct = {"timestamp": time.time(), "text": content}
            payload = json.dumps(msg_struct).encode('utf-8')
            ciphertext = session.encrypt_message(payload)
            self.transport.sendto(b'\x03' + ciphertext, addr)
        except Exception as e:
            self.on_log(f"❌ Send failed: {e}")

class DiscoveryService:
    def __init__(self, port, pubkey_bytes, on_service_found):
        self.aiozc = None # AsyncZeroconf instance
        self.port = port
        self.pubkey_b64 = pubkey_bytes.hex()
        self.on_found = on_service_found
        self.info = None
        self.browser = None

    async def start(self, username):
        """Inicia el servicio mDNS de forma asíncrona"""
        self.aiozc = AsyncZeroconf()
        
        desc = {'pub': self.pubkey_b64, 'user': username}
        hostname = socket.gethostname()
        local_ip = self.get_local_ip()
        
        self.info = ServiceInfo(
            MDNS_TYPE,
            f"{username}.{MDNS_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=desc,
            server=f"{hostname}.local."
        )
        
        # Registro asíncrono
        await self.aiozc.async_register_service(self.info)
        
        # Browser asíncrono
        self.browser = AsyncServiceBrowser(
            self.aiozc.zeroconf, 
            MDNS_TYPE, 
            handlers=[self.on_service_state_change]
        )

    async def stop(self):
        """Detiene el servicio mDNS y libera recursos"""
        if self.info and self.aiozc:
            await self.aiozc.async_unregister_service(self.info)
        if self.aiozc:
            await self.aiozc.async_close()

    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        if state_change.name == "ServiceAdded":
            # Zeroconf callback is sync, but we need to be careful not to block
            asyncio.create_task(self._resolve_service(zeroconf, service_type, name))

    async def _resolve_service(self, zeroconf, service_type, name):
        info = await self.aiozc.async_get_service_info(service_type, name)
        if info:
            addr = socket.inet_ntoa(info.addresses[0])
            # Decodificar propiedades
            props = {}
            for k, v in info.properties.items():
                key = k.decode('utf-8') if isinstance(k, bytes) else k
                val = v.decode('utf-8') if isinstance(v, bytes) else v
                props[key] = val
            
            # Evitar detectarnos a nosotros mismos
            if props.get('pub') == self.pubkey_b64:
                return

            self.on_found(name, addr, props)

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP