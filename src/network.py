import asyncio
import socket
import struct
import logging
import json
import time
from zeroconf import ServiceInfo, IPVersion, Zeroconf, InterfaceChoice
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from protocol import NoiseIKState

MDNS_TYPE = "_dni-im._udp.local."

class SessionManager:
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
        sock = transport.get_extra_info('socket')
        try:
            addr = sock.getsockname()
            self.on_log(f"✅ UDP Listening on {addr[0]}:{addr[1]}")
        except: pass

    def datagram_received(self, data, addr):
        if len(data) < 1: return
        try:
            packet_type = data[0]
            payload = data[1:]
            if packet_type == 0x01:
                self.handle_handshake_init(payload, addr)
            elif packet_type == 0x02:
                self.handle_handshake_resp(payload, addr)
            elif packet_type == 0x03:
                self.handle_data(payload, addr)
        except Exception as e:
            self.on_log(f"❌ Error packet {addr}: {e}")

    def handle_handshake_init(self, data, addr):
        self.on_log(f"🔄 Handshake Init from {addr}")
        session = self.sessions.create_responder_session(addr)
        try:
            remote_pub = session.consume_handshake_message(data)
            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Response sent to {addr}")
            asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], remote_pub))
        except Exception as e:
            self.on_log(f"❌ Handshake failed: {e}")
            if addr in self.sessions.sessions: del self.sessions.sessions[addr]

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
        if not session: return
        try:
            plaintext = session.decrypt_message(data)
            msg_struct = json.loads(plaintext.decode('utf-8'))
            self.on_message(addr, msg_struct)
        except Exception as e:
            self.on_log(f"❌ Decryption failed: {e}")

    def send_message(self, addr, content):
        session = self.sessions.get_session(addr)
        if not session:
            remote_pub = self.sessions.db.get_pubkey_by_addr(addr[0], addr[1])
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
    def __init__(self, port, pubkey_bytes, on_service_found, on_log=None):
        self.aiozc = None 
        self.port = port
        self.pubkey_b64 = pubkey_bytes.hex()
        self.on_found = on_service_found
        self.on_log = on_log if on_log else lambda x: None
        self.info = None
        self.browser = None
        self.loop = None

    async def start(self, username, bind_ip=None):
        self.loop = asyncio.get_running_loop()
        
        # Configuración estándar para LAN: Usar todas las interfaces
        # Esto permite escuchar tanto en Ethernet como en WiFi simultáneamente
        self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All, ip_version=IPVersion.V4Only)
        
        # Detectar automáticamente la IP real de la LAN (ej: 192.168.1.X)
        # Si el usuario fuerza una IP con --bind, usamos esa.
        local_ip = bind_ip if (bind_ip and bind_ip != "0.0.0.0") else self.get_local_ip()
        
        service_name = f"{username}_{self.port}.{MDNS_TYPE}"
        
        desc = {'pub': self.pubkey_b64, 'user': username}
        
        self.info = ServiceInfo(
            MDNS_TYPE,
            service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=desc,
            server=f"{socket.gethostname()}.local."
        )
        
        self.on_log(f"📢 Advertising: {service_name} @ {local_ip}")
        
        # Publicar servicio
        await self.aiozc.async_register_service(self.info)
        
        # Buscar otros servicios
        self.browser = AsyncServiceBrowser(
            self.aiozc.zeroconf, 
            MDNS_TYPE, 
            handlers=[self.on_service_state_change]
        )

    async def stop(self):
        if self.info and self.aiozc:
            await self.aiozc.async_unregister_service(self.info)
        if self.aiozc:
            await self.aiozc.async_close()

    def refresh(self):
        """Fuerza una consulta activa en la red"""
        if self.aiozc and self.aiozc.zeroconf:
             self.on_log("📡 Broadcasting query...")
             try:
                 self.aiozc.zeroconf.get_service_info(MDNS_TYPE, "placeholder", timeout=0.1)
             except: pass

    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        if state_change.name == "ServiceAdded":
            if self.loop and not self.loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    self._resolve_service(name), 
                    self.loop
                )

    async def _resolve_service(self, name):
        try:
            # Resolvemos la información del servicio detectado
            info = await self.aiozc.async_get_service_info(MDNS_TYPE, name, timeout=3000)
            
            if info:
                addr = socket.inet_ntoa(info.addresses[0])
                
                props = {}
                for k, v in info.properties.items():
                    try:
                        key = k.decode('utf-8') if isinstance(k, bytes) else k
                        val = v.decode('utf-8') if isinstance(v, bytes) else v
                        props[key] = val
                    except: pass
                
                # Filtro estándar: Si la clave pública es la mía, me ignoro a mí mismo
                if props.get('pub') == self.pubkey_b64:
                    return

                self.on_found(name, addr, info.port, props)
        except Exception:
            pass

    def get_local_ip(self):
        """Obtiene la IP de la interfaz que tiene salida a Internet/LAN"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Conectar a una IP pública (Google DNS) no envía paquetes,
            # solo consulta la tabla de enrutamiento del Kernel.
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP