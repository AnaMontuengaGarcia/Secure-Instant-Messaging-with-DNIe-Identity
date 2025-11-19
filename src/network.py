import asyncio
import socket
import struct
import logging
import json
import time
import re
from zeroconf import ServiceInfo, IPVersion, Zeroconf, InterfaceChoice, DNSIncoming
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from protocol import NoiseIKState

MDNS_TYPE = "_dni-im._udp.local."

# Constantes DNS
_TYPE_A = 1
_TYPE_PTR = 12
_TYPE_TXT = 16
_TYPE_SRV = 33

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
            self.on_log(f"✅ UDP Bound to {addr[0]}:{addr[1]}")
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

class RawSniffer(asyncio.DatagramProtocol):
    """
    Sniffer robusto que imita check_mdns.py y usa extracción por Regex.
    CORREGIDO: Eliminado filtro agresivo por puerto que bloqueaba peers reales.
    """
    def __init__(self, service):
        self.service = service

    def connection_made(self, transport):
        self.transport = transport
        # Socket ya configurado externamente

    def datagram_received(self, data, addr):
        # Filtro básico
        if b"_dni-im" not in data: return

        # self.service.on_log(f"🔍 RAW PACKET from {addr} ({len(data)}b)")

        try:
            found_info = None

            # A) Decodificación DNS
            try:
                msg = DNSIncoming(data)
                for record in msg.answers + msg.additionals:
                    if MDNS_TYPE in record.name and "User-" in record.name:
                        found_info = self._parse_record_name(record.name)
                        if found_info: break
            except: pass

            # B) Regex sobre bytes (Fuerza bruta)
            if not found_info:
                try:
                    raw_text = data.decode('utf-8', errors='ignore')
                    match = re.search(r'User-([a-zA-Z0-9]+)_(\d+)', raw_text)
                    if match:
                        name = match.group(1)
                        port = int(match.group(2))
                        found_info = (name, port)
                except: pass

            if found_info:
                name, port = found_info
                
                # CORRECCIÓN: Eliminado filtro 'if port == self.service.port: return'
                # Ahora confiamos en el filtrado por clave pública o IP.
                
                props = {'user': name}
                
                # Intentar extraer clave pública
                try:
                    raw_text = data.decode('utf-8', errors='ignore')
                    pub_match = re.search(r'pub=([a-fA-F0-9]+)', raw_text)
                    if pub_match:
                        props['pub'] = pub_match.group(1)
                        
                        # FILTRO SEGURO: Solo descartar si la clave es IDÉNTICA a la mía
                        if props['pub'] == self.service.pubkey_b64:
                            return
                except: pass

                self.service.on_found(name, addr[0], port, props)

        except Exception as e:
            self.service.on_log(f"⚠️ Sniffer exception: {e}")

    def _parse_record_name(self, record_name):
        try:
            base = record_name.split(MDNS_TYPE)[0]
            if base.startswith("User-"):
                base = base[5:]
            if "_" in base:
                parts = base.split('_')
                port_str = parts[-1].replace('.', '')
                name = "_".join(parts[:-1])
                return name, int(port_str)
        except: pass
        return None

class DiscoveryService:
    def __init__(self, port, pubkey_bytes, on_service_found, on_log=None):
        self.aiozc = None 
        self.port = port
        self.pubkey_b64 = pubkey_bytes.hex()
        self.on_found = on_service_found
        self.on_log = on_log if on_log else lambda x: None
        self.info = None
        self.loop = None
        self.sniffer_transport = None
        self.bind_ip = None

    async def start(self, username, bind_ip=None):
        self.loop = asyncio.get_running_loop()
        self.bind_ip = bind_ip
        
        # 1. Zeroconf para PUBLICAR
        interfaces = InterfaceChoice.All
        if bind_ip and bind_ip != "0.0.0.0":
            interfaces = [bind_ip]

        try:
            self.aiozc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only)
        except:
            self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All)

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
        await self.aiozc.async_register_service(self.info)
        
        # 2. Sniffer Manual (Receptor)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError: pass
            
            sock.bind(('', 5353))
            
            group = socket.inet_aton('224.0.0.251')
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            self.sniffer_transport, _ = await self.loop.create_datagram_endpoint(
                lambda: RawSniffer(self),
                sock=sock
            )
            self.on_log("👂 Raw Sniffer active")
        except Exception as e:
            self.on_log(f"⚠️ Sniffer bind failed: {e}")

    async def stop(self):
        if self.sniffer_transport:
            self.sniffer_transport.close()
        if self.info and self.aiozc:
            await self.aiozc.async_unregister_service(self.info)
        if self.aiozc:
            await self.aiozc.async_close()

    def refresh(self):
        if self.aiozc and self.aiozc.zeroconf:
             self.on_log("📡 Broadcasting query...")
             try:
                 self.aiozc.zeroconf.get_service_info(MDNS_TYPE, "placeholder", timeout=0.1)
             except: pass

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP