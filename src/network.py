import asyncio
import socket
import struct
import logging
import json
import time
import re
import netifaces
from zeroconf import ServiceInfo, IPVersion, Zeroconf, InterfaceChoice, DNSIncoming
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from protocol import NoiseIKState

MDNS_TYPE = "_dni-im._udp.local."
RAW_MDNS_QUERY = (
    b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x07_dni-im\x04_udp\x05local\x00'
    b'\x00\x0c'
    b'\x00\x01'
)

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
    def __init__(self, session_manager, on_message_received, on_log, on_handshake_success=None):
        self.sessions = session_manager
        self.on_message = on_message_received
        self.on_log = on_log
        self.on_handshake_success = on_handshake_success
        self.transport = None
        self.pending_messages = {} # Cola de mensajes esperando handshake: addr -> [msg1, msg2]

    def connection_made(self, transport):
        self.transport = transport
        self.sessions.transport = transport
        try:
            sock = transport.get_extra_info('socket')
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
            if self.on_handshake_success:
                self.on_handshake_success(addr, remote_pub)
                
        except Exception as e:
            self.on_log(f"❌ Handshake failed: {e}")
            if addr in self.sessions.sessions: del self.sessions.sessions[addr]

    def handle_handshake_resp(self, data, addr):
        session = self.sessions.get_session(addr)
        if not session: return
        try:
            session.consume_handshake_response(data)
            self.on_log(f"🔒 Secure Session established with {addr}")
            
            # REVISAR COLA: Si hay mensajes pendientes para este destino, enviarlos ahora
            if addr in self.pending_messages:
                count = len(self.pending_messages[addr])
                self.on_log(f"📨 Flushing {count} queued messages to {addr}")
                for content in self.pending_messages[addr]:
                    self.send_message(addr, content)
                del self.pending_messages[addr] # Limpiar cola

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

    def _queue_message(self, addr, content):
        """Guarda un mensaje para enviarlo cuando el handshake termine"""
        if addr not in self.pending_messages:
            self.pending_messages[addr] = []
        self.pending_messages[addr].append(content)
        self.on_log(f"⏳ Message queued (waiting for handshake)...")

    def send_message(self, addr, content):
        session = self.sessions.get_session(addr)
        
        # Caso 1: No existe sesión -> Iniciar Handshake y Encolar
        if not session:
            remote_pub = self.sessions.db.get_pubkey_by_addr(addr[0], addr[1])
            if not remote_pub:
                self.on_log(f"❌ Cannot send: No public key for {addr}")
                return
            
            # Crear sesión e iniciar handshake
            session = self.sessions.create_initiator_session(addr, remote_pub)
            hs_msg = session.create_handshake_message()
            self.transport.sendto(b'\x01' + hs_msg, addr)
            self.on_log(f"🔄 Initiating handshake with {addr}")
            
            # Encolar el mensaje para envío posterior
            self._queue_message(addr, content)
            return

        # Caso 2: Existe sesión pero el handshake no ha terminado (aún no tenemos claves de transporte)
        # Si encryptor es None, es que estamos esperando el Msg 2
        if session.encryptor is None:
            self._queue_message(addr, content)
            return

        # Caso 3: Sesión lista -> Enviar
        try:
            msg_struct = {"timestamp": time.time(), "text": content}
            payload = json.dumps(msg_struct).encode('utf-8')
            ciphertext = session.encrypt_message(payload)
            self.transport.sendto(b'\x03' + ciphertext, addr)
        except Exception as e:
            self.on_log(f"❌ Send failed: {e}")

class RawSniffer(asyncio.DatagramProtocol):
    def __init__(self, service):
        self.service = service

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info('socket')
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except: pass

        group = socket.inet_aton('224.0.0.251')
        try:
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except: pass

        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        if ip == '127.0.0.1': continue
                        try:
                            local = socket.inet_aton(ip)
                            mreq = struct.pack('4s4s', group, local)
                            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                        except: pass
        except Exception: pass

    def datagram_received(self, data, addr):
        if b"_dni-im" not in data: return
        try:
            found_info = None
            try:
                match = re.search(rb'User-([^_\x00]+)_(\d+)', data)
                if match:
                    name = match.group(1).decode('utf-8', errors='ignore')
                    port = int(match.group(2).decode('utf-8'))
                    found_info = (name, port)
            except: pass

            if not found_info:
                try:
                    msg = DNSIncoming(data)
                    for record in msg.answers + msg.additionals:
                        if MDNS_TYPE in record.name and "User-" in record.name:
                            base = record.name.split(MDNS_TYPE)[0].replace("User-", "")
                            if "_" in base:
                                n = base.rsplit("_", 1)[0]
                                p = int(base.rsplit("_", 1)[1].replace(".", ""))
                                found_info = (n, p)
                                break
                except: pass

            if found_info:
                name, port = found_info
                if name == self.service.username: return

                props = {'user': name}
                try:
                    pub_match = re.search(rb'pub=([a-fA-F0-9]+)', data)
                    if pub_match:
                        props['pub'] = pub_match.group(1).decode('utf-8')
                        if props['pub'] == self.service.pubkey_b64: return
                except: pass

                self.service.on_found(name, addr[0], port, props)
        except Exception:
            pass

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
        self.username = None
        self._polling_task = None

    async def start(self, username, bind_ip=None):
        self.loop = asyncio.get_running_loop()
        self.bind_ip = bind_ip
        self.username = username.replace("User-", "")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except: pass
            sock.bind(('', 5353))
            
            self.sniffer_transport, _ = await self.loop.create_datagram_endpoint(
                lambda: RawSniffer(self), sock=sock
            )
            self.on_log("👂 Sniffer Active on all interfaces")
        except Exception as e:
            self.on_log(f"⚠️ Sniffer failed: {e}")

        interfaces = InterfaceChoice.All
        if bind_ip and bind_ip != "0.0.0.0": interfaces = [bind_ip]
        try:
            self.aiozc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only)
        except:
            self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All)

        local_ip = bind_ip if (bind_ip and bind_ip != "0.0.0.0") else self.get_local_ip()
        service_name = f"{username}_{self.port}.{MDNS_TYPE}"
        
        desc = {'pub': self.pubkey_b64, 'user': username}
        self.info = ServiceInfo(
            MDNS_TYPE, service_name, addresses=[socket.inet_aton(local_ip)],
            port=self.port, properties=desc, server=f"{socket.gethostname()}.local."
        )
        
        self.on_log(f"📢 Advertising: {service_name} @ {local_ip}")
        await self.aiozc.async_register_service(self.info)
        
        self._polling_task = asyncio.create_task(self._active_polling_loop())

    async def stop(self):
        if self._polling_task: self._polling_task.cancel()
        if self.sniffer_transport: self.sniffer_transport.close()
        if self.info and self.aiozc: await self.aiozc.async_unregister_service(self.info)
        if self.aiozc: await self.aiozc.async_close()

    async def _active_polling_loop(self):
        while True:
            await asyncio.sleep(5)
            if self.sniffer_transport:
                 try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                 except: pass

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 80)); IP = s.getsockname()[0]
        except: IP = '127.0.0.1'
        finally: s.close()
        return IP