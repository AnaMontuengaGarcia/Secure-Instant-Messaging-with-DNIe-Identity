import asyncio
import socket
import struct
import logging
import json
import time
import re
import os
import netifaces
import secrets
import uuid
import hashlib
from collections import deque
from datetime import datetime, timezone
from zeroconf import ServiceInfo, IPVersion, Zeroconf, InterfaceChoice, DNSIncoming
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from protocol import NoiseIKState
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

MDNS_TYPE = "_dni-im._udp.local."
RAW_MDNS_QUERY = (
    b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x07_dni-im\x04_udp\x05local\x00'
    b'\x00\x0c'
    b'\x00\x01'
)
TRUSTED_CERTS_DIR = "certs"

def load_trusted_cas():
    """Carga certificados CA de confianza desde el disco."""
    trusted_cas = []
    if not os.path.exists(TRUSTED_CERTS_DIR):
        return []
    
    for filename in os.listdir(TRUSTED_CERTS_DIR):
        if filename.endswith(".pem") or filename.endswith(".crt") or filename.endswith(".cer"):
            try:
                with open(os.path.join(TRUSTED_CERTS_DIR, filename), "rb") as f:
                    cert_data = f.read()
                    try:
                        cert = x509.load_pem_x509_certificate(cert_data)
                    except:
                        cert = x509.load_der_x509_certificate(cert_data)
                    trusted_cas.append(cert)
            except Exception as e:
                print(f"⚠️ Failed to load CA {filename}: {e}")
    return trusted_cas

GLOBAL_TRUST_STORE = load_trusted_cas()

def get_common_name(cert):
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return "Unknown Common Name"

def verify_peer_identity(x25519_pub_key, proofs):
    if not proofs or 'cert' not in proofs or 'sig' not in proofs:
        raise Exception("No identity proofs provided by peer")

    try:
        cert_bytes = bytes.fromhex(proofs['cert'])
        signature_bytes = bytes.fromhex(proofs['sig'])
        peer_cert = x509.load_der_x509_certificate(cert_bytes)
        rsa_pub_key = peer_cert.public_key()

        now = datetime.now(timezone.utc)
        if now < peer_cert.not_valid_before_utc:
            raise Exception("Certificate is NOT YET valid")
        if now > peer_cert.not_valid_after_utc:
            raise Exception("Certificate has EXPIRED")

        try:
            key_usage_ext = peer_cert.extensions.get_extension_for_class(x509.KeyUsage)
            usage = key_usage_ext.value
            if not (usage.digital_signature or usage.content_commitment):
                raise Exception("Certificate not allowed for Digital Signature/Authentication")
        except x509.ExtensionNotFound:
            pass

        issuer_name = "Unknown CA (No Verification)"
        is_trusted = False
        
        if not GLOBAL_TRUST_STORE:
             issuer_name = "UNTRUSTED/NO-STORE"
             is_trusted = True 
        else:
            for ca_cert in GLOBAL_TRUST_STORE:
                try:
                    ca_public_key = ca_cert.public_key()
                    ca_public_key.verify(
                        peer_cert.signature,
                        peer_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        peer_cert.signature_hash_algorithm
                    )
                    is_trusted = True
                    issuer_name = get_common_name(ca_cert)
                    break 
                except Exception:
                    continue

            if not is_trusted:
                raise Exception("Certificate Issuer is NOT TRUSTED (No matching CA in ./certs)")

        data_to_verify = x25519_pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        rsa_pub_key.verify(
            signature_bytes,
            data_to_verify,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        real_name = get_common_name(peer_cert).replace("(AUTENTICACIÓN)", "").strip()
        return real_name, issuer_name

    except Exception as e:
        raise Exception(f"Identity Verification Failed: {e}")


class SessionManager:
    def __init__(self, local_static_key, db, local_proofs):
        self.local_static_key = local_static_key
        self.local_proofs = local_proofs
        
        # AUDIT FIX: Mapping sessions by ID for Multiplexing
        self.sessions_by_addr = {} # (ip, port) -> session (Legacy/Initial)
        self.sessions_by_id = {}   # local_index (int) -> session
        
        self.db = db
        self.transport = None

    def get_session_by_addr(self, addr):
        return self.sessions_by_addr.get(addr)
    
    def get_session_by_id(self, idx):
        return self.sessions_by_id.get(idx)

    def register_session(self, session, addr):
        self.sessions_by_addr[addr] = session
        self.sessions_by_id[session.local_index] = session
        # Almacenamos la dirección actual en la sesión para "Roaming"
        session.current_addr = addr

    def create_initiator_session(self, addr, remote_pub_key):
        session = NoiseIKState(
            self.local_static_key, 
            remote_pub_key, 
            initiator=True,
            local_proofs=self.local_proofs
        )
        session.initialize()
        self.register_session(session, addr)
        return session

    def create_responder_session(self, addr):
        session = NoiseIKState(
            self.local_static_key, 
            initiator=False,
            local_proofs=self.local_proofs
        )
        session.initialize()
        self.register_session(session, addr)
        return session
        
    def update_session_addr(self, session, new_addr):
        if session.current_addr != new_addr:
            if session.current_addr in self.sessions_by_addr:
                del self.sessions_by_addr[session.current_addr]
            session.current_addr = new_addr
            self.sessions_by_addr[new_addr] = session
            return True
        return False

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, session_manager, on_message_received, on_log, on_handshake_success=None, on_ack_received=None):
        self.sessions = session_manager
        self.on_message = on_message_received
        self.on_log = on_log
        self.on_handshake_success = on_handshake_success
        self.on_ack_received = on_ack_received
        self.transport = None
        
        # --- RELIABILITY & RETRY SYSTEM (SEQUENTIAL) ---
        # Key: addr (ip, port), Value: deque of dicts {'msg_id', 'content', 'attempts', 'last_retry', 'status'}
        self.peer_message_queues = {} 
        self.dedup_buffer = deque(maxlen=200) # Almacena msg_id recientes recibidos para evitar duplicados
        self.is_online_checker = lambda addr: True # Callback por defecto (asume todos online)
        self._retry_task_handle = None

    def connection_made(self, transport):
        self.transport = transport
        self.sessions.transport = transport
        try:
            sock = transport.get_extra_info('socket')
            addr = sock.getsockname()
            self.on_log(f"✅ UDP Bound to {addr[0]}:{addr[1]}")
        except: pass
        
        # Iniciar tarea de reintentos
        self._retry_task_handle = asyncio.create_task(self._retry_worker())

    def set_online_checker(self, func):
        """Permite a la capa superior (TUI) definir cómo saber si una IP está online."""
        self.is_online_checker = func

    def notify_peer_online(self, ip, port):
        """Llamado cuando un peer vuelve a estar online. Reinicia contadores de reintento."""
        addr = (ip, port)
        if addr in self.peer_message_queues and self.peer_message_queues[addr]:
            head = self.peer_message_queues[addr][0]
            head['attempts'] = 0 # Reiniciamos intentos
            head['last_retry'] = 0 # Forzar reintento inmediato

    def migrate_queue(self, old_addr, new_addr):
        """Mueve la cola de mensajes de una dirección antigua a una nueva (Roaming)."""
        if old_addr in self.peer_message_queues:
            self.on_log(f"🔀 Migrating message queue from {old_addr} to {new_addr}")
            old_q = self.peer_message_queues.pop(old_addr)
            
            if new_addr not in self.peer_message_queues:
                self.peer_message_queues[new_addr] = old_q
            else:
                # Si ya existía cola en la nueva (raro), ponemos los viejos PRIMERO
                self.peer_message_queues[new_addr].extendleft(reversed(old_q))
            
            # Forzamos reintento inmediato en la nueva dirección
            if self.peer_message_queues[new_addr]:
                 head = self.peer_message_queues[new_addr][0]
                 head['attempts'] = 0 
                 head['last_retry'] = 0

    def consolidate_peer_sessions(self, active_session, current_addr):
        """
        Busca sesiones antiguas con la misma identidad (Public Key) y migra sus colas
        de mensajes a la dirección actual. Vital cuando cambia la IP de ambos extremos.
        """
        if not active_session.rs_pub: return

        active_pub_bytes = active_session.rs_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        # Copiamos para iterar seguro
        for addr, session in list(self.sessions.sessions_by_addr.items()):
            if addr == current_addr: continue
            if not session.rs_pub: continue

            other_pub_bytes = session.rs_pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )

            if active_pub_bytes == other_pub_bytes:
                self.on_log(f"🔗 Consolidating session for peer {addr} -> {current_addr}")
                self.migrate_queue(addr, current_addr)

    async def _retry_worker(self):
        """Tarea en segundo plano para reenviar el mensaje en cabecera de cada cola."""
        while True:
            await asyncio.sleep(1.0) # Check frequency
            now = time.time()
            
            # Iteramos sobre todos los peers con cola
            for addr, queue in list(self.peer_message_queues.items()):
                if not queue: continue
                
                head = queue[0]
                
                # AUDIT FIX: Estrategia híbrida Fast/Slow sin dependencia de is_online_checker
                attempts = head['attempts']
                delta = now - head['last_retry']
                
                # 2s para ráfaga inicial, 10s para persistencia en desconexiones largas
                interval = 2.0 if attempts < 10 else 10.0
                
                if delta >= interval:
                    try:
                        # Reenviar cabecera
                        await self._attempt_send_head(addr, head)
                    except Exception as e:
                        print(f"Retry error: {e}")

    async def _attempt_send_head(self, addr, item):
        """Intenta enviar el mensaje de cabecera. Si no hay sesión, inicia handshake."""
        item['last_retry'] = time.time()
        item['attempts'] += 1
        
        # Llamamos a _transmit_raw que maneja la lógica de sesión/handshake
        await self._transmit_raw(addr, item['content'], item['msg_id'], timestamp=item['timestamp'])

    def datagram_received(self, data, addr):
        if len(data) < 1: return
        try:
            packet_type = data[0]
            payload = data[1:]
            
            if packet_type == 0x01: # Handshake Init
                self.handle_handshake_init(payload, addr)
            elif packet_type == 0x02: # Handshake Resp
                self.handle_handshake_resp(payload, addr)
            elif packet_type == 0x03: # Data Message
                self.handle_data(payload, addr)
        except Exception as e:
            self.on_log(f"❌ Error packet {addr}: {e}")

    def handle_handshake_init(self, data, addr):
        self.on_log(f"🔄 Handshake Init from {addr}")
        session = self.sessions.create_responder_session(addr)
        try:
            remote_pub = session.consume_handshake_message(data)
            try:
                real_name, issuer = verify_peer_identity(remote_pub, session.remote_proofs)
                self.on_log(f"✅ Verified Identity: {real_name}")
                self.on_log(f"   ↳ Signed by: {issuer}")
            except Exception as e:
                self.on_log(f"⛔ SECURITY ALERT: {e}")
                return

            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Response sent to {addr} (CID: {session.local_index})")
            
            asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], remote_pub, real_name=real_name))
            if self.on_handshake_success:
                self.on_handshake_success(addr, remote_pub, real_name)
            
            # NUEVO: Consolidar colas por identidad y forzar envío si hay pendientes
            self.consolidate_peer_sessions(session, addr)
            if addr in self.peer_message_queues and self.peer_message_queues[addr]:
                head = self.peer_message_queues[addr][0]
                asyncio.create_task(self._attempt_send_head(addr, head))
                
        except Exception as e:
            self.on_log(f"❌ Handshake failed: {e}")
            if session.local_index in self.sessions.sessions_by_id:
                del self.sessions.sessions_by_id[session.local_index]

    def handle_handshake_resp(self, data, addr):
        if len(data) < 8: return
        receiver_index = struct.unpack('<I', data[4:8])[0]
        session = self.sessions.get_session_by_id(receiver_index)
        
        if not session: 
            self.on_log(f"❌ Received HandshakeResp for unknown ID {receiver_index}")
            return

        try:
            # Check Roaming y Migrar Cola
            old_addr = session.current_addr
            if self.sessions.update_session_addr(session, addr):
                 self.on_log(f"ℹ️ Peer {session.local_index} roamed to {addr}")
                 self.migrate_queue(old_addr, addr)

            session.consume_handshake_response(data)
            try:
                real_name, issuer = verify_peer_identity(session.rs_pub, session.remote_proofs)
                self.on_log(f"✅ Verified Identity: {real_name}")
                self.on_log(f"   ↳ Signed by: {issuer}")
                asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], session.rs_pub, real_name=real_name))
            except Exception as e:
                self.on_log(f"⛔ SECURITY ALERT: {e}")
                return

            self.on_log(f"🔒 Secure Session established with {real_name} (CID: {session.local_index})")
            if self.on_handshake_success:
                self.on_handshake_success(addr, session.rs_pub, real_name)

            # NUEVO: Consolidar colas por identidad (Cross-IP Queue Migration)
            self.consolidate_peer_sessions(session, addr)

            # Forzar envío inmediato si hay cola (ahora en la dirección correcta)
            if addr in self.peer_message_queues and self.peer_message_queues[addr]:
                head = self.peer_message_queues[addr][0]
                asyncio.create_task(self._attempt_send_head(addr, head))

        except Exception as e:
            self.on_log(f"❌ Handshake completion failed: {e}")

    def handle_data(self, data, addr):
        if len(data) < 4: return
        receiver_index = struct.unpack('<I', data[:4])[0]
        encrypted_payload = data[4:]
        session = self.sessions.get_session_by_id(receiver_index)
        
        if not session:
            self.on_log(f"❌ Data packet for unknown session ID {receiver_index} from {addr}")
            return
        
        # Check Roaming y Migrar Cola
        old_addr = session.current_addr
        if self.sessions.update_session_addr(session, addr):
             self.on_log(f"ℹ️ Peer {session.local_index} roamed to {addr}")
             self.migrate_queue(old_addr, addr)
        
        try:
            plaintext = session.decrypt_message(encrypted_payload)
            msg_struct = json.loads(plaintext.decode('utf-8'))

            # --- MANEJO DE ACK (SEQUENTIAL) ---
            if 'ack_id' in msg_struct:
                ack_id = msg_struct['ack_id']
                if addr in self.peer_message_queues and self.peer_message_queues[addr]:
                    queue = self.peer_message_queues[addr]
                    # Solo confirmamos si coincide con la cabecera (orden estricto)
                    if queue and queue[0]['msg_id'] == ack_id:
                        queue.popleft() # ¡Confirmado! Quitamos de la cola
                        
                        # Si queda otro mensaje, lo enviamos inmediatamente (Trigger Chain)
                        if queue:
                            next_head = queue[0]
                            next_head['last_retry'] = 0 # Reset para envío inmediato
                            next_head['attempts'] = 0
                            asyncio.create_task(self._attempt_send_head(addr, next_head))

                if self.on_ack_received:
                    self.on_ack_received(addr, ack_id)
                return 

            # --- MANEJO DE MENSAJES DE TEXTO ---
            if 'text' in msg_struct and 'hash' in msg_struct:
                content = msg_struct['text']
                received_hash = msg_struct['hash']
                local_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                msg_struct['integrity'] = (local_hash == received_hash)
            
            # --- DEDUPLICACIÓN Y ENVÍO DE ACK ---
            if 'id' in msg_struct and not msg_struct.get('disconnect'):
                incoming_id = msg_struct['id']
                asyncio.create_task(self.send_ack(addr, incoming_id))
                
                if incoming_id in self.dedup_buffer:
                    return
                self.dedup_buffer.append(incoming_id)

            self.on_message(addr, msg_struct)
            
        except Exception as e:
            self.on_log(f"❌ Decryption failed: {e}")

    async def send_ack(self, addr, msg_id):
        session = self.sessions.get_session_by_addr(addr)
        if not session or not session.encryptor: return
        try:
            ack_payload = {"timestamp": time.time(), "ack_id": msg_id}
            json_bytes = json.dumps(ack_payload).encode('utf-8')
            full_packet_payload = session.encrypt_message(json_bytes)
            self.transport.sendto(b'\x03' + full_packet_payload, addr)
        except Exception as e:
            self.on_log(f"❌ Failed to send ACK: {e}")

    async def broadcast_disconnect(self):
        self.on_log("📡 Sending encrypted disconnect to active chats...")
        active_sessions = list(self.sessions.sessions_by_addr.values())
        tasks = []
        for sess in active_sessions:
            # Disconnects bypass the queue
            tasks.append(self._transmit_raw(sess.current_addr, None, str(uuid.uuid4()), is_disconnect=True))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_message(self, addr, content, is_disconnect=False, forced_msg_id=None):
        """
        Encola un mensaje para envío secuencial y fiable.
        Returns: msg_id (str) inmediatamente.
        """
        msg_id = forced_msg_id if forced_msg_id else str(uuid.uuid4())
        
        # Caso especial: Disconnects no se encolan, se envían directos
        if is_disconnect:
            await self._transmit_raw(addr, content, msg_id, is_disconnect=True)
            return msg_id

        # Encolado Secuencial
        if addr not in self.peer_message_queues:
            self.peer_message_queues[addr] = deque()
            
        queue = self.peer_message_queues[addr]
        
        # MODIFICADO: Capturar timestamp AHORA (creación) para usarlo siempre
        creation_timestamp = time.time()
        
        queue.append({
            'msg_id': msg_id,
            'content': content,
            'attempts': 0,
            'last_retry': 0,
            'timestamp': creation_timestamp # Guardamos la hora original
        })
        
        # Si era el único mensaje (la cola estaba vacía), iniciamos el proceso de envío
        if len(queue) == 1:
            await self._attempt_send_head(addr, queue[0])
            
        return msg_id

    async def _transmit_raw(self, addr, content, msg_id, is_disconnect=False, timestamp=None):
        """Lógica de bajo nivel: Busca sesión y envía, o inicia handshake."""
        session = self.sessions.get_session_by_addr(addr)
        
        if not session and is_disconnect:
            return

        # FIX: Detectar sesión atascada en handshake incompleto (Stale Session)
        if session and session.encryptor is None:
            # Si estamos aquí, es porque el retry loop ha disparado este intento y el handshake sigue sin acabar.
            # Borramos la sesión para forzar un nuevo Handshake Init.
            if session.current_addr in self.sessions.sessions_by_addr:
                del self.sessions.sessions_by_addr[session.current_addr]
            if session.local_index in self.sessions.sessions_by_id:
                del self.sessions.sessions_by_id[session.local_index]
            session = None

        # Si no hay sesión, iniciamos Handshake (no enviamos datos aún)
        if not session:
            # Buscamos pubkey para iniciar handshake
            remote_pub = await self.sessions.db.get_pubkey_by_addr(addr[0], addr[1])
            if not remote_pub:
                self.on_log(f"❌ Cannot send: No public key for {addr}")
                # Si falla fatalmente, deberíamos quitarlo de la cola para no bloquear,
                # pero por simplicidad dejamos que el retry expire o el usuario intervenga.
                return 
            
            # Start Handshake
            session = self.sessions.create_initiator_session(addr, remote_pub)
            hs_msg = session.create_handshake_message()
            self.transport.sendto(b'\x01' + hs_msg, addr)
            self.on_log(f"🔄 Initiating handshake with {addr} (Triggered by queue)")
            return 

        # Enviar mensaje cifrado (La sesión ya debe estar completa aquí)
        try:
            if is_disconnect:
                msg_struct = {"timestamp": time.time(), "disconnect": True}
            else:
                text_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                
                # Usamos el timestamp original si se proporciona (reintentos), sino el actual
                final_ts = timestamp if timestamp is not None else time.time()
                
                msg_struct = {
                    "id": msg_id,
                    "timestamp": final_ts, 
                    "text": content,
                    "hash": text_hash
                }
            
            payload = json.dumps(msg_struct).encode('utf-8')
            full_packet_payload = session.encrypt_message(payload)
            self.transport.sendto(b'\x03' + full_packet_payload, addr)
            
        except Exception as e:
            self.on_log(f"❌ Send raw failed: {e}")

class RawSniffer(asyncio.DatagramProtocol):
    def __init__(self, service):
        self.service = service
        self.transport = None
        self.sock = None

    def connection_made(self, transport):
        self.transport = transport
        self.sock = transport.get_extra_info('socket')
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except: pass

        self.join_multicast_groups()

    def join_multicast_groups(self):
        """
        Se asegura de que el socket sea miembro del grupo multicast en todas las interfaces.
        Es seguro llamar a esto repetidamente (los errores de 'ya unido' se ignoran).
        """
        if not self.sock: return
        group = socket.inet_aton('224.0.0.251')
        
        # 1. Intento unirse en la interfaz por defecto (INADDR_ANY)
        try:
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except: pass

        # 2. Intento unirse explícitamente en todas las interfaces detectadas
        # Esto es vital si la interfaz por defecto cambia o cae.
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
                            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
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
                user_id_from_net, port = found_info
                if user_id_from_net == self.service.unique_instance_id and port == self.service.port:
                    return

                props = {'user': user_id_from_net}
                is_exit_msg = re.search(rb'stat=exit', data)
                if is_exit_msg:
                    props['stat'] = 'exit'
                    self.service.on_found(user_id_from_net, addr[0], port, props)
                    return

                try:
                    pub_match = re.search(rb'pub=([a-fA-F0-9]+)', data)
                    if pub_match:
                        pub_str = pub_match.group(1).decode('utf-8')
                        if len(pub_str) != 64: return 
                        props['pub'] = pub_str
                    else:
                        return 
                except: return
                
                try:
                    user_match = re.search(rb'user=([^\x00]+)', data)
                    if user_match:
                        clean_user = user_match.group(1).decode('utf-8')
                        props['user'] = clean_user
                except: pass

                self.service.on_found(user_id_from_net, addr[0], port, props)
        except Exception:
            pass

class DiscoveryService:
    def __init__(self, port, pubkey_bytes, on_service_found, on_log=None):
        self.aiozc = None 
        self.port = port
        self.pubkey_b64 = pubkey_bytes.hex()
        self.on_found = on_service_found
        self.on_log = on_log if on_log else lambda x: None
        self.loop = None
        self.sniffer_transport = None
        self.sniffer_protocol = None 
        self.bind_ip = None
        self.unique_instance_id = None 
        self.protocol_ref = None # Referencia al protocolo para notificar cambios

    def set_protocol(self, proto):
        self.protocol_ref = proto

    async def start(self, username, bind_ip=None):
        self.loop = asyncio.get_running_loop()
        self.bind_ip = bind_ip
        
        clean_username = username.replace("User-", "")
        self.unique_instance_id = clean_username
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except: pass
            sock.bind(('', 5353))
            
            # Guardamos transporte Y protocolo
            self.sniffer_transport, self.sniffer_protocol = await self.loop.create_datagram_endpoint(
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
        service_name = f"User-{self.unique_instance_id}_{self.port}.{MDNS_TYPE}"
        
        desc = {'pub': self.pubkey_b64, 'user': clean_username}
        self.info = ServiceInfo(
            MDNS_TYPE, service_name, addresses=[socket.inet_aton(local_ip)],
            port=self.port, properties=desc, server=f"{socket.gethostname()}.local."
        )
        
        self.on_log(f"📢 Advertising: {service_name} @ {local_ip}")
        await self.aiozc.async_register_service(self.info)
        
        self._polling_task = asyncio.create_task(self._active_polling_loop())

    def on_found(self, user_id, ip, port, props):
        # Lógica original de on_found (delegada a TUI)
        if self.on_found_callback:
             self.on_found_callback(user_id, ip, port, props)
        
        # NUEVO: Notificar al protocolo sobre posible Roaming
        # Esto ayuda si el cambio de IP se detecta por mDNS antes que por tráfico UDP directo
        if self.protocol_ref:
             # Buscamos si tenemos una sesión activa con este usuario (por ID) para actualizar IP
             # Como DiscoveryService no tiene acceso directo al session manager, 
             # delegamos una función específica en UDPProtocol si es necesario,
             # pero aquí lo crítico es que el protocolo sepa "Oye, User X está en IP Y".
             # Sin embargo, el protocolo trabaja con IPs, no UserIDs en su capa baja.
             # La forma más robusta es que la TUI, al recibir on_found, notifique al protocolo
             # si detecta que es un usuario conocido con IP diferente.
             pass

    # Modificamos init para guardar el callback original correctamente
    def __init__(self, port, pubkey_bytes, on_service_found, on_log=None):
        self.aiozc = None 
        self.port = port
        self.pubkey_b64 = pubkey_bytes.hex()
        self.on_found_callback = on_service_found # Renombramos para uso interno
        self.on_log = on_log if on_log else lambda x: None
        self.loop = None
        self.sniffer_transport = None
        self.sniffer_protocol = None 
        self.bind_ip = None
        self.unique_instance_id = None 
        self.protocol_ref = None

    def broadcast_exit(self):
        if not self.sniffer_transport: return
        try:
            fake_payload = (
                b'\x00' * 12 +     
                b'_dni-im' +       
                f'User-{self.unique_instance_id}_{self.port}'.encode('utf-8') + 
                b'\x00fake\x00' +  
                b'stat=exit'       
            )
            self.sniffer_transport.sendto(fake_payload, ('224.0.0.251', 5353))
            self.on_log("📡 Broadcasted custom 'stat=exit' mDNS packet.")
        except Exception as e:
            print(f"Error broadcasting exit: {e}")

    async def stop(self):
        self.broadcast_exit()
        if hasattr(self, '_polling_task'): self._polling_task.cancel()
        if self.sniffer_transport: self.sniffer_transport.close()
        if hasattr(self, 'info') and hasattr(self, 'aiozc'): 
            await self.aiozc.async_unregister_service(self.info)
        if hasattr(self, 'aiozc'): await self.aiozc.async_close()

    def refresh(self):
        if self.sniffer_transport:
             try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
             except: pass

    async def _active_polling_loop(self):
        while True:
            await asyncio.sleep(5)
            
            # RE-UNIRSE a grupos multicast si la red ha cambiado
            if self.sniffer_protocol:
                self.sniffer_protocol.join_multicast_groups()

            # DETECTAR CAMBIO DE IP Y REINICIAR SERVICIO SI ES NECESARIO
            if hasattr(self, 'info') and self.aiozc:
                try:
                    # Determinar IP actual
                    current_ip = self.bind_ip if (self.bind_ip and self.bind_ip != "0.0.0.0") else self.get_local_ip()
                    current_ip_bytes = socket.inet_aton(current_ip)
                    
                    # Comprobamos si la IP registrada coincide con la actual
                    registered_ip_bytes = self.info.addresses[0] if self.info.addresses else b''

                    if registered_ip_bytes != current_ip_bytes:
                         self.on_log(f"🔄 Network IP changed: {current_ip}. Restarting mDNS Service...")
                         
                         # 1. Desregistrar servicio antiguo
                         try: await self.aiozc.async_unregister_service(self.info)
                         except: pass
                         
                         # 2. Cerrar instancia vieja (para liberar sockets viejos)
                         try: await self.aiozc.async_close()
                         except: pass
                         
                         # 3. Crear nueva instancia Zeroconf
                         interfaces = InterfaceChoice.All
                         if self.bind_ip and self.bind_ip != "0.0.0.0": interfaces = [self.bind_ip]
                         
                         try:
                             self.aiozc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only)
                         except:
                             self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All)

                         # 4. Actualizar IP en la info del servicio
                         self.info.addresses = [current_ip_bytes]
                         
                         # 5. Registrar de nuevo con la nueva instancia
                         await self.aiozc.async_register_service(self.info)
                         self.on_log(f"✅ mDNS Service Restarted on {current_ip}")

                    else:
                        # Si la IP no ha cambiado, enviamos un "update" como heartbeat
                        await self.aiozc.async_update_service(self.info)
                        
                except Exception as e:
                    # self.on_log(f"⚠️ Error updating mDNS: {e}")
                    pass

            if self.sniffer_transport:
                 try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                 except: pass

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 80)); IP = s.getsockname()[0]
        except: IP = '127.0.0.1'
        finally: s.close()
        return IP