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
from cryptography.hazmat.primitives.asymmetric import padding, x25519

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
        
        # Mapping sessions by ID for Multiplexing
        self.sessions_by_addr = {} # (ip, port) -> session
        self.sessions_by_id = {}   # local_index (int) -> session
        
        # PRO-P2P: Identity Index to handle Roaming
        # key: pub_key_bytes, value: session
        self.sessions_by_identity = {} 
        
        self.db = db
        self.transport = None

    def get_session_by_addr(self, addr):
        return self.sessions_by_addr.get(addr)
    
    def get_session_by_id(self, idx):
        return self.sessions_by_id.get(idx)
    
    def get_session_by_pubkey(self, pub_bytes):
        return self.sessions_by_identity.get(pub_bytes)

    def register_session(self, session, addr):
        self.sessions_by_addr[addr] = session
        self.sessions_by_id[session.local_index] = session
        session.current_addr = addr
        
        # If remote pub key is known (Handshake done or initiated with known key)
        if session.rs_pub:
            pub_bytes = session.rs_pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            self.sessions_by_identity[pub_bytes] = session

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
        """
        Maneja el Roaming: Si la IP cambia, actualiza el puntero de la sesión.
        """
        if session.current_addr != new_addr:
            # Eliminar referencia antigua
            if session.current_addr in self.sessions_by_addr:
                del self.sessions_by_addr[session.current_addr]
            
            # Actualizar
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
        
        # --- PRO-P2P: IDENTITY BASED QUEUES ---
        # Key: pub_key_bytes (Identity) OR addr (Temporary/Anonymous)
        # Value: deque of dicts
        self.message_queues = {} 
        
        # --- HANDSHAKE PROTECTION ---
        # Rastrea handshakes en curso para evitar que el worker de reintentos mate la sesión
        # antes de que termine. Key: addr, Value: timestamp
        self.pending_handshakes = {}
        
        self.dedup_buffer = deque(maxlen=200)
        self._retry_task_handle = None

    def connection_made(self, transport):
        self.transport = transport
        self.sessions.transport = transport
        try:
            sock = transport.get_extra_info('socket')
            addr = sock.getsockname()
            self.on_log(f"✅ UDP Bound to {addr[0]}:{addr[1]}")
        except: pass
        
        self._retry_task_handle = asyncio.create_task(self._retry_worker())

    def _get_queue_key(self, addr, pub_bytes=None):
        """
        Devuelve la clave para la cola. 
        Prioridad: Identidad (pub_bytes) > Dirección IP (addr)
        """
        if pub_bytes:
            return pub_bytes # Identity Queue (Persistent)
        
        # Si no tenemos identidad, buscamos si hay sesión asociada a esta IP
        session = self.sessions.get_session_by_addr(addr)
        if session and session.rs_pub:
            return session.rs_pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        
        return addr # Anonymous/Temporary Queue

    def promote_queue_to_identity(self, addr, pub_bytes):
        """
        Mueve mensajes de una cola temporal basada en IP a una basada en Identidad.
        Crucial cuando completamos un handshake y verificamos quién es.
        """
        if not pub_bytes: return
        
        # Claves
        id_key = pub_bytes
        ip_key = addr
        
        if ip_key in self.message_queues:
            self.on_log(f"🔗 Promoting queue from IP {addr} to Identity (Roaming ready)")
            temp_queue = self.message_queues.pop(ip_key)
            
            if id_key not in self.message_queues:
                self.message_queues[id_key] = temp_queue
            else:
                # Appendleft para mantener orden cronológico si había mezcla
                self.message_queues[id_key].extendleft(reversed(temp_queue))
            
            # Forzar reintento inmediato
            if self.message_queues[id_key]:
                self.message_queues[id_key][0]['last_retry'] = 0

    def update_peer_location(self, new_addr, pub_bytes):
        """
        Llamado por DiscoveryService cuando detecta un peer.
        Si tenemos mensajes en cola y detectamos cambio de IP, forzamos Handshake.
        """
        # 1. Buscar si existe sesión activa
        session = self.sessions.get_session_by_pubkey(pub_bytes)
        has_pending = pub_bytes in self.message_queues and self.message_queues[pub_bytes]
        
        # Forzar que la cola se procese INMEDIATAMENTE
        if has_pending:
            self.message_queues[pub_bytes][0]['last_retry'] = 0

        # Check anti-spam para handshakes
        is_handshake_pending = new_addr in self.pending_handshakes and (time.time() - self.pending_handshakes[new_addr] < 5.0)

        if session:
            # Caso A: Sesión existe
            ip_changed = self.sessions.update_session_addr(session, new_addr)
            
            if ip_changed or has_pending:
                self.on_log(f"📍 Peer located at {new_addr}")
                
                if has_pending and not is_handshake_pending:
                    self.on_log(f"⚡ IP Changed & Pending Messages -> Forcing Handshake to {new_addr}")
                    try:
                        pub_key_obj = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                        # Sobreescribimos la sesión con una nueva iniciadora
                        new_session = self.sessions.create_initiator_session(new_addr, pub_key_obj)
                        hs_msg = new_session.create_handshake_message()
                        self.transport.sendto(b'\x01' + hs_msg, new_addr)
                        # Registrar handshake pendiente para proteger la sesión
                        self.pending_handshakes[new_addr] = time.time()
                    except Exception as e:
                        self.on_log(f"❌ Force Handshake failed: {e}")
                    
        else:
            # Caso B: No hay sesión, pero hay cola. (Auto-Healing)
            if has_pending and not is_handshake_pending:
                self.on_log(f"🔍 Found peer at {new_addr}, triggering Handshake for pending queue...")
                try:
                    pub_key_obj = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                    session = self.sessions.create_initiator_session(new_addr, pub_key_obj)
                    hs_msg = session.create_handshake_message()
                    self.transport.sendto(b'\x01' + hs_msg, new_addr)
                    # Registrar handshake pendiente
                    self.pending_handshakes[new_addr] = time.time()
                    self.on_log(f"🔄 Auto-Healing: Initiating handshake with {new_addr}")
                except Exception as e:
                    self.on_log(f"❌ Auto-Healing failed: {e}")

    async def _retry_worker(self):
        """
        Professional Retry Logic:
        En lugar de reintentar a la IP guardada en el mensaje,
        resuelve la IP actual de la Identidad en cada ciclo.
        Esto permite que si la IP cambia, el siguiente reintento vaya al lugar correcto.
        """
        while True:
            await asyncio.sleep(1.0)
            now = time.time()
            
            # Iteramos sobre una copia de las claves
            for queue_key in list(self.message_queues.keys()):
                queue = self.message_queues[queue_key]
                if not queue: continue
                
                head = queue[0]
                attempts = head['attempts']
                delta = now - head['last_retry']
                
                # Backoff exponencial limitado
                interval = min(2.0 * (1.5 ** attempts), 30.0)
                if attempts == 0: interval = 0 # Primer intento inmediato
                
                if delta >= interval:
                    # RESOLUCIÓN DINÁMICA DE DESTINO
                    target_addr = None
                    
                    if isinstance(queue_key, bytes):
                        # Es una cola basada en Identidad. Buscamos la IP actual.
                        session = self.sessions.get_session_by_pubkey(queue_key)
                        if session:
                            target_addr = session.current_addr
                        else:
                            # Tenemos cola pero no sesión activa.
                            # Si update_peer_location funciona bien, ya debería haber intentado handshake.
                            continue 
                    else:
                        # Es una cola basada en IP (Handshake inicial)
                        target_addr = queue_key
                    
                    if target_addr:
                        try:
                            await self._attempt_send_head(target_addr, head)
                        except Exception as e:
                            # print(f"Retry error: {e}")
                            pass

    async def _attempt_send_head(self, addr, item):
        item['last_retry'] = time.time()
        item['attempts'] += 1
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
            
            # Verificar Identidad
            try:
                real_name, issuer = verify_peer_identity(remote_pub, session.remote_proofs)
                self.on_log(f"✅ Verified Identity: {real_name}")
            except Exception as e:
                self.on_log(f"⛔ SECURITY ALERT: {e}")
                return

            # Registrar sesión por identidad también
            pub_bytes = remote_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.sessions.sessions_by_identity[pub_bytes] = session

            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Response sent to {addr}")
            
            asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], remote_pub, real_name=real_name))
            if self.on_handshake_success:
                self.on_handshake_success(addr, remote_pub, real_name)
            
            # PRO-P2P: Si teníamos mensajes en cola para esta IP (anónima), 
            # ahora sabemos quién es -> Promocionamos la cola a Identidad.
            self.promote_queue_to_identity(addr, pub_bytes)
            
            # WAKE UP QUEUE: Si tenemos mensajes para este usuario, despierta la cola ahora
            if pub_bytes in self.message_queues and self.message_queues[pub_bytes]:
                self.message_queues[pub_bytes][0]['last_retry'] = 0
                self.on_log(f"🚀 Found pending queue for incoming peer {real_name}, activating...")
                
        except Exception as e:
            self.on_log(f"❌ Handshake failed: {e}")
            if session.local_index in self.sessions.sessions_by_id:
                del self.sessions.sessions_by_id[session.local_index]

    def handle_handshake_resp(self, data, addr):
        # Limpiar flag de handshake pendiente
        self.pending_handshakes.pop(addr, None)
        
        if len(data) < 8: return
        receiver_index = struct.unpack('<I', data[4:8])[0]
        session = self.sessions.get_session_by_id(receiver_index)
        
        if not session: return

        try:
            # Check Roaming
            old_addr = session.current_addr
            if self.sessions.update_session_addr(session, addr):
                 self.on_log(f"ℹ️ Peer {session.local_index} roamed to {addr}")

            session.consume_handshake_response(data)
            
            # Verificar Identidad
            try:
                real_name, issuer = verify_peer_identity(session.rs_pub, session.remote_proofs)
                self.on_log(f"✅ Verified Identity: {real_name} (Completed)")
                asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], session.rs_pub, real_name=real_name))
            except Exception as e:
                self.on_log(f"⛔ SECURITY ALERT: {e}")
                return

            # Registrar sesión por identidad
            pub_bytes = session.rs_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.sessions.sessions_by_identity[pub_bytes] = session

            if self.on_handshake_success:
                self.on_handshake_success(addr, session.rs_pub, real_name)

            # PRO-P2P: Promocionar cola de IP a Identidad
            self.promote_queue_to_identity(addr, pub_bytes)
            
            # Despertar worker de reintentos para esta identidad inmediatamente
            if pub_bytes in self.message_queues and self.message_queues[pub_bytes]:
                self.message_queues[pub_bytes][0]['last_retry'] = 0

        except Exception as e:
            self.on_log(f"❌ Handshake completion failed: {e}")

    def handle_data(self, data, addr):
        if len(data) < 4: return
        receiver_index = struct.unpack('<I', data[:4])[0]
        encrypted_payload = data[4:]
        session = self.sessions.get_session_by_id(receiver_index)
        
        if not session: return
        
        # PRO-P2P: Roaming Automático en recepción de datos
        # Si recibimos datos válidos de una nueva IP, actualizamos la ruta
        if self.sessions.update_session_addr(session, addr):
             self.on_log(f"🚀 Roaming detected: Peer moved to {addr}")
             # Al actualizar la sesión, el próximo ciclo de _retry_worker
             # enviará automáticamente a la nueva IP.
        
        try:
            plaintext = session.decrypt_message(encrypted_payload)
            msg_struct = json.loads(plaintext.decode('utf-8'))

            # --- MANEJO DE ACK ---
            if 'ack_id' in msg_struct:
                ack_id = msg_struct['ack_id']
                queue_key = self._get_queue_key(addr) # Obtiene PubKey si posible
                
                # Buscar en la cola correcta
                if queue_key in self.message_queues:
                    queue = self.message_queues[queue_key]
                    if queue and queue[0]['msg_id'] == ack_id:
                        queue.popleft() # Confirmado
                        # Trigger siguiente
                        if queue:
                            queue[0]['last_retry'] = 0
                            queue[0]['attempts'] = 0

                if self.on_ack_received:
                    self.on_ack_received(addr, ack_id)
                return 

            # --- MENSAJES DE TEXTO ---
            if 'text' in msg_struct and 'hash' in msg_struct:
                content = msg_struct['text']
                received_hash = msg_struct['hash']
                local_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                msg_struct['integrity'] = (local_hash == received_hash)
            
            if 'id' in msg_struct and not msg_struct.get('disconnect'):
                incoming_id = msg_struct['id']
                asyncio.create_task(self.send_ack(session, incoming_id)) # Pass session, not just addr
                
                if incoming_id in self.dedup_buffer:
                    return
                self.dedup_buffer.append(incoming_id)

            self.on_message(addr, msg_struct)
            
        except Exception as e:
            self.on_log(f"❌ Decryption failed: {e}")

    async def send_ack(self, session, msg_id):
        # Usamos la sesión directamente para asegurar que respondemos a donde está ahora
        if not session or not session.encryptor: return
        try:
            ack_payload = {"timestamp": time.time(), "ack_id": msg_id}
            json_bytes = json.dumps(ack_payload).encode('utf-8')
            full_packet_payload = session.encrypt_message(json_bytes)
            # Enviar a la dirección actual de la sesión
            self.transport.sendto(b'\x03' + full_packet_payload, session.current_addr)
        except Exception as e:
            self.on_log(f"❌ Failed to send ACK: {e}")

    async def broadcast_disconnect(self):
        self.on_log("📡 Sending encrypted disconnect...")
        active_sessions = list(self.sessions.sessions_by_addr.values())
        tasks = []
        for sess in active_sessions:
            tasks.append(self._transmit_raw(sess.current_addr, None, str(uuid.uuid4()), is_disconnect=True))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_message(self, addr, content, is_disconnect=False, forced_msg_id=None):
        msg_id = forced_msg_id if forced_msg_id else str(uuid.uuid4())
        
        if is_disconnect:
            await self._transmit_raw(addr, content, msg_id, is_disconnect=True)
            return msg_id

        # Determinamos la clave de la cola (Identidad o IP)
        queue_key = self._get_queue_key(addr)
        
        if queue_key not in self.message_queues:
            self.message_queues[queue_key] = deque()
            
        queue = self.message_queues[queue_key]
        
        queue.append({
            'msg_id': msg_id,
            'content': content,
            'attempts': 0,
            'last_retry': 0,
            'timestamp': time.time()
        })
        
        # Intentar enviar inmediatamente si es el primero
        if len(queue) == 1:
            await self._attempt_send_head(addr, queue[0])
            
        return msg_id

    async def _transmit_raw(self, addr, content, msg_id, is_disconnect=False, timestamp=None):
        session = self.sessions.get_session_by_addr(addr)
        
        # Verificar si hay un handshake pendiente para esta dirección
        is_handshake_pending = addr in self.pending_handshakes and (time.time() - self.pending_handshakes[addr] < 5.0)

        # Stale Session check (Solo si NO hay handshake pendiente)
        if session and session.encryptor is None:
            if not is_handshake_pending:
                # Limpiar sesión muerta
                if session.current_addr in self.sessions.sessions_by_addr:
                    del self.sessions.sessions_by_addr[session.current_addr]
                session = None
            else:
                # Si hay handshake pendiente, simplemente esperamos
                return 

        if not session:
            # Si ya tenemos un handshake pendiente, no spameamos otro
            if is_handshake_pending:
                return

            # Handshake
            remote_pub = await self.sessions.db.get_pubkey_by_addr(addr[0], addr[1])
            if not remote_pub:
                self.on_log(f"❌ Cannot send: No public key for {addr}")
                return 
            
            session = self.sessions.create_initiator_session(addr, remote_pub)
            hs_msg = session.create_handshake_message()
            self.transport.sendto(b'\x01' + hs_msg, addr)
            # Marcar handshake como pendiente
            self.pending_handshakes[addr] = time.time()
            self.on_log(f"🔄 Initiating handshake with {addr}")
            return 

        # Enviar mensaje cifrado
        try:
            if is_disconnect:
                msg_struct = {"timestamp": time.time(), "disconnect": True}
            else:
                text_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                final_ts = timestamp if timestamp is not None else time.time()
                msg_struct = {
                    "id": msg_id,
                    "timestamp": final_ts, 
                    "text": content,
                    "hash": text_hash
                }
            
            payload = json.dumps(msg_struct).encode('utf-8')
            full_packet_payload = session.encrypt_message(payload)
            
            # PRO-P2P: Siempre enviar a la dirección actual que la sesión cree tener
            self.transport.sendto(b'\x03' + full_packet_payload, session.current_addr)
            
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
        if not self.sock: return
        group = socket.inet_aton('224.0.0.251')
        try:
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
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
        self.on_found_callback = on_service_found 
        self.on_log = on_log if on_log else lambda x: None
        self.loop = None
        self.sniffer_transport = None
        self.sniffer_protocol = None 
        self.bind_ip = None
        self.unique_instance_id = None 
        self.protocol_ref = None

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
        if self.on_found_callback:
             self.on_found_callback(user_id, ip, port, props)
             
        # NUEVO: Roaming proactivo basado en mDNS
        if self.protocol_ref and 'pub' in props:
            try:
                pub_hex = props['pub']
                pub_bytes = bytes.fromhex(pub_hex)
                # Notificamos al protocolo para que actualice rutas o despierte colas
                self.protocol_ref.update_peer_location((ip, port), pub_bytes)
            except Exception as e:
                pass # Ignorar errores de parsing en descubrimiento

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
            if self.sniffer_protocol:
                self.sniffer_protocol.join_multicast_groups()
            if hasattr(self, 'info') and self.aiozc:
                try:
                    current_ip = self.bind_ip if (self.bind_ip and self.bind_ip != "0.0.0.0") else self.get_local_ip()
                    current_ip_bytes = socket.inet_aton(current_ip)
                    registered_ip_bytes = self.info.addresses[0] if self.info.addresses else b''

                    if registered_ip_bytes != current_ip_bytes:
                         self.on_log(f"🔄 Network IP changed: {current_ip}. Restarting mDNS Service...")
                         
                         # --- RESTART SNIFFER SOCKET ---
                         # Crucial cuando cambia la interfaz de red (e.g. WiFi -> 4G)
                         if self.sniffer_transport:
                             self.sniffer_transport.close()
                             
                         try:
                             sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                             sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                             try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                             except: pass
                             sock.bind(('', 5353))
                             
                             self.sniffer_transport, self.sniffer_protocol = await self.loop.create_datagram_endpoint(
                                 lambda: RawSniffer(self), sock=sock
                             )
                             self.on_log("👂 Sniffer Restarted")
                         except Exception as e:
                             self.on_log(f"⚠️ Sniffer restart failed: {e}")
                         
                         # --- RESTART AIOZC ---
                         try: await self.aiozc.async_unregister_service(self.info)
                         except: pass
                         try: await self.aiozc.async_close()
                         except: pass
                         
                         interfaces = InterfaceChoice.All
                         if self.bind_ip and self.bind_ip != "0.0.0.0": interfaces = [self.bind_ip]
                         try: self.aiozc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only)
                         except: self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All)

                         self.info.addresses = [current_ip_bytes]
                         await self.aiozc.async_register_service(self.info)
                         self.on_log(f"✅ mDNS Service Restarted on {current_ip}")
                    else:
                        await self.aiozc.async_update_service(self.info)
                except Exception as e: pass

            if self.sniffer_transport:
                 try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                 except: pass

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 80)); IP = s.getsockname()[0]
        except: IP = '127.0.0.1'
        finally: s.close()
        return IP