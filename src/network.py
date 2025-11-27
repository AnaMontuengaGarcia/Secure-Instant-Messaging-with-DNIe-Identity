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
        
        # Registrar la clave efímera para poder encontrar la cola más tarde
        # Esto es importante para recuperar colas huérfanas cuando cambia la IP
        self.db.ephemeral_keys[addr] = remote_pub_key
        
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
        
        # --- COLAS DE MENSAJES POR ID DE USUARIO (DNIe ID) ---
        # Key: user_id (string, ej: "896fde27" - primeros 8 chars del hash del DNIe)
        # Value: deque of dicts con mensajes pendientes
        # Las colas SOLO se identifican por user_id, la IP se resuelve en tiempo real
        self.message_queues = {}
        
        # --- CALLBACKS PARA RESOLVER DESDE EL TUI ---
        # get_peer_addr(user_id) -> (ip, port) or None
        self.get_peer_addr_callback = None
        # get_user_id_for_addr(addr) -> user_id or None
        self.get_user_id_callback = None
        
        # --- LATEST KNOWN LOCATIONS (Discovery Source of Truth) ---
        # Key: pub_key_bytes -> (ip, port)
        # Esto permite saber dónde está un usuario incluso si no hay sesión activa
        self.latest_peer_locations = {}
        
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

    def _get_pub_key_for_addr(self, addr):
        """
        Obtiene la clave pública asociada a una dirección.
        Retorna pub_bytes o None si no se puede determinar.
        """
        # 1. Búsqueda en caché de Discovery (La más fresca)
        for p_key, p_addr in self.latest_peer_locations.items():
            if p_addr == addr:
                return p_key

        # 2. Si no tenemos identidad en mDNS, buscamos si hay sesión activa
        session = self.sessions.get_session_by_addr(addr)
        if session and session.rs_pub:
            return session.rs_pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        
        # 3. Buscar en la base de datos de claves efímeras (almacén persistente)
        known_key = self.sessions.db.ephemeral_keys.get(addr)
        if known_key:
            try:
                return known_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            except: pass
        
        return None  # No se puede determinar la identidad

    def update_peer_location(self, new_addr, pub_bytes):
        """
        Llamado por DiscoveryService cuando detecta un peer.
        Actualiza la 'Source of Truth' de ubicaciones y despierta colas.
        """
        pub_hex_short = pub_bytes.hex()[:8] if pub_bytes else "None"
        self.on_log(f"📡 Discovery update: peer {pub_hex_short}... at {new_addr}")
        
        # 1. Actualizar el mapa de ubicaciones (Discovery)
        if pub_bytes:
            old_addr = self.latest_peer_locations.get(pub_bytes)
            self.latest_peer_locations[pub_bytes] = new_addr
            
            if old_addr and old_addr != new_addr:
                self.on_log(f"📍 IP CHANGED: {old_addr} -> {new_addr}")
                # Limpiar handshake pendiente de la IP antigua
                self.pending_handshakes.pop(old_addr, None)
            elif not old_addr:
                self.on_log(f"📍 NEW peer location: {new_addr}")
            
            # Actualizar ephemeral_keys con la nueva dirección
            try:
                pub_key_obj = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                self.sessions.db.ephemeral_keys[new_addr] = pub_key_obj
            except: pass

        # 2. Actualizar sesión existente si la hay
        session = self.sessions.get_session_by_pubkey(pub_bytes)
        if session:
            if session.current_addr != new_addr:
                self.on_log(f"🔄 Session addr update: {session.current_addr} -> {new_addr}")
                self.sessions.update_session_addr(session, new_addr)
                # Si la sesión tenía encryptor, lo invalidamos porque la IP cambió
                # (necesitamos nuevo handshake con la nueva IP)
                if session.encryptor:
                    self.on_log(f"⚠️ Invalidating old session encryptor (IP changed)")
                    session.encryptor = None
                    session.decryptor = None

        # 3. Las colas ahora se gestionan por user_id, no por pub_bytes
        # El retry_worker consultará la IP actualizada desde el TUI
        # Por lo que no necesitamos lógica de colas aquí

    async def _retry_worker(self):
        """
        Worker de reintento de mensajes en cola:
        - Cada 5 segundos intenta enviar el primer mensaje de cada cola
        - Colas vinculadas a user_id (ID del DNIe)
        - IP destino consultada en tiempo real desde el TUI (ChatItem)
        - Solo avanza al siguiente mensaje cuando recibe ACK del anterior
        """
        while True:
            await asyncio.sleep(5.0)  # Intervalo fijo de 5 segundos
            now = time.time()
            
            # Iteramos sobre las colas (todas son por user_id)
            for user_id in list(self.message_queues.keys()):
                queue = self.message_queues[user_id]
                if not queue: 
                    continue
                
                head = queue[0]
                
                # OBTENER IP EN TIEMPO REAL DESDE EL TUI
                target_addr = None
                if self.get_peer_addr_callback:
                    target_addr = self.get_peer_addr_callback(user_id)
                
                if not target_addr:
                    # Peer no está online, esperamos silenciosamente
                    continue
                
                # Verificar si tenemos sesión válida con esta dirección
                session = self.sessions.get_session_by_addr(target_addr)
                
                if session and session.encryptor:
                    # Enviar el mensaje silenciosamente
                    try:
                        head['last_retry'] = now
                        head['attempts'] += 1
                        await self._transmit_raw(target_addr, head['content'], head['msg_id'], timestamp=head['timestamp'])
                    except Exception as e:
                        pass  # Reintentos silenciosos
                else:
                    # No hay sesión válida - iniciar handshake silenciosamente
                    last_hs = self.pending_handshakes.get(target_addr, 0)
                    if now - last_hs > 5.0:
                        try:
                            # Obtener clave pública del peer desde el storage
                            remote_pub = await self.sessions.db.get_pubkey_by_addr(target_addr[0], target_addr[1])
                            if remote_pub:
                                new_session = self.sessions.create_initiator_session(target_addr, remote_pub)
                                hs_msg = new_session.create_handshake_message()
                                self.transport.sendto(b'\x01' + hs_msg, target_addr)
                                self.pending_handshakes[target_addr] = now
                        except Exception as e:
                            pass  # Handshake silencioso

    def _resolve_addr_for_pubkey(self, pub_bytes):
        """
        Obtiene la dirección IP actual para una clave pública.
        SIEMPRE prioriza mDNS (latest_peer_locations) sobre la sesión.
        """
        # 1. ÚNICA FUENTE DE VERDAD: Discovery (mDNS)
        addr = self.latest_peer_locations.get(pub_bytes)
        if addr:
            self.on_log(f"📍 Resolved addr from mDNS: {addr}")
            return addr
        
        # 2. Fallback: Dirección de la sesión activa (pero con advertencia)
        session = self.sessions.get_session_by_pubkey(pub_bytes)
        if session and session.current_addr:
            self.on_log(f"⚠️ Using stale session addr (no mDNS): {session.current_addr}")
            return session.current_addr
        
        self.on_log(f"❓ No address found for peer")
        return None

    async def _send_next_in_queue(self, user_id):
        """
        Envía inmediatamente el siguiente mensaje en la cola tras recibir ACK.
        """
        if user_id not in self.message_queues:
            return
        
        queue = self.message_queues[user_id]
        if not queue:
            return
        
        head = queue[0]
        
        # Obtener IP actual desde el TUI
        target_addr = None
        if self.get_peer_addr_callback:
            target_addr = self.get_peer_addr_callback(user_id)
        
        if not target_addr:
            return  # Silencioso
        
        session = self.sessions.get_session_by_addr(target_addr)
        if session and session.encryptor:
            try:
                head['last_retry'] = time.time()
                head['attempts'] += 1
                await self._transmit_raw(target_addr, head['content'], head['msg_id'], timestamp=head['timestamp'])
            except Exception as e:
                pass  # Silencioso

    async def _attempt_send_head(self, addr, item):
        item['last_retry'] = time.time()
        item['attempts'] += 1
        # Pasamos forced_msg_id=None porque ya lo tenemos en el item, 
        # pero _transmit_raw lo usa solo para logging o disconnects.
        # Aquí llamamos a _transmit_raw pasando el ID para que lo incruste correctamente.
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
            # Actualizar ubicación conocida
            self.latest_peer_locations[pub_bytes] = addr

            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Response sent to {addr}")
            
            asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], remote_pub, real_name=real_name))
            if self.on_handshake_success:
                self.on_handshake_success(addr, remote_pub, real_name)
            
            # ENVÍO INMEDIATO: Forzar envío de mensajes pendientes ahora que el handshake está completo
            # Usamos el callback para obtener el user_id desde la dirección
            user_id = None
            if self.get_user_id_callback:
                user_id = self.get_user_id_callback(addr)
            if user_id and user_id in self.message_queues and self.message_queues[user_id]:
                self.on_log(f"🚀 Handshake complete (responder), flushing {len(self.message_queues[user_id])} pending messages...")
                asyncio.create_task(self._flush_pending_queue(user_id, session))
                
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
            # Actualizar ubicación conocida
            self.latest_peer_locations[pub_bytes] = addr

            if self.on_handshake_success:
                self.on_handshake_success(addr, session.rs_pub, real_name)

            # ENVÍO INMEDIATO: Forzar envío de mensajes pendientes ahora que el handshake está completo
            # Usamos el callback para obtener el user_id desde la dirección
            user_id = None
            if self.get_user_id_callback:
                user_id = self.get_user_id_callback(addr)
            if user_id and user_id in self.message_queues and self.message_queues[user_id]:
                self.on_log(f"🚀 Handshake complete, flushing {len(self.message_queues[user_id])} pending messages...")
                asyncio.create_task(self._flush_pending_queue(user_id, session))

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
             # Actualizar también latest_peer_locations si sabemos la identidad
             if session.rs_pub:
                 pub_bytes = session.rs_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                 self.latest_peer_locations[pub_bytes] = addr
        
        try:
            plaintext = session.decrypt_message(encrypted_payload)
            msg_struct = json.loads(plaintext.decode('utf-8'))

            # --- MANEJO DE ACK ---
            if 'ack_id' in msg_struct:
                ack_id = msg_struct['ack_id']
                
                # Obtener user_id del remitente del ACK desde el TUI
                user_id = None
                if self.get_user_id_callback:
                    user_id = self.get_user_id_callback(addr)
                
                # Buscar en la cola del usuario
                if user_id and user_id in self.message_queues:
                    queue = self.message_queues[user_id]
                    if queue and queue[0]['msg_id'] == ack_id:
                        queue.popleft()  # Mensaje confirmado, lo eliminamos
                        
                        # Si hay más mensajes, enviar el siguiente inmediatamente
                        if queue:
                            asyncio.create_task(self._send_next_in_queue(user_id))

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

    async def _flush_pending_queue(self, user_id, session):
        """
        Envía inmediatamente todos los mensajes pendientes para un usuario.
        Se llama después de completar un handshake para garantizar entrega sin esperar al retry_worker.
        """
        if user_id not in self.message_queues:
            return
        
        queue = self.message_queues[user_id]
        if not queue:
            return
        
        # Verificar que la sesión está lista para enviar
        if not session or not session.encryptor:
            self.on_log(f"⚠️ Flush aborted: Session not ready")
            return
        
        target_addr = session.current_addr
        if not target_addr:
            self.on_log(f"⚠️ Flush aborted: No target address")
            return
        
        # Enviar el primer mensaje de la cola inmediatamente
        # (el resto se enviará mediante el mecanismo de ACK/retry normal)
        head = queue[0]
        try:
            head['last_retry'] = time.time()
            head['attempts'] += 1
            await self._transmit_raw(target_addr, head['content'], head['msg_id'], timestamp=head['timestamp'])
            self.on_log(f"📤 Flushed pending message to {target_addr}")
        except Exception as e:
            self.on_log(f"❌ Flush failed: {e}")

    async def broadcast_disconnect(self):
        self.on_log("📡 Sending encrypted disconnect...")
        active_sessions = list(self.sessions.sessions_by_addr.values())
        tasks = []
        for sess in active_sessions:
            tasks.append(self._transmit_raw(sess.current_addr, None, str(uuid.uuid4()), is_disconnect=True))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_message(self, addr, content, is_disconnect=False, forced_msg_id=None, user_id=None):
        msg_id = forced_msg_id if forced_msg_id else str(uuid.uuid4())
        
        if is_disconnect:
            await self._transmit_raw(addr, content, msg_id, is_disconnect=True)
            return msg_id

        # NUEVO: user_id es REQUERIDO para encolar mensajes
        if not user_id:
            self.on_log(f"❌ Cannot queue message: No user_id provided")
            return None
        
        # Crear cola si no existe (vinculada al user_id del DNIe)
        if user_id not in self.message_queues:
            self.message_queues[user_id] = deque()
            
        queue = self.message_queues[user_id]
        
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
                self.on_log(f"📡 mDNS: Notifying protocol of peer at {ip}:{port}")
                # Notificamos al protocolo para que actualice rutas o despierte colas
                self.protocol_ref.update_peer_location((ip, port), pub_bytes)
            except Exception as e:
                self.on_log(f"❌ mDNS update failed: {e}")

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

                    if registered_ip_bytes != current_ip_bytes and current_ip != '127.0.0.1':
                         self.on_log(f"🔄 Network IP changed: {current_ip}. Restarting mDNS Service...")
                         
                         # --- LIMPIAR UBICACIONES CONOCIDAS DE LA RED ANTERIOR ---
                         if self.protocol_ref:
                             old_count = len(self.protocol_ref.latest_peer_locations)
                             self.protocol_ref.latest_peer_locations.clear()
                             self.on_log(f"🗑️ Cleared {old_count} stale peer locations from previous network")
                         
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
                         
                         # Enviar query inmediatamente para descubrir peers en la nueva red
                         if self.sniffer_transport:
                             try: 
                                 self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                                 self.on_log("📡 Sent mDNS query to discover peers on new network")
                             except: pass
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