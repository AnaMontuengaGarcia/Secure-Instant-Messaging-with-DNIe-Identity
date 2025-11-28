import asyncio
import socket
import struct
import json
import time
import os
import uuid
import hashlib
import netifaces
import re
from collections import deque
from datetime import datetime, timezone

from zeroconf import ServiceInfo, IPVersion, InterfaceChoice
from zeroconf.asyncio import AsyncZeroconf
from protocol import NoiseIKState
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519

# --- CONFIGURACIÓN Y CONSTANTES ---

# Regex para casos complejos donde el slicing directo no es seguro (nombres variables)
RE_USER_PORT = re.compile(rb'User-([^_\x00]+)_(\d+)')
RE_USER_PROP = re.compile(rb'user=([^\x00]+)')
RE_STAT_EXIT = re.compile(rb'stat=exit')

# Constantes del protocolo mDNS
MDNS_TYPE = "_dni-im._udp.local."
RAW_MDNS_QUERY = (
    b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x07_dni-im\x04_udp\x05local\x00'
    b'\x00\x0c'
    b'\x00\x01'
)
TRUSTED_CERTS_DIR = "certs"

# --- UTILIDADES DE CERTIFICADOS ---

def load_trusted_cas():
    """
    Carga los certificados de Autoridad de Certificación (CA) de confianza desde el disco.
    
    Cómo lo hace:
    1. Escanea el directorio 'certs/'.
    2. Intenta cargar cada archivo como certificado X.509 (PEM o DER).
    3. Retorna una lista de objetos Certificate de la librería cryptography.
    """
    trusted_cas = []
    if not os.path.exists(TRUSTED_CERTS_DIR):
        return []
    
    for filename in os.listdir(TRUSTED_CERTS_DIR):
        if filename.endswith((".pem", ".crt", ".cer")):
            try:
                with open(os.path.join(TRUSTED_CERTS_DIR, filename), "rb") as f:
                    cert_data = f.read()
                    try:
                        cert = x509.load_pem_x509_certificate(cert_data)
                    except:
                        cert = x509.load_der_x509_certificate(cert_data)
                    trusted_cas.append(cert)
            except Exception as e:
                print(f"⚠️ Fallo al cargar CA {filename}: {e}")
    return trusted_cas

GLOBAL_TRUST_STORE = load_trusted_cas()

def get_common_name(cert):
    """
    Extrae el nombre común (CN) de un certificado X.509.
    
    Cómo lo hace:
    Itera sobre los atributos del Subject buscando el OID correspondiente al Common Name.
    """
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return "Unknown Common Name"

def verify_peer_identity(x25519_pub_key, proofs):
    """
    Verifica criptográficamente la identidad de un par remoto usando su certificado DNIe.
    
    Cómo lo hace:
    1. Valida las fechas de vigencia del certificado.
    2. Comprueba los permisos de uso de clave (Key Usage).
    3. Verifica la cadena de confianza contra el almacén local (GLOBAL_TRUST_STORE).
    4. Verifica que la firma digital sobre la clave efímera (x25519) sea válida.
    """
    if not proofs or 'cert' not in proofs or 'sig' not in proofs:
        raise Exception("No se proporcionaron pruebas de identidad")

    try:
        cert_bytes = bytes.fromhex(proofs['cert'])
        signature_bytes = bytes.fromhex(proofs['sig'])
        peer_cert = x509.load_der_x509_certificate(cert_bytes)
        rsa_pub_key = peer_cert.public_key()

        now = datetime.now(timezone.utc)
        if now < peer_cert.not_valid_before_utc:
            raise Exception("El certificado AÚN NO es válido")
        if now > peer_cert.not_valid_after_utc:
            raise Exception("El certificado ha CADUCADO")

        try:
            key_usage_ext = peer_cert.extensions.get_extension_for_class(x509.KeyUsage)
            usage = key_usage_ext.value
            if not (usage.digital_signature or usage.content_commitment):
                raise Exception("Certificado no permitido para Firma Digital/Autenticación")
        except x509.ExtensionNotFound:
            pass

        issuer_name = "CA Desconocida (Sin Verificación)"
        is_trusted = False
        
        if not GLOBAL_TRUST_STORE:
             issuer_name = "NO-CONFIABLE/SIN-ALMACEN"
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
                    print(f"🔐 [SEGURIDAD] Certificado DNIe verificado correctamente por: {issuer_name}")
                    break 
                except Exception:
                    continue

            if not is_trusted:
                raise Exception("El emisor del certificado NO ES DE CONFIANZA")

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
        raise Exception(f"Verificación de Identidad Fallida: {e}")

# --- GESTIÓN DE SESIONES ---

class SessionManager:
    """
    Gestor central de sesiones criptográficas Noise IK.
    Usa la identidad DNIe (real_name) como clave principal para las sesiones.
    """
    def __init__(self, local_static_key, db, local_proofs):
        self.local_static_key = local_static_key
        self.local_proofs = local_proofs
        # Diccionario principal: real_name (DNIe) -> session
        self.sessions = {}
        # Índice secundario necesario para recibir paquetes (el protocolo usa local_index)
        self.sessions_by_id = {}
        self.db = db
        self.transport = None

    def get_session(self, identity):
        """Busca una sesión por identidad DNIe (real_name)."""
        return self.sessions.get(identity)
    
    def get_session_by_id(self, idx):
        """Busca una sesión por su ID de multiplexación local (necesario para recibir paquetes)."""
        return self.sessions_by_id.get(idx)

    def register_session(self, session, identity=None):
        """
        Registra una sesión nueva.
        Si ya existe una sesión para esta identidad, la reemplaza.
        """
        # Limpiar sesión anterior si existe para esta identidad
        if identity and identity in self.sessions:
            old_session = self.sessions[identity]
            if old_session.local_index in self.sessions_by_id:
                del self.sessions_by_id[old_session.local_index]
        
        # Registrar en índice por ID (siempre)
        self.sessions_by_id[session.local_index] = session
        
        # Registrar por identidad si la conocemos
        if identity:
            self.sessions[identity] = session
            session.peer_identity = identity

    def update_session_identity(self, session, identity):
        """
        Actualiza/establece la identidad de una sesión tras verificar el DNIe.
        Si ya existe otra sesión para esta identidad, la reemplaza.
        """
        # Si ya hay una sesión para esta identidad y no es la misma, limpiarla
        if identity in self.sessions:
            old_session = self.sessions[identity]
            if old_session is not session:
                if old_session.local_index in self.sessions_by_id:
                    del self.sessions_by_id[old_session.local_index]
        
        self.sessions[identity] = session
        session.peer_identity = identity

    def remove_session(self, session):
        """Elimina una sesión de todos los índices."""
        if session.local_index in self.sessions_by_id:
            del self.sessions_by_id[session.local_index]
        
        identity = getattr(session, 'peer_identity', None)
        if identity and identity in self.sessions:
            if self.sessions[identity] is session:
                del self.sessions[identity]

    def create_initiator_session(self, remote_pub_key, identity=None):
        """
        Crea una nueva sesión en modo INICIADOR (Cliente).
        Prepara el estado Noise IK para comenzar el handshake.
        """
        session = NoiseIKState(
            self.local_static_key, 
            remote_pub_key, 
            initiator=True,
            local_proofs=self.local_proofs
        )
        session.initialize()
        session.peer_identity = identity
        self.register_session(session, identity)
        return session

    def create_responder_session(self):
        """
        Crea una nueva sesión en modo RESPONDEDOR (Servidor).
        Espera recibir el primer mensaje del handshake.
        """
        session = NoiseIKState(
            self.local_static_key, 
            initiator=False,
            local_proofs=self.local_proofs
        )
        session.initialize()
        session.peer_identity = None
        # Solo registramos en sessions_by_id, la identidad se añade tras verificar DNIe
        self.sessions_by_id[session.local_index] = session
        return session

# --- PROTOCOLO UDP ---

class UDPProtocol(asyncio.DatagramProtocol):
    """
    Implementación del protocolo de red UDP asíncrono.
    Usa la identidad DNIe (user_id/real_name) como clave para gestionar sesiones.
    """
    def __init__(self, session_manager, on_message_received, on_log, on_handshake_success=None, on_ack_received=None):
        self.sessions = session_manager
        self.on_message = on_message_received
        self.on_log = on_log
        self.on_handshake_success = on_handshake_success
        self.on_ack_received = on_ack_received
        self.transport = None
        
        # Colas de mensajes por identidad (user_id)
        self.message_queues = {}
        # Mapeo: user_id -> (ip, port) actual
        self.peer_addresses = {}
        # Mapeo: (ip, port) -> user_id (inverso, para recibir mensajes)
        self.addr_to_identity = {}
        # Handshakes pendientes por user_id
        self.pending_handshakes = {}
        self.dedup_buffer = deque(maxlen=200)
        
        # Callbacks para integración con UI
        self.get_peer_addr_callback = None
        self.get_user_id_callback = None
        self.is_peer_online_callback = None  # Para verificar si el peer está online antes de retry
        self.discovery_service = None 
        
        self._retry_task_handle = None

    def connection_made(self, transport):
        """Evento de inicio del protocolo."""
        self.transport = transport
        self.sessions.transport = transport
        try:
            sock = transport.get_extra_info('socket')
            addr = sock.getsockname()
            self.on_log(f"✅ UDP Vinculado a {addr[0]}:{addr[1]}")
        except: pass
        self._retry_task_handle = asyncio.create_task(self._retry_worker())

    def update_peer_location(self, user_id, new_addr, pub_key_obj=None):
        """
        Actualiza la ubicación (IP:puerto) de un peer identificado por su user_id.
        Se llama cuando recibimos anuncios mDNS o cuando un peer envía un mensaje.
        """
        old_addr = self.peer_addresses.get(user_id)
        
        if old_addr == new_addr:
            return  # Sin cambios
        
        self.on_log(f"📡 Ubicación de {user_id}: {old_addr} -> {new_addr}")
        
        # Limpiar mapeo inverso antiguo
        if old_addr and old_addr in self.addr_to_identity:
            del self.addr_to_identity[old_addr]
        
        # Actualizar mapeos
        self.peer_addresses[user_id] = new_addr
        self.addr_to_identity[new_addr] = user_id
        
        # Guardar clave pública efímera para handshakes
        if pub_key_obj:
            self.sessions.db.ephemeral_keys[new_addr] = pub_key_obj
        
        # Si hay sesión existente para este usuario, actualizar su dirección
        session = self.sessions.get_session(user_id)
        if session:
            session.current_addr = new_addr
            # Si cambió la dirección y teníamos handshake pendiente en la vieja, limpiarlo
            if old_addr:
                self.pending_handshakes.pop(user_id, None)
            # Invalidar cifrado - necesitamos nuevo handshake porque la clave efímera cambió
            if pub_key_obj and session.rs_pub:
                old_pub = session.rs_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                new_pub = pub_key_obj.public_bytes_raw() if hasattr(pub_key_obj, 'public_bytes_raw') else pub_key_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                if old_pub != new_pub:
                    self.on_log(f"🔄 {user_id} reconectó con nueva clave, invalidando sesión")
                    session.encryptor = None
                    session.decryptor = None

    def get_identity_from_addr(self, addr):
        """Obtiene el user_id asociado a una dirección."""
        return self.addr_to_identity.get(addr)

    def get_addr_for_identity(self, user_id):
        """Obtiene la dirección actual de un usuario."""
        return self.peer_addresses.get(user_id)

    async def _retry_worker(self):
        """
        Tarea en bucle infinito que revisa las colas de mensajes.
        Reintenta el envío de mensajes que no han recibido ACK después de un timeout.
        """
        while True:
            await asyncio.sleep(5.0)
            now = time.time()
            for user_id in list(self.message_queues.keys()):
                queue = self.message_queues[user_id]
                if not queue: continue
                head = queue[0]
                
                # Obtener dirección actual del peer
                target_addr = self.peer_addresses.get(user_id)
                if not target_addr:
                    continue
                
                # Buscar sesión por identidad
                session = self.sessions.get_session(user_id)
                
                # Si hay sesión establecida con encryptor válido
                if session and session.encryptor:
                    try:
                        head['last_retry'] = now
                        head['attempts'] += 1
                        await self._transmit_raw(user_id, head['content'], head['msg_id'], timestamp=head['timestamp'])
                    except Exception as e:
                        self.on_log(f"❌ Retry fallido: {e}")
                # Si no hay sesión o el encryptor es inválido, iniciar handshake
                else:
                    # Verificar si el peer está online antes de reintentar
                    if self.is_peer_online_callback and not self.is_peer_online_callback(user_id):
                        # Peer no está online, no reintentar handshake
                        continue
                    
                    last_hs = self.pending_handshakes.get(user_id, 0)
                    if now - last_hs > 5.0:
                        try:
                            remote_pub = await self.sessions.db.get_pubkey_by_addr(target_addr[0], target_addr[1])
                            if remote_pub:
                                self.on_log(f"🔄 Retry: Iniciando handshake con {user_id} @ {target_addr}")
                                new_session = self.sessions.create_initiator_session(remote_pub, user_id)
                                new_session.current_addr = target_addr
                                hs_msg = new_session.create_handshake_message()
                                self.transport.sendto(b'\x01' + hs_msg, target_addr)
                                self.pending_handshakes[user_id] = now
                        except Exception as e:
                            self.on_log(f"❌ Error en retry handshake: {e}")

    async def _send_next_in_queue(self, user_id):
        """Envía el siguiente mensaje en la cola tras recibir un ACK."""
        if user_id not in self.message_queues: return
        queue = self.message_queues[user_id]
        if not queue: return
        head = queue[0]
        
        session = self.sessions.get_session(user_id)
        if session and session.encryptor:
            try:
                head['last_retry'] = time.time()
                head['attempts'] += 1
                await self._transmit_raw(user_id, head['content'], head['msg_id'], timestamp=head['timestamp'])
            except Exception: pass

    async def _attempt_send_head(self, user_id, item):
        """Intenta enviar el primer mensaje de una cola nueva."""
        item['last_retry'] = time.time()
        item['attempts'] += 1
        await self._transmit_raw(user_id, item['content'], item['msg_id'], timestamp=item['timestamp'])

    def datagram_received(self, data, addr):
        """Punto de entrada de paquetes UDP."""
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
            self.on_log(f"❌ Paquete erróneo {addr}: {e}")

    def handle_handshake_init(self, data, addr):
        """
        Maneja la recepción de un Handshake inicial (Lado Respondedor).
        Crea sesión, verifica identidad y envía respuesta.
        """
        self.on_log(f"🔄 Handshake Init desde {addr}")
        session = self.sessions.create_responder_session()
        session.current_addr = addr
        try:
            remote_pub = session.consume_handshake_message(data)
            try:
                real_name, issuer = verify_peer_identity(remote_pub, session.remote_proofs)
                self.on_log(f"✅ Identidad Verificada: {real_name} | Emisor: {issuer}")
            except Exception as e:
                self.on_log(f"⛔ ALERTA DE SEGURIDAD: {e}")
                self.sessions.remove_session(session)
                return

            # Usar el user_id que ya conocíamos por mDNS, o el real_name si es nuevo
            user_id = self.addr_to_identity.get(addr, real_name)
            self.sessions.update_session_identity(session, user_id)
            
            # Actualizar mapeos de direcciones
            self.peer_addresses[user_id] = addr
            self.addr_to_identity[addr] = user_id
            
            # Limpiar handshake pendiente si existía
            self.pending_handshakes.pop(user_id, None)

            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Respuesta enviado a {addr}")
            
            asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], remote_pub, real_name=real_name))
            if self.on_handshake_success:
                self.on_handshake_success(addr, remote_pub, real_name)
            
            # Enviar mensajes pendientes si los hay
            if user_id in self.message_queues and self.message_queues[user_id]:
                self.on_log(f"🚀 Handshake completado, enviando mensajes pendientes a {user_id}...")
                asyncio.create_task(self._flush_pending_queue(user_id, session))
                
        except Exception as e:
            self.on_log(f"❌ Handshake fallido: {e}")
            self.sessions.remove_session(session)

    def handle_handshake_resp(self, data, addr):
        """
        Maneja la recepción de una respuesta de Handshake (Lado Iniciador).
        Finaliza el establecimiento de claves y verifica identidad.
        """
        if len(data) < 8: return
        receiver_index = struct.unpack('<I', data[4:8])[0]
        session = self.sessions.get_session_by_id(receiver_index)
        if not session: return

        try:
            session.current_addr = addr
            session.consume_handshake_response(data)
            
            try:
                real_name, issuer = verify_peer_identity(session.rs_pub, session.remote_proofs)
                self.on_log(f"✅ Identidad Verificada: {real_name} (Completado) | Emisor: {issuer}")
                asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], session.rs_pub, real_name=real_name))
            except Exception as e:
                self.on_log(f"⛔ ALERTA DE SEGURIDAD: {e}")
                self.sessions.remove_session(session)
                return

            # Usar el user_id con el que se creó la sesión, o el de addr_to_identity
            user_id = getattr(session, 'peer_identity', None) or self.addr_to_identity.get(addr, real_name)
            self.sessions.update_session_identity(session, user_id)
            
            # Actualizar mapeos de direcciones
            self.peer_addresses[user_id] = addr
            self.addr_to_identity[addr] = user_id
            
            # Limpiar handshake pendiente
            self.pending_handshakes.pop(user_id, None)

            if self.on_handshake_success:
                self.on_handshake_success(addr, session.rs_pub, real_name)

            # Enviar mensajes pendientes
            if user_id in self.message_queues and self.message_queues[user_id]:
                self.on_log(f"🚀 Handshake completado, liberando cola para {user_id}...")
                asyncio.create_task(self._flush_pending_queue(user_id, session))

        except Exception as e:
            self.on_log(f"❌ Completado de Handshake fallido: {e}")

    def handle_data(self, data, addr):
        """Maneja paquetes de datos cifrados (Mensajes de chat)."""
        if len(data) < 4: return
        receiver_index = struct.unpack('<I', data[:4])[0]
        encrypted_payload = data[4:]
        session = self.sessions.get_session_by_id(receiver_index)
        if not session: return
        
        # Obtener identidad del peer
        user_id = getattr(session, 'peer_identity', None)
        
        # Actualizar dirección si cambió (roaming)
        if session.current_addr != addr:
            self.on_log(f"🚀 Roaming detectado: {user_id} movido de {session.current_addr} a {addr}")
            old_addr = session.current_addr
            session.current_addr = addr
            
            # Actualizar mapeos
            if user_id:
                self.peer_addresses[user_id] = addr
                if old_addr in self.addr_to_identity:
                    del self.addr_to_identity[old_addr]
                self.addr_to_identity[addr] = user_id
        
        try:
            plaintext = session.decrypt_message(encrypted_payload)
            msg_struct = json.loads(plaintext.decode('utf-8'))

            if 'ack_id' in msg_struct:
                ack_id = msg_struct['ack_id']
                if user_id and user_id in self.message_queues:
                    queue = self.message_queues[user_id]
                    if queue and queue[0]['msg_id'] == ack_id:
                        queue.popleft() 
                        if queue:
                            asyncio.create_task(self._send_next_in_queue(user_id))
                if self.on_ack_received:
                    self.on_ack_received(addr, ack_id)
                return 

            if 'text' in msg_struct and 'hash' in msg_struct:
                content = msg_struct['text']
                received_hash = msg_struct['hash']
                local_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                msg_struct['integrity'] = (local_hash == received_hash)
            
            if 'id' in msg_struct and not msg_struct.get('disconnect'):
                incoming_id = msg_struct['id']
                asyncio.create_task(self.send_ack(session, incoming_id))
                
                if incoming_id in self.dedup_buffer:
                    return
                self.dedup_buffer.append(incoming_id)

            self.on_message(addr, msg_struct)
        except Exception as e:
            self.on_log(f"❌ Descifrado fallido: {e}")

    async def send_ack(self, session, msg_id):
        """Envía ACK de mensaje recibido."""
        if not session or not session.encryptor: return
        try:
            ack_payload = {"timestamp": time.time(), "ack_id": msg_id}
            json_bytes = json.dumps(ack_payload).encode('utf-8')
            full_packet_payload = session.encrypt_message(json_bytes)
            self.transport.sendto(b'\x03' + full_packet_payload, session.current_addr)
        except Exception as e:
            self.on_log(f"❌ Fallo al enviar ACK: {e}")

    async def _flush_pending_queue(self, user_id, session):
        """Vuelca la cola de mensajes tras reconexión."""
        if user_id not in self.message_queues: return
        queue = self.message_queues[user_id]
        if not queue: return
        if not session or not session.encryptor: return
        head = queue[0]
        try:
            head['last_retry'] = time.time()
            head['attempts'] += 1
            await self._transmit_raw(user_id, head['content'], head['msg_id'], timestamp=head['timestamp'])
            self.on_log(f"📤 Mensaje pendiente volcado a {user_id}")
        except Exception as e:
            self.on_log(f"❌ Volcado fallido: {e}")

    async def broadcast_disconnect(self):
        """Anuncia desconexión cifrada a todas las sesiones activas."""
        self.on_log("📡 Enviando desconexión cifrada...")
        tasks = []
        for user_id, session in list(self.sessions.sessions.items()):
            if session.encryptor and session.current_addr:
                tasks.append(self._send_disconnect_to_session(session))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_disconnect_to_session(self, session):
        """Envía mensaje de desconexión a una sesión específica."""
        try:
            msg_struct = {"timestamp": time.time(), "disconnect": True}
            payload = json.dumps(msg_struct).encode('utf-8')
            full_packet_payload = session.encrypt_message(payload)
            self.transport.sendto(b'\x03' + full_packet_payload, session.current_addr)
        except Exception:
            pass

    async def send_message(self, user_id, content, is_disconnect=False, forced_msg_id=None):
        """Encola un mensaje para envío a un usuario identificado por su DNIe."""
        msg_id = forced_msg_id if forced_msg_id else str(uuid.uuid4())
        
        if is_disconnect:
            session = self.sessions.get_session(user_id)
            if session and session.encryptor:
                await self._send_disconnect_to_session(session)
            return msg_id
        
        if not user_id:
            self.on_log(f"❌ No se puede encolar: falta user_id")
            return None
            
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
        if len(queue) == 1:
            await self._attempt_send_head(user_id, queue[0])
        return msg_id

    async def _transmit_raw(self, user_id, content, msg_id, is_disconnect=False, timestamp=None):
        """Transmite un paquete por la red a un usuario identificado."""
        # Obtener dirección actual del peer
        target_addr = self.peer_addresses.get(user_id)
        if not target_addr:
            self.on_log(f"❌ No se conoce la dirección de {user_id}")
            return
        
        # Buscar sesión por identidad
        session = self.sessions.get_session(user_id)
        is_handshake_pending = user_id in self.pending_handshakes and (time.time() - self.pending_handshakes[user_id] < 5.0)

        # Si hay sesión pero sin encryptor válido
        if session and session.encryptor is None:
            if is_handshake_pending:
                return  # Esperar a que termine el handshake
            # Sesión obsoleta, no la borramos solo marcamos para nuevo handshake
            session = None

        # Si no hay sesión válida, iniciar handshake
        if not session or not session.encryptor:
            if is_handshake_pending:
                return
            remote_pub = await self.sessions.db.get_pubkey_by_addr(target_addr[0], target_addr[1])
            if not remote_pub:
                self.on_log(f"❌ No se puede enviar a {user_id}: Faltan claves públicas")
                return 
            
            self.on_log(f"🔄 Iniciando handshake con {user_id} @ {target_addr}")
            new_session = self.sessions.create_initiator_session(remote_pub, user_id)
            new_session.current_addr = target_addr
            hs_msg = new_session.create_handshake_message()
            self.transport.sendto(b'\x01' + hs_msg, target_addr)
            self.pending_handshakes[user_id] = time.time()
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
            self.transport.sendto(b'\x03' + full_packet_payload, session.current_addr)
        except Exception as e:
            self.on_log(f"❌ Fallo envío a {user_id}: {e}")

# --- DESCUBRIMIENTO DE RED (mDNS) ---

class RawSniffer(asyncio.DatagramProtocol):
    """
    Protocolo de escucha de bajo nivel OPTIMIZADO.
    Evita regex en paquetes irrelevantes y usa extracción directa de bytes cuando es posible.
    """
    def __init__(self, service):
        self.service = service
        self.transport = None
        self.sock = None

    def connection_made(self, transport):
        """Configura el socket multicast."""
        self.transport = transport
        self.sock = transport.get_extra_info('socket')
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except: pass
        self.join_multicast_groups()

    def join_multicast_groups(self):
        """Se une al grupo multicast en todas las interfaces."""
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
        """
        Analiza paquetes mDNS entrantes.
        OPTIMIZACIÓN: Usa 'fail-fast' y slicing de bytes en lugar de regex masivo.
        """
        # 1. OPTIMIZACIÓN: Fail-Fast (O(N) simple)
        if b"_dni-im" not in data: return
        
        user_id_found = None
        port_found = 0
        props = {}
        
        # 2. OPTIMIZACIÓN: Extracción directa de Clave Pública
        # 'pub=' es fijo, seguido de 64 bytes hex. Usamos .find() + Slicing (O(N))
        pub_idx = data.find(b'pub=')
        if pub_idx != -1:
            # Verificar longitud segura antes de cortar
            if pub_idx + 4 + 64 <= len(data):
                try:
                    # Extraer exactamente 64 bytes
                    props['pub'] = data[pub_idx+4 : pub_idx+4+64].decode('utf-8')
                except: pass
        
        # 3. Extracción de User ID
        # Intentamos primero con regex simple para User-ID_Port que es formato variable
        match_name = RE_USER_PORT.search(data)
        if match_name:
            try:
                user_id_found = match_name.group(1).decode('utf-8', errors='ignore')
                port_found = int(match_name.group(2).decode('utf-8'))
            except: pass
        
        # Override si existe propiedad explícita 'user='
        match_user = RE_USER_PROP.search(data)
        if match_user:
            try:
                props['user'] = match_user.group(1).decode('utf-8')
                if not user_id_found:
                    user_id_found = props['user']
            except: pass
            
        # 4. Estado de salida
        if RE_STAT_EXIT.search(data):
            props['stat'] = 'exit'

        if user_id_found:
            # Filtrar loopback (tanto el propio como IPs localhost)
            if user_id_found == self.service.unique_instance_id and port_found == self.service.port:
                return
            # Ignorar paquetes que vienen desde localhost/loopback
            if addr[0] == '127.0.0.1' or addr[0].startswith('127.'):
                return
            self.service.on_found(user_id_found, addr[0], port_found, props)


class DiscoveryService:
    """
    Servicio de alto nivel para descubrimiento de pares.
    Orquesta el anuncio (Zeroconf) y la escucha (RawSniffer).
    """
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
        """Vincula el servicio de descubrimiento con el protocolo UDP."""
        self.protocol_ref = proto
        proto.discovery_service = self

    async def start(self, username, bind_ip=None):
        """Inicia los servicios de red (Anuncio y Escucha)."""
        self.loop = asyncio.get_running_loop()
        self.bind_ip = bind_ip
        clean_username = username.replace("User-", "")
        self.unique_instance_id = clean_username
        
        # Sniffer
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except: pass
            sock.bind(('', 5353))
            
            self.sniffer_transport, self.sniffer_protocol = await self.loop.create_datagram_endpoint(
                lambda: RawSniffer(self), sock=sock
            )
            self.on_log("👂 Sniffer Activo")
        except Exception as e:
            self.on_log(f"⚠️ Fallo al iniciar Sniffer: {e}")

        # Anuncios Zeroconf
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
        
        self.on_log(f"📢 Anunciando: {service_name} @ {local_ip}")
        await self.aiozc.async_register_service(self.info)
        
        self._polling_task = asyncio.create_task(self._active_polling_loop())

    def on_found(self, user_id, ip, port, props):
        """Callback al encontrar un par en la red."""
        if self.on_found_callback:
             self.on_found_callback(user_id, ip, port, props)
        
        # Manejar señal de desconexión (stat=exit)
        if props.get('stat') == 'exit' and self.protocol_ref:
            self.on_log(f"📴 Peer {user_id} anunció desconexión (stat=exit)")
            # Marcar la sesión como inválida si existe
            session = self.protocol_ref.sessions.get_session(user_id)
            if session:
                session.encryptor = None
                session.decryptor = None
            return
        
        # Actualizar ubicación del peer
        if self.protocol_ref:
            try:
                pub_key_obj = None
                if 'pub' in props:
                    pub_hex = props['pub']
                    pub_bytes = bytes.fromhex(pub_hex)
                    pub_key_obj = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                
                self.protocol_ref.update_peer_location(user_id, (ip, port), pub_key_obj)
            except Exception as e:
                self.on_log(f"❌ Fallo actualización mDNS: {e}")

    def broadcast_exit(self):
        """Emite señal de salida 'Goodbye'."""
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
            self.on_log("📡 Emitido paquete mDNS 'stat=exit'.")
        except Exception as e:
            pass

    async def stop(self):
        """Detiene servicios de red."""
        self.broadcast_exit()
        if hasattr(self, '_polling_task'): self._polling_task.cancel()
        if self.sniffer_transport: self.sniffer_transport.close()
        if hasattr(self, 'info') and hasattr(self, 'aiozc'): 
            await self.aiozc.async_unregister_service(self.info)
        if hasattr(self, 'aiozc'): await self.aiozc.async_close()

    def refresh(self):
        """Fuerza actualización de red."""
        if self.sniffer_transport:
             try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
             except: pass

    async def _active_polling_loop(self):
        """Monitoriza la IP local para cambios de red."""
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
                         self.on_log(f"🔄 IP de Red cambió: {current_ip}. Reiniciando Servicio mDNS...")
                         
                         if self.protocol_ref:
                             old_count = len(self.protocol_ref.peer_addresses)
                             self.protocol_ref.peer_addresses.clear()
                             self.protocol_ref.addr_to_identity.clear()
                             self.on_log(f"🗑️ Limpiadas {old_count} ubicaciones obsoletas de la red anterior")
                         
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
                             self.on_log("👂 Sniffer Reiniciado (Cambio IP)")
                         except Exception as e:
                             self.on_log(f"⚠️ Fallo reinicio Sniffer: {e}")
                         
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
                         self.on_log(f"✅ Servicio mDNS Reiniciado en {current_ip}")
                         
                         if self.sniffer_transport:
                             try: 
                                 self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                                 self.on_log("📡 Enviada consulta mDNS para descubrir pares en nueva red")
                             except: pass
                    else:
                        await self.aiozc.async_update_service(self.info)
                except Exception as e:
                    pass

            if self.sniffer_transport:
                 try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                 except: pass

    def get_local_ip(self):
        """Obtiene la IP local preferida."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 80)); IP = s.getsockname()[0]
        except: IP = '127.0.0.1'
        finally: s.close()
        return IP