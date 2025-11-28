"""
Módulo de Red y Comunicaciones (Networking)
-------------------------------------------
Gestiona toda la comunicación de bajo nivel, incluyendo:
1. Sockets UDP asíncronos.
2. Descubrimiento de pares mediante mDNS (Multicast DNS).
3. Verificación de certificados X.509 del DNIe.
4. Gestión de retransmisiones (Reliability layer sobre UDP).
"""

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

# Expresiones regulares para parsing manual de paquetes mDNS.
# Se usa regex en lugar de librerías completas para extraer datos de paquetes malformados o crudos.
RE_USER_PORT = re.compile(rb'User-([^_\x00]+)_(\d+)')
RE_USER_PROP = re.compile(rb'user=([^\x00]+)')
RE_STAT_EXIT = re.compile(rb'stat=exit')

# Identificador del servicio mDNS
MDNS_TYPE = "_dni-im._udp.local."

# Paquete de consulta mDNS pre-construido (para hacer polling activo)
RAW_MDNS_QUERY = (
    b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' # Header
    b'\x07_dni-im\x04_udp\x05local\x00'                # QNAME: _dni-im._udp.local
    b'\x00\x0c'                                        # QTYPE: PTR (12)
    b'\x00\x01'                                        # QCLASS: IN (1)
)
TRUSTED_CERTS_DIR = "certs"

# --- UTILIDADES DE CERTIFICADOS ---

def load_trusted_cas():
    """
    Carga los certificados de Autoridad de Certificación (CA) de confianza desde el disco.
    
    Esta función es vital para establecer la Cadena de Confianza. Sin estos certificados,
    no podemos verificar que el DNIe del otro usuario sea legítimo.
    
    Returns:
        list: Lista de objetos Certificate (x509) cargados.
    """
    trusted_cas = []
    if not os.path.exists(TRUSTED_CERTS_DIR):
        return []
    
    for filename in os.listdir(TRUSTED_CERTS_DIR):
        if filename.endswith((".pem", ".crt", ".cer")):
            try:
                with open(os.path.join(TRUSTED_CERTS_DIR, filename), "rb") as f:
                    cert_data = f.read()
                    # Intentamos cargar formato PEM, si falla, probamos DER (binario)
                    try:
                        cert = x509.load_pem_x509_certificate(cert_data)
                    except:
                        cert = x509.load_der_x509_certificate(cert_data)
                    trusted_cas.append(cert)
            except Exception as e:
                print(f"⚠️ Fallo al cargar CA {filename}: {e}")
    return trusted_cas

# Cargamos el almacén de confianza al iniciar el módulo
GLOBAL_TRUST_STORE = load_trusted_cas()

def get_common_name(cert):
    """
    Extrae el Nombre Común (CN) de un certificado X.509.
    El CN suele contener el nombre completo del titular en el DNIe.
    """
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return "Unknown Common Name"

def verify_peer_identity(x25519_pub_key, proofs):
    """
    Verifica criptográficamente la identidad de un par remoto.
    
    Pasos de verificación:
    1. **Validez Temporal:** Verifica que el certificado no haya caducado.
    2. **Uso de Clave:** Verifica que el certificado sirva para Firma Digital o No Repudio.
    3. **Cadena de Confianza:** Verifica que el certificado haya sido firmado por una CA
       confiable (Cuerpo Nacional de Policía) presente en `GLOBAL_TRUST_STORE`.
    4. **Firma de Propiedad:** Verifica que la firma adjunta (`sig`) sobre la clave pública
       de sesión (`x25519_pub_key`) sea válida usando la clave pública RSA del certificado.
       Esto demuestra que el dueño del DNIe autorizó esta sesión.

    Args:
        x25519_pub_key: La clave pública efímera de la sesión Noise.
        proofs (dict): Diccionario con 'cert' (hex) y 'sig' (hex).

    Returns:
        tuple: (Nombre Real, Nombre del Emisor)
    
    Raises:
        Exception: Si alguna validación falla.
    """
    if not proofs or 'cert' not in proofs or 'sig' not in proofs:
        raise Exception("No se proporcionaron pruebas de identidad")

    try:
        cert_bytes = bytes.fromhex(proofs['cert'])
        signature_bytes = bytes.fromhex(proofs['sig'])
        peer_cert = x509.load_der_x509_certificate(cert_bytes)
        rsa_pub_key = peer_cert.public_key()

        # 1. Verificación Temporal
        now = datetime.now(timezone.utc)
        if now < peer_cert.not_valid_before_utc:
            raise Exception("El certificado AÚN NO es válido")
        if now > peer_cert.not_valid_after_utc:
            raise Exception("El certificado ha CADUCADO")

        # 2. Verificación de Uso de Clave (Key Usage)
        try:
            key_usage_ext = peer_cert.extensions.get_extension_for_class(x509.KeyUsage)
            usage = key_usage_ext.value
            if not (usage.digital_signature or usage.content_commitment):
                raise Exception("Certificado no permitido para Firma Digital/Autenticación")
        except x509.ExtensionNotFound:
            pass # Si no tiene la extensión, asumimos permisividad (aunque es raro en DNIe)

        # 3. Verificación de Cadena de Confianza (Chain of Trust)
        issuer_name = "CA Desconocida (Sin Verificación)"
        is_trusted = False
        
        if not GLOBAL_TRUST_STORE:
             issuer_name = "NO-CONFIABLE/SIN-ALMACEN"
             # Permitimos continuar sin validación CA solo si no hay CAs cargadas (Modo inseguro)
             is_trusted = True 
        else:
            for ca_cert in GLOBAL_TRUST_STORE:
                try:
                    ca_public_key = ca_cert.public_key()
                    # Verificamos la firma criptográfica del certificado del par con la clave de la CA
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
                    continue # Probamos con la siguiente CA

            if not is_trusted:
                raise Exception("El emisor del certificado NO ES DE CONFIANZA (No está en certs/)")

        # 4. Verificación de la Firma sobre la Clave Efímera
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
    
    Mantiene el estado de todas las conexiones activas.
    Utiliza dos índices:
    1. Por Identidad (DNIe): Para enviar mensajes a una persona específica.
    2. Por ID de Sesión (Index): Para enrutar paquetes entrantes a la sesión correcta.
    """
    def __init__(self, local_static_key, db, local_proofs):
        self.local_static_key = local_static_key
        self.local_proofs = local_proofs
        # Diccionario principal: real_name (DNIe) -> session object
        self.sessions = {}
        # Índice secundario: local_index (int) -> session object (para multiplexación UDP)
        self.sessions_by_id = {}
        self.db = db
        self.transport = None

    def get_session(self, identity):
        """Busca una sesión activa por identidad DNIe (real_name)."""
        return self.sessions.get(identity)
    
    def get_session_by_id(self, idx):
        """Busca una sesión por su ID numérico local (necesario para recibir paquetes)."""
        return self.sessions_by_id.get(idx)

    def register_session(self, session, identity=None):
        """
        Registra una nueva sesión en los índices.
        Si ya existe una sesión para esa identidad, la reemplaza (re-keying).
        """
        # Limpiar sesión anterior si existe
        if identity and identity in self.sessions:
            old_session = self.sessions[identity]
            if old_session.local_index in self.sessions_by_id:
                del self.sessions_by_id[old_session.local_index]
        
        self.sessions_by_id[session.local_index] = session
        
        if identity:
            self.sessions[identity] = session
            session.peer_identity = identity

    def update_session_identity(self, session, identity):
        """
        Asocia una sesión anónima con una identidad tras verificar el handshake.
        """
        # Limpieza defensiva
        if identity in self.sessions:
            old_session = self.sessions[identity]
            if old_session is not session:
                if old_session.local_index in self.sessions_by_id:
                    del self.sessions_by_id[old_session.local_index]
        
        self.sessions[identity] = session
        session.peer_identity = identity

    def remove_session(self, session):
        """Elimina una sesión de todos los registros y borra sus claves de forma segura."""
        # Borrado seguro de claves de la sesión
        if hasattr(session, 'zeroize_session'):
            session.zeroize_session()
        
        if session.local_index in self.sessions_by_id:
            del self.sessions_by_id[session.local_index]
        
        identity = getattr(session, 'peer_identity', None)
        if identity and identity in self.sessions:
            if self.sessions[identity] is session:
                del self.sessions[identity]

    def zeroize_all_sessions(self):
        """Borra de forma segura todas las sesiones activas. Llamar al cerrar la aplicación."""
        for session in list(self.sessions_by_id.values()):
            if hasattr(session, 'zeroize_session'):
                session.zeroize_session()
        self.sessions.clear()
        self.sessions_by_id.clear()

    def create_initiator_session(self, remote_pub_key, identity=None):
        """
        Crea una sesión en modo INICIADOR (Cliente).
        Prepara el estado Noise para enviar el primer mensaje.
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
        Crea una sesión en modo RESPONDEDOR (Servidor).
        Espera recibir un mensaje inicial.
        """
        session = NoiseIKState(
            self.local_static_key, 
            initiator=False,
            local_proofs=self.local_proofs
        )
        session.initialize()
        session.peer_identity = None
        # Solo registramos por ID, la identidad se desconoce hasta procesar el handshake
        self.sessions_by_id[session.local_index] = session
        return session

# --- PROTOCOLO UDP ---

class UDPProtocol(asyncio.DatagramProtocol):
    """
    Implementación del protocolo de red sobre UDP.
    
    Características:
    - Asíncrono (asyncio).
    - Multiplexación de sesiones.
    - Soporte para Roaming (cambio de IP del par).
    - Sistema de ACK y retransmisión (Reliability).
    """
    def __init__(self, session_manager, on_message_received, on_log, on_handshake_success=None, on_ack_received=None):
        self.sessions = session_manager
        self.on_message = on_message_received
        self.on_log = on_log
        self.on_handshake_success = on_handshake_success
        self.on_ack_received = on_ack_received
        self.transport = None
        
        # Colas de mensajes pendientes por usuario
        self.message_queues = {}
        # Mapeo de identidad -> (IP, Puerto)
        self.peer_addresses = {}
        # Mapeo inverso (IP, Puerto) -> identidad
        self.addr_to_identity = {}
        
        self.pending_handshakes = {}
        # Buffer circular para deduplicación de mensajes recibidos
        self.dedup_buffer = deque(maxlen=200)
        
        # Callbacks UI
        self.get_peer_addr_callback = None
        self.get_user_id_callback = None
        self.is_peer_online_callback = None
        self.discovery_service = None 
        
        self._retry_task_handle = None

    def connection_made(self, transport):
        """Callback llamado cuando el socket UDP está listo."""
        self.transport = transport
        self.sessions.transport = transport
        try:
            sock = transport.get_extra_info('socket')
            addr = sock.getsockname()
            self.on_log(f"✅ UDP Vinculado a {addr[0]}:{addr[1]}")
        except: pass
        # Iniciar tarea de retransmisión en segundo plano
        self._retry_task_handle = asyncio.create_task(self._retry_worker())

    def update_peer_location(self, user_id, new_addr, pub_key_obj=None):
        """
        Actualiza la tabla de rutas cuando un usuario cambia de IP/Puerto (Roaming).
        """
        old_addr = self.peer_addresses.get(user_id)
        
        if old_addr == new_addr:
            return  # No hay cambio
        
        self.on_log(f"📡 Ubicación de {user_id}: {old_addr} -> {new_addr}")
        
        # Actualización de mapas
        if old_addr and old_addr in self.addr_to_identity:
            del self.addr_to_identity[old_addr]
        
        self.peer_addresses[user_id] = new_addr
        self.addr_to_identity[new_addr] = user_id
        
        # Guardar clave pública efímera (necesaria si queremos iniciar un handshake nosotros)
        if pub_key_obj:
            self.sessions.db.ephemeral_keys[new_addr] = pub_key_obj
        
        # Notificar a la sesión activa sobre el cambio de dirección
        session = self.sessions.get_session(user_id)
        if session:
            session.current_addr = new_addr
            # Si cambió la IP, invalidamos la sesión porque la seguridad de la clave efímera podría estar comprometida
            # o el par podría haberse reiniciado.
            if pub_key_obj and session.rs_pub:
                old_pub = session.rs_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                new_pub = pub_key_obj.public_bytes_raw() if hasattr(pub_key_obj, 'public_bytes_raw') else pub_key_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                if old_pub != new_pub:
                    self.on_log(f"🔄 {user_id} reconectó con nueva clave, invalidando sesión criptográfica.")
                    session.encryptor = None
                    session.decryptor = None

    async def _retry_worker(self):
        """
        Hilo de fondo que reenvía mensajes no confirmados (ACK).
        Implementa un mecanismo simple de "Stop-and-Wait" por usuario.
        """
        while True:
            await asyncio.sleep(5.0) # Check cada 5 segundos
            now = time.time()
            for user_id in list(self.message_queues.keys()):
                queue = self.message_queues[user_id]
                if not queue: continue
                
                # Solo reintentamos el primer mensaje de la cola (Head-of-Line Blocking intencional para orden)
                head = queue[0]
                target_addr = self.peer_addresses.get(user_id)
                if not target_addr: continue
                
                session = self.sessions.get_session(user_id)
                
                if session and session.encryptor:
                    try:
                        head['last_retry'] = now
                        head['attempts'] += 1
                        await self._transmit_raw(user_id, head['content'], head['msg_id'], timestamp=head['timestamp'])
                    except Exception as e:
                        self.on_log(f"❌ Retry fallido: {e}")
                else:
                    # Si no hay sesión cifrada, intentamos handshake
                    if self.is_peer_online_callback and not self.is_peer_online_callback(user_id):
                        continue
                    
                    # Control de flood de handshakes (max 1 cada 5s)
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
        """Envía el siguiente mensaje en la cola tras recibir un ACK del anterior."""
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

    def datagram_received(self, data, addr):
        """
        Manejador principal de paquetes UDP entrantes.
        Despacha según el byte de cabecera.
        """
        if len(data) < 1: return
        try:
            packet_type = data[0]
            payload = data[1:]
            
            if packet_type == 0x01: # Handshake Initial
                self.handle_handshake_init(payload, addr)
            elif packet_type == 0x02: # Handshake Response
                self.handle_handshake_resp(payload, addr)
            elif packet_type == 0x03: # Data Packet (Cifrado)
                self.handle_data(payload, addr)
        except Exception as e:
            self.on_log(f"❌ Paquete erróneo desde {addr}: {e}")

    def handle_handshake_init(self, data, addr):
        """
        Procesa el inicio de un handshake (Rol: Respondedor).
        Verifica la identidad del iniciador y responde.
        """
        self.on_log(f"🔄 Handshake Init desde {addr}")
        session = self.sessions.create_responder_session()
        session.current_addr = addr
        try:
            # Procesar criptografía Noise
            remote_pub = session.consume_handshake_message(data)
            
            # Verificar identidad DNIe
            try:
                real_name, issuer = verify_peer_identity(remote_pub, session.remote_proofs)
                self.on_log(f"✅ Identidad Verificada: {real_name} | Emisor: {issuer}")
            except Exception as e:
                self.on_log(f"⛔ ALERTA DE SEGURIDAD: Identidad inválida ({e})")
                self.sessions.remove_session(session)
                return

            # Registrar sesión
            user_id = self.addr_to_identity.get(addr, real_name)
            self.sessions.update_session_identity(session, user_id)
            self.peer_addresses[user_id] = addr
            self.addr_to_identity[addr] = user_id
            
            # Enviar respuesta
            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Respuesta enviado a {addr}")
            
            # Persistir contacto y notificar UI
            asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], remote_pub, real_name=real_name))
            if self.on_handshake_success:
                self.on_handshake_success(addr, remote_pub, real_name)
            
            # Si teníamos mensajes en cola para este usuario, enviarlos ahora
            if user_id in self.message_queues and self.message_queues[user_id]:
                asyncio.create_task(self._flush_pending_queue(user_id, session))
                
        except Exception as e:
            self.on_log(f"❌ Handshake fallido: {e}")
            self.sessions.remove_session(session)

    def handle_handshake_resp(self, data, addr):
        """
        Procesa la respuesta de un handshake (Rol: Iniciador).
        Completa el establecimiento de claves.
        """
        if len(data) < 8: return
        receiver_index = struct.unpack('<I', data[4:8])[0]
        session = self.sessions.get_session_by_id(receiver_index)
        if not session: return

        try:
            session.current_addr = addr
            session.consume_handshake_response(data)
            
            # Verificación de identidad del servidor/respondedor
            try:
                real_name, issuer = verify_peer_identity(session.rs_pub, session.remote_proofs)
                self.on_log(f"✅ Identidad del Par Verificada: {real_name}")
                asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], session.rs_pub, real_name=real_name))
            except Exception as e:
                self.on_log(f"⛔ SEGURIDAD: Fallo verificación par: {e}")
                self.sessions.remove_session(session)
                return

            user_id = getattr(session, 'peer_identity', None) or self.addr_to_identity.get(addr, real_name)
            self.sessions.update_session_identity(session, user_id)
            self.peer_addresses[user_id] = addr
            self.addr_to_identity[addr] = user_id
            
            self.pending_handshakes.pop(user_id, None)

            if self.on_handshake_success:
                self.on_handshake_success(addr, session.rs_pub, real_name)

            # Liberar cola de mensajes
            if user_id in self.message_queues and self.message_queues[user_id]:
                self.on_log(f"🚀 Canal seguro establecido, enviando cola...")
                asyncio.create_task(self._flush_pending_queue(user_id, session))

        except Exception as e:
            self.on_log(f"❌ Error completando handshake: {e}")

    def handle_data(self, data, addr):
        """
        Maneja paquetes de datos cifrados (Type 0x03).
        """
        if len(data) < 4: return
        receiver_index = struct.unpack('<I', data[:4])[0]
        encrypted_payload = data[4:]
        
        session = self.sessions.get_session_by_id(receiver_index)
        if not session: return
        
        # Si la sesión fue invalidada (zeroizada), ignorar el paquete silenciosamente
        # Esto ocurre cuando el peer envía desconexión por mDNS y luego llega el paquete UDP
        if not session.decryptor:
            return
        
        user_id = getattr(session, 'peer_identity', None)
        
        # Detección de Roaming (Cambio de IP)
        if session.current_addr != addr:
            self.on_log(f"🚀 Roaming detectado: {user_id} movido de {session.current_addr} a {addr}")
            session.current_addr = addr
            if user_id:
                self.peer_addresses[user_id] = addr
                self.addr_to_identity[addr] = user_id
        
        try:
            plaintext = session.decrypt_message(encrypted_payload)
            msg_struct = json.loads(plaintext.decode('utf-8'))

            # Manejo de ACKs (Confirmaciones de recepción)
            if 'ack_id' in msg_struct:
                ack_id = msg_struct['ack_id']
                if user_id and user_id in self.message_queues:
                    queue = self.message_queues[user_id]
                    # Si el ACK coincide con el mensaje que estamos intentando enviar, lo quitamos
                    if queue and queue[0]['msg_id'] == ack_id:
                        queue.popleft() 
                        if queue:
                            asyncio.create_task(self._send_next_in_queue(user_id))
                if self.on_ack_received:
                    self.on_ack_received(addr, ack_id)
                return 

            # Verificación de integridad del mensaje (Hash Check)
            if 'text' in msg_struct and 'hash' in msg_struct:
                content = msg_struct['text']
                local_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                msg_struct['integrity'] = (local_hash == msg_struct['hash'])
            
            # Enviar ACK automático y deduplicar
            if 'id' in msg_struct and not msg_struct.get('disconnect'):
                incoming_id = msg_struct['id']
                asyncio.create_task(self.send_ack(session, incoming_id))
                
                if incoming_id in self.dedup_buffer:
                    return # Mensaje duplicado ignorado
                self.dedup_buffer.append(incoming_id)

            self.on_message(addr, msg_struct)
        except Exception as e:
            self.on_log(f"❌ Error descifrando mensaje: {e}")

    async def send_ack(self, session, msg_id):
        """Envía un paquete de confirmación (ACK) cifrado."""
        if not session or not session.encryptor: return
        try:
            ack_payload = {"timestamp": time.time(), "ack_id": msg_id}
            json_bytes = json.dumps(ack_payload).encode('utf-8')
            full_packet_payload = session.encrypt_message(json_bytes)
            self.transport.sendto(b'\x03' + full_packet_payload, session.current_addr)
        except Exception: pass

    async def _transmit_raw(self, user_id, content, msg_id, is_disconnect=False, timestamp=None):
        """
        Función interna para construir y enviar paquetes.
        Inicia handshakes automáticamente si no hay sesión cifrada.
        """
        target_addr = self.peer_addresses.get(user_id)
        if not target_addr: return
        
        session = self.sessions.get_session(user_id)
        
        # Lógica de inicio de sesión bajo demanda
        if not session or not session.encryptor:
            remote_pub = await self.sessions.db.get_pubkey_by_addr(target_addr[0], target_addr[1])
            if remote_pub:
                self.on_log(f"🔄 Handshake automático al enviar a {user_id}")
                new_session = self.sessions.create_initiator_session(remote_pub, user_id)
                new_session.current_addr = target_addr
                hs_msg = new_session.create_handshake_message()
                self.transport.sendto(b'\x01' + hs_msg, target_addr)
                self.pending_handshakes[user_id] = time.time()
            return 

        # Envío cifrado
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
            self.on_log(f"❌ Fallo transmisión: {e}")

    async def send_message(self, user_id, content, is_disconnect=False, forced_msg_id=None):
        """Interfaz pública para encolar mensajes."""
        msg_id = forced_msg_id if forced_msg_id else str(uuid.uuid4())
        
        if is_disconnect:
            # Los mensajes de desconexión no se encolan, se intentan enviar una vez ("Best Effort")
            session = self.sessions.get_session(user_id)
            if session and session.encryptor:
                await self._send_disconnect_to_session(session)
            return msg_id
        
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
        # Si es el único mensaje, intentar enviarlo inmediatamente
        if len(queue) == 1:
            await self._attempt_send_head(user_id, queue[0])
        return msg_id

    async def _attempt_send_head(self, user_id, item):
        item['last_retry'] = time.time()
        item['attempts'] += 1
        await self._transmit_raw(user_id, item['content'], item['msg_id'], timestamp=item['timestamp'])
    
    async def broadcast_disconnect(self):
        """Informa a todos los pares conectados que nos vamos."""
        tasks = []
        for user_id, session in list(self.sessions.sessions.items()):
            if session.encryptor and session.current_addr:
                tasks.append(self._send_disconnect_to_session(session))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_disconnect_to_session(self, session):
        try:
            msg_struct = {"timestamp": time.time(), "disconnect": True}
            payload = json.dumps(msg_struct).encode('utf-8')
            full_packet_payload = session.encrypt_message(payload)
            self.transport.sendto(b'\x03' + full_packet_payload, session.current_addr)
        except: pass
    
    async def _flush_pending_queue(self, user_id, session):
        # Helper para vaciar cola
        if user_id not in self.message_queues: return
        queue = self.message_queues[user_id]
        if not queue: return
        head = queue[0]
        try:
            head['last_retry'] = time.time()
            head['attempts'] += 1
            await self._transmit_raw(user_id, head['content'], head['msg_id'], timestamp=head['timestamp'])
        except Exception: pass

# --- DESCUBRIMIENTO DE RED (mDNS) ---

class RawSniffer(asyncio.DatagramProtocol):
    """
    Protocolo de escucha mDNS de bajo nivel optimizado.
    
    Por qué una clase dedicada:
    Las librerías estándar de mDNS a veces fallan al procesar paquetes no estándar 
    o malformados. Esta clase inspecciona los bytes crudos para garantizar que 
    detectamos a otros usuarios incluso si el paquete no es perfecto.
    """
    def __init__(self, service):
        self.service = service
        self.transport = None
        self.sock = None

    def connection_made(self, transport):
        self.transport = transport
        self.sock = transport.get_extra_info('socket')
        try:
            # Permitir reutilización de puertos para convivir con Avahi/Bonjour
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except: pass
        self.join_multicast_groups()

    def join_multicast_groups(self):
        """Se une al grupo multicast 224.0.0.251 para escuchar tráfico mDNS."""
        if not self.sock: return
        group = socket.inet_aton('224.0.0.251')
        try:
            # Unirse en interfaz por defecto
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except: pass
        
        # Intentar unirse en todas las interfaces detectadas
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
        Analiza paquetes mDNS.
        
        Estrategia de Optimización:
        1. Fail-Fast: Si no contiene "_dni-im", descartar inmediatamente.
        2. Slicing directo: Buscar "pub=" y extraer 64 bytes fijos es más rápido que regex.
        3. Fallback a Regex: Solo para campos variables como el nombre de usuario.
        """
        if b"_dni-im" not in data: return
        
        user_id_found = None
        port_found = 0
        props = {}
        
        # Extracción rápida de clave pública (64 bytes hex)
        pub_idx = data.find(b'pub=')
        if pub_idx != -1:
            if pub_idx + 4 + 64 <= len(data):
                try:
                    props['pub'] = data[pub_idx+4 : pub_idx+4+64].decode('utf-8')
                except: pass
        
        # Extracción de usuario y puerto (Variable)
        match_name = RE_USER_PORT.search(data)
        if match_name:
            try:
                user_id_found = match_name.group(1).decode('utf-8', errors='ignore')
                port_found = int(match_name.group(2).decode('utf-8'))
            except: pass
        
        if RE_STAT_EXIT.search(data):
            props['stat'] = 'exit'

        if user_id_found:
            # Ignorarnos a nosotros mismos
            if user_id_found == self.service.unique_instance_id and port_found == self.service.port:
                return
            if addr[0].startswith('127.'):
                return
            self.service.on_found(user_id_found, addr[0], port_found, props)


class DiscoveryService:
    """
    Servicio de Alto Nivel para Descubrimiento de Pares.
    
    Orquesta:
    1. AsyncZeroconf: Para ANUNCIAR nuestra presencia de forma estándar.
    2. RawSniffer: Para ESCUCHAR a otros de forma robusta.
    3. Monitorización de IP: Reinicia el servicio si cambia la red (WiFi -> Ethernet).
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
        self.protocol_ref = proto
        proto.discovery_service = self

    async def start(self, username, bind_ip=None):
        """Inicia el anuncio y la escucha."""
        self.loop = asyncio.get_running_loop()
        self.bind_ip = bind_ip
        clean_username = username.replace("User-", "")
        self.unique_instance_id = clean_username
        
        # Iniciar Sniffer (Escucha)
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

        # Iniciar Zeroconf (Anuncio)
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
        
        # Tarea periódica para detectar cambios de red
        self._polling_task = asyncio.create_task(self._active_polling_loop())

    def on_found(self, user_id, ip, port, props):
        """Callback invocado por el Sniffer cuando detecta un par."""
        if self.on_found_callback:
             self.on_found_callback(user_id, ip, port, props)
        
        # Manejar desconexión voluntaria
        if props.get('stat') == 'exit':
            self.on_log(f"📴 Peer {user_id} anunció desconexión (stat=exit)")
            if self.protocol_ref:
                session = self.protocol_ref.sessions.get_session(user_id)
                if session:
                    # Borrado seguro de claves de la sesión
                    if hasattr(session, 'zeroize_session'):
                        session.zeroize_session()
                    else:
                        session.encryptor = None
            return
        
        # Actualizar dirección IP en el protocolo
        if self.protocol_ref:
            try:
                pub_key_obj = None
                if 'pub' in props:
                    pub_bytes = bytes.fromhex(props['pub'])
                    pub_key_obj = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                
                self.protocol_ref.update_peer_location(user_id, (ip, port), pub_key_obj)
                
                # También registrar la clave en storage para que esté disponible para handshakes
                if pub_key_obj:
                    import asyncio
                    asyncio.create_task(self.protocol_ref.sessions.db.register_contact(ip, port, pub_key_obj, user_id=user_id, real_name=None))
            except Exception as e:
                self.on_log(f"⚠️ Error actualizando ubicación de peer: {e}")

    def broadcast_exit(self):
        """Envía manualmente un paquete mDNS 'stat=exit' para despedirse rápido."""
        if not self.sniffer_transport: return
        try:
            # Construcción manual de paquete para ser rápido
            fake_payload = (
                b'\x00' * 12 +     
                b'_dni-im' +       
                f'User-{self.unique_instance_id}_{self.port}'.encode('utf-8') + 
                b'\x00fake\x00' +  
                b'stat=exit'       
            )
            self.sniffer_transport.sendto(fake_payload, ('224.0.0.251', 5353))
        except: pass

    async def stop(self):
        self.broadcast_exit()
        if hasattr(self, '_polling_task'): self._polling_task.cancel()
        if self.sniffer_transport: self.sniffer_transport.close()
        if hasattr(self, 'info') and hasattr(self, 'aiozc'): 
            await self.aiozc.async_unregister_service(self.info)
        if hasattr(self, 'aiozc'): await self.aiozc.async_close()

    def get_local_ip(self):
        """Truco para obtener la IP real usada para salir a Internet."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 80)); IP = s.getsockname()[0]
        except: IP = '127.0.0.1'
        finally: s.close()
        return IP

    async def _active_polling_loop(self):
        """Monitoriza cambios de IP y mantiene viva la escucha."""
        while True:
            await asyncio.sleep(5)
            # Re-unirse al grupo multicast para evitar timeout del switch/router
            if self.sniffer_protocol:
                self.sniffer_protocol.join_multicast_groups()
            
            # Chequeo de cambio de IP
            try:
                current_ip = self.bind_ip if (self.bind_ip and self.bind_ip != "0.0.0.0") else self.get_local_ip()
                current_ip_bytes = socket.inet_aton(current_ip)
                registered_ip_bytes = self.info.addresses[0] if self.info.addresses else b''

                if registered_ip_bytes != current_ip_bytes and current_ip != '127.0.0.1':
                     self.on_log(f"🔄 IP de Red cambió: {current_ip}. Reiniciando Servicio mDNS...")
                     try:
                         # Cerrar completamente el Zeroconf antiguo
                         try:
                             await self.aiozc.async_unregister_service(self.info)
                         except: pass
                         try:
                             await self.aiozc.async_close()
                         except: pass
                         
                         # Crear nuevo AsyncZeroconf con la nueva interfaz
                         interfaces = [current_ip] if current_ip != "0.0.0.0" else InterfaceChoice.All
                         try:
                             self.aiozc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only)
                         except:
                             self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All)
                         
                         # Actualizar ServiceInfo con la nueva IP
                         self.info.addresses = [current_ip_bytes]
                         
                         # Registrar el servicio en el nuevo Zeroconf
                         await self.aiozc.async_register_service(self.info)
                         self.on_log(f"✅ Servicio mDNS reiniciado completamente en {current_ip}")
                         
                         # Rejoin al grupo multicast en la nueva interfaz
                         if self.sniffer_protocol:
                             self.sniffer_protocol.join_multicast_groups()
                             self.on_log(f"✅ Multicast re-unido en nueva interfaz")
                         
                         # Enviar varias queries para que los otros nos descubran rápido
                         if self.sniffer_transport:
                             for _ in range(3):
                                 self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                                 await asyncio.sleep(0.5)
                             self.on_log(f"📡 Queries mDNS enviadas para redescubrimiento")
                             
                     except Exception as e:
                         import traceback
                         self.on_log(f"⚠️ Error reiniciando mDNS: {type(e).__name__}: {e}")
                         self.on_log(f"   Traceback: {traceback.format_exc()}")
            except: pass
            
            # Enviar query activa para despertar a otros
            if self.sniffer_transport:
                 try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                 except: pass