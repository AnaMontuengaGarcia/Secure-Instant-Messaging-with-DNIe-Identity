"""
Módulo de Red y Comunicaciones (Networking) - Versión QUIC
----------------------------------------------------------
Gestiona toda la comunicación de bajo nivel usando QUIC/TLS 1.3, incluyendo:
1. Conexiones QUIC con aioquic (transporte fiable y cifrado).
2. Handshake Noise IK sobre QUIC para autenticación DNIe.
3. Descubrimiento de pares mediante mDNS (Multicast DNS).
4. Verificación de certificados X.509 del DNIe.

Arquitectura Híbrida:
- QUIC (TLS 1.3 Autofirmado) para el transporte fiable y cifrado base.
- Noise IK corriendo DENTRO de QUIC únicamente para autenticar 
  que "el dueño de este túnel tiene el DNIe X".
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
from typing import Dict, Optional, Callable, Any

from aioquic.asyncio import QuicConnectionProtocol, serve, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    StreamDataReceived, 
    HandshakeCompleted, 
    ConnectionTerminated,
    StreamReset
)

from zeroconf import ServiceInfo, IPVersion, InterfaceChoice
from zeroconf.asyncio import AsyncZeroconf
from protocol import NoiseIKState
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519

# --- CONFIGURACIÓN Y CONSTANTES ---

def normalize_addr(addr: tuple) -> tuple:
    """
    Normaliza una dirección de red.
    Convierte IPv6-mapped IPv4 (::ffff:x.x.x.x) a IPv4 puro (x.x.x.x).
    Convierte tuplas de 4 elementos (IPv6) a tuplas de 2 elementos (IPv4).
    """
    if not addr:
        return addr
    
    ip = addr[0]
    port = addr[1]
    
    # Convertir IPv6-mapped IPv4 a IPv4 puro
    if ip.startswith('::ffff:'):
        ip = ip[7:]  # Quitar el prefijo '::ffff:'
    
    return (ip, port)

# Expresiones regulares para parsing manual de paquetes mDNS.
RE_USER_PORT = re.compile(rb'User-([^_\x00]+)_(\d+)')
RE_USER_PROP = re.compile(rb'user=([^\x00]+)')
RE_STAT_EXIT = re.compile(rb'stat=exit')

# Identificador del servicio mDNS
MDNS_TYPE = "_dni-im._udp.local."

# Paquete de consulta mDNS pre-construido
RAW_MDNS_QUERY = (
    b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x07_dni-im\x04_udp\x05local\x00'
    b'\x00\x0c'
    b'\x00\x01'
)

TRUSTED_CERTS_DIR = "certs"

# --- Tipos de Paquete para el Stream de Señalización (Stream 0) ---
SIGNAL_NOISE_INIT = 0x01      # Handshake Noise: Mensaje inicial
SIGNAL_NOISE_RESPONSE = 0x02  # Handshake Noise: Respuesta
SIGNAL_DISCONNECT = 0x03      # Notificación de desconexión
SIGNAL_MSG_ACK = 0x04         # ACK de mensaje recibido

# --- UTILIDADES DE CERTIFICADOS ---

def load_trusted_cas():
    """
    Carga los certificados de Autoridad de Certificación (CA) de confianza desde el disco.
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
    """Extrae el Nombre Común (CN) de un certificado X.509."""
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return "Unknown Common Name"

def verify_peer_identity(x25519_pub_key, proofs):
    """
    Verifica criptográficamente la identidad de un par remoto.
    
    Pasos de verificación:
    1. Validez Temporal
    2. Uso de Clave
    3. Cadena de Confianza
    4. Firma de Propiedad
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

        # 2. Verificación de Uso de Clave
        try:
            key_usage_ext = peer_cert.extensions.get_extension_for_class(x509.KeyUsage)
            usage = key_usage_ext.value
            if not (usage.digital_signature or usage.content_commitment):
                raise Exception("Certificado no permitido para Firma Digital/Autenticación")
        except x509.ExtensionNotFound:
            pass

        # 3. Verificación de Cadena de Confianza
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
    En la arquitectura QUIC híbrida, Noise IK se usa SOLO para autenticación,
    no para cifrar datos (eso lo hace TLS 1.3 de QUIC).
    """
    def __init__(self, local_static_key, db, local_proofs):
        self.local_static_key = local_static_key
        self.local_proofs = local_proofs
        self.sessions = {}           # real_name (DNIe) -> session object
        self.sessions_by_id = {}     # local_index (int) -> session object
        self.db = db

    def get_session(self, identity: str):
        """
        Busca una sesión activa por identidad DNIe.
        
        Args:
            identity: Nombre real del titular del DNIe (ej: "JUAN GARCÍA PÉREZ").
            
        Returns:
            NoiseIKSession si existe una sesión activa, None en caso contrario.
        """
        return self.sessions.get(identity)

    def register_session(self, session, identity: str = None):
        """
        Registra una nueva sesión Noise IK en los índices del gestor.
        
        Si ya existe una sesión con la misma identidad, la reemplaza
        y elimina la sesión antigua de los índices.
        
        Args:
            session: Instancia de NoiseIKSession a registrar.
            identity: Nombre real del titular (opcional, puede asociarse después).
        """
        if identity and identity in self.sessions:
            old_session = self.sessions[identity]
            if old_session.local_index in self.sessions_by_id:
                del self.sessions_by_id[old_session.local_index]
        
        self.sessions_by_id[session.local_index] = session
        
        if identity:
            self.sessions[identity] = session
            session.peer_identity = identity

    def update_session_identity(self, session, identity: str):
        """
        Asocia una sesión anónima con una identidad tras verificar el handshake.
        
        Se llama después de que la verificación DNIe confirme la identidad
        del peer remoto.
        
        Args:
            session: Sesión Noise IK ya establecida.
            identity: Nombre real verificado del titular del DNIe.
        """
        if identity in self.sessions:
            old_session = self.sessions[identity]
            if old_session is not session:
                if old_session.local_index in self.sessions_by_id:
                    del self.sessions_by_id[old_session.local_index]
        
        self.sessions[identity] = session
        session.peer_identity = identity

    def remove_session(self, session):
        """
        Elimina una sesión de todos los registros y borra sus claves criptográficas.
        
        Realiza zeroización segura de las claves de la sesión antes de
        eliminarla de los índices.
        
        Args:
            session: Sesión Noise IK a eliminar.
        """
        if hasattr(session, 'zeroize_session'):
            session.zeroize_session()
        
        if session.local_index in self.sessions_by_id:
            del self.sessions_by_id[session.local_index]
        
        identity = getattr(session, 'peer_identity', None)
        if identity and identity in self.sessions:
            if self.sessions[identity] is session:
                del self.sessions[identity]

    def zeroize_all_sessions(self):
        """Borra de forma segura todas las sesiones activas."""
        for session in list(self.sessions_by_id.values()):
            if hasattr(session, 'zeroize_session'):
                session.zeroize_session()
        self.sessions.clear()
        self.sessions_by_id.clear()

    def create_initiator_session(self, remote_pub_key, identity: str = None):
        """
        Crea una sesión Noise IK en modo INICIADOR (Cliente).
        
        El iniciador conoce la clave pública del servidor de antemano
        (obtenida vía mDNS) y puede enviar datos cifrados desde el primer mensaje.
        
        Args:
            remote_pub_key: Clave pública X25519 del peer remoto.
            identity: Identidad DNIe del peer (opcional, puede ser None inicialmente).
            
        Returns:
            NoiseIKState: Sesión inicializada lista para crear mensaje de handshake.
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
        Crea una sesión Noise IK en modo RESPONDEDOR (Servidor).
        
        El respondedor no conoce al iniciador hasta recibir el primer mensaje.
        La identidad se asociará después de verificar las pruebas DNIe.
        
        Returns:
            NoiseIKState: Sesión inicializada esperando mensaje de handshake.
        """
        session = NoiseIKState(
            self.local_static_key, 
            initiator=False,
            local_proofs=self.local_proofs
        )
        session.initialize()
        session.peer_identity = None
        self.sessions_by_id[session.local_index] = session
        return session


# --- PROTOCOLO QUIC ---

class MeshQuicProtocol(QuicConnectionProtocol):
    """
    Protocolo QUIC para la malla de mensajería.
    
    Maneja eventos de la conexión QUIC y coordina el handshake Noise IK
    para autenticación de identidad DNIe.
    
    Streams:
    - Stream 0: Señalización (Handshake Noise)
    - Streams pares (2, 4, 6...): Datos de chat (iniciados por cliente)
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.network_manager: Optional['QuicNetworkManager'] = None
        self.noise_session: Optional[NoiseIKState] = None
        self.peer_identity: Optional[str] = None
        self.is_authenticated = False
        self.target_pub_key = None  # Clave pública del peer (para iniciadores)
        self.target_user_id = None  # user_id mDNS del peer (para recovery_queue)
        self._pending_messages = []  # Mensajes pendientes hasta autenticación
        self._unacked_messages = {}  # msg_id -> msg_struct (enviados pero sin ACK)
        self._signal_buffer = b""    # Buffer para Stream 0

    def set_network_manager(self, manager: 'QuicNetworkManager'):
        """Inyecta referencia al gestor de red."""
        self.network_manager = manager

    def set_target_pub_key(self, pub_key):
        """Establece la clave pública objetivo (para conexiones salientes)."""
        self.target_pub_key = pub_key

    def quic_event_received(self, event):
        """Manejador principal de eventos QUIC."""
        
        # 1. Conexión TLS establecida
        if isinstance(event, HandshakeCompleted):
            self._handle_tls_handshake_complete()
        
        # 2. Datos recibidos en un Stream
        elif isinstance(event, StreamDataReceived):
            if event.stream_id == 0:
                # Stream de señalización
                self._handle_signal_data(event.data, event.end_stream)
            else:
                # Stream de datos de chat
                self._handle_chat_data(event.stream_id, event.data, event.end_stream)
        
        # 3. Conexión terminada
        elif isinstance(event, ConnectionTerminated):
            self._handle_connection_closed(event)
        
        # 4. Stream reseteado
        elif isinstance(event, StreamReset):
            self._log(f"⚠️ Stream {event.stream_id} reseteado: {event.error_code}")

    def _handle_tls_handshake_complete(self):
        """Callback cuando TLS 1.3 se establece."""
        # Detectar si somos cliente (iniciador de conexión)
        # En aioquic, el cliente tiene _quic._is_client = True
        is_client = self._quic._is_client
        
        if is_client:
            # Como clientes, iniciamos el handshake Noise
            self._initiate_noise_handshake()

    def _initiate_noise_handshake(self):
        """Inicia Noise IK sobre el Stream 0 de QUIC (lado cliente)."""
        if not self.target_pub_key:
            self._log("❌ No hay clave pública objetivo para Noise handshake")
            return
        
        if not self.network_manager:
            self._log("❌ NetworkManager no configurado")
            return
        
        # Crear sesión Noise como iniciador
        self.noise_session = self.network_manager.sessions.create_initiator_session(
            self.target_pub_key,
            identity=None  # Se sabrá tras verificar el handshake
        )
        
        # Crear y enviar mensaje A de Noise
        msg_a = self.noise_session.create_handshake_message()
        self._send_signal(SIGNAL_NOISE_INIT, msg_a)

    def _handle_signal_data(self, data: bytes, end_stream: bool):
        """Procesa datos del Stream 0 (señalización/handshake).
        
        Formato de paquete: [tipo 1B][longitud 4B][payload NB]
        """
        self._signal_buffer += data
        
        # Necesitamos al menos 5 bytes para tipo + longitud
        while len(self._signal_buffer) >= 5:
            packet_type = self._signal_buffer[0]
            payload_len = struct.unpack('<I', self._signal_buffer[1:5])[0]
            
            # Verificar que tenemos el mensaje completo
            total_len = 5 + payload_len
            if len(self._signal_buffer) < total_len:
                # Esperar más datos
                break
            
            payload = self._signal_buffer[5:total_len]
            self._signal_buffer = self._signal_buffer[total_len:]  # Consumir paquete
            
            if packet_type == SIGNAL_NOISE_INIT:
                self._handle_noise_init(payload)
            
            elif packet_type == SIGNAL_NOISE_RESPONSE:
                self._handle_noise_response(payload)
            
            elif packet_type == SIGNAL_DISCONNECT:
                self._handle_peer_disconnect()
            
            elif packet_type == SIGNAL_MSG_ACK:
                self._handle_msg_ack(payload)
            
            else:
                self._log(f"⚠️ Tipo de señal desconocido: {packet_type}")
                break

    def _handle_noise_init(self, data: bytes):
        """Procesa mensaje inicial de Noise (lado servidor/respondedor)."""
        if not self.network_manager:
            self._log("❌ NetworkManager no disponible en _handle_noise_init")
            return
        
        try:
            # Crear sesión Noise como respondedor
            self.noise_session = self.network_manager.sessions.create_responder_session()
            
            # Procesar mensaje A
            remote_pub = self.noise_session.consume_handshake_message(data)
            
            # Verificar identidad DNIe
            try:
                real_name, issuer = verify_peer_identity(remote_pub, self.noise_session.remote_proofs)
                self.peer_identity = real_name
            except Exception as e:
                self._log(f"⛔ ALERTA DE SEGURIDAD: Identidad inválida ({e})")
                self.network_manager.sessions.remove_session(self.noise_session)
                self.close()
                return
            
            # Registrar sesión con identidad
            self.network_manager.sessions.update_session_identity(self.noise_session, real_name)
            
            # Crear y enviar respuesta (Mensaje B) - SIEMPRE completar el handshake
            resp_data = self.noise_session.create_handshake_response()
            self._send_signal(SIGNAL_NOISE_RESPONSE, resp_data)
            
            # Verificar si ya existe una conexión activa con este peer
            # Buscar primero el user_id del peer para verificar correctamente
            raw_peer_addr = normalize_addr(self._quic._network_paths[0].addr) if self._quic._network_paths else None
            peer_user_id = None
            if self.network_manager:
                # Buscar user_id por dirección IP
                if raw_peer_addr:
                    for uid, addr in self.network_manager.peer_addresses.items():
                        if addr[0] == raw_peer_addr[0]:  # Misma IP
                            peer_user_id = uid
                            break
            
            existing_proto = None
            if peer_user_id:
                existing_proto = self.network_manager.active_connections.get(peer_user_id)
                if existing_proto and existing_proto.is_authenticated and existing_proto is not self:
                    pass  # Encontrada conexión existente
                else:
                    existing_proto = None
            
            if existing_proto:
                # Ya tenemos conexión activa con este peer
                # Completamos el handshake pero cerramos esta conexión redundante
                self._log(f"ℹ️ Conexión entrante de {real_name} - reutilizando conexión existente")
                self.is_authenticated = True  # Para que el cierre sea limpio
                # NO registrar esta conexión - cerrarla después de responder
                # Dar tiempo a que el handshake response llegue
                asyncio.get_event_loop().call_later(0.5, self._close_redundant)
                return
            
            # Es una conexión nueva - registrarla
            self._log(f"✅ Conectado con: {real_name} (Firmado por: {issuer})")
            
            # Obtener dirección de conexión (puede ser puerto efímero)
            raw_peer_addr = normalize_addr(self._quic._network_paths[0].addr) if self._quic._network_paths else None
            
            # Buscar la dirección correcta (puerto anunciado) del peer y su user_id
            announced_addr = None
            peer_user_id = None
            if self.network_manager:
                # Buscar por identidad primero
                announced_addr = self.network_manager.peer_addresses.get(real_name)
                if announced_addr:
                    # Buscar user_id para esta dirección
                    peer_user_id = self.network_manager.addr_to_identity.get(announced_addr)
                
                if not announced_addr and raw_peer_addr:
                    # Buscar por IP (normalizada)
                    for uid, addr in self.network_manager.peer_addresses.items():
                        if addr[0] == raw_peer_addr[0]:  # Misma IP
                            announced_addr = addr
                            peer_user_id = uid
                            # Actualizar mapeo de identidad
                            self.network_manager.peer_addresses[real_name] = addr
                            self.network_manager.addr_to_identity[addr] = real_name
                            break
            
            # Guardar user_id del peer para identificación
            self.target_user_id = peer_user_id
            
            # Marcar como autenticado y registrar conexión
            self.is_authenticated = True
            self._register_connection()
            
            # Usar dirección anunciada si existe, sino la de conexión
            peer_addr = announced_addr or raw_peer_addr
            
            # Registrar clave pública en memoria (NO en DB, cambia cada sesión)
            if peer_user_id and self.network_manager:
                self.network_manager.peer_pubkeys[peer_user_id] = remote_pub
            
            # Notificar a UI si hay callback
            if self.network_manager.on_handshake_success:
                self.network_manager.on_handshake_success(peer_addr, remote_pub, real_name)
                
        except Exception as e:
            import traceback
            self._log(f"❌ Error de autenticación: {type(e).__name__}")
            
            # Si el error es InvalidTag, probablemente el peer tiene una clave diferente
            # a la que usó para cifrar el mensaje. Esto puede pasar si:
            # 1. El peer usó nuestra clave pública antigua (nosotros nos reconectamos)
            # 2. Hay corrupción de datos
            
            if self.noise_session:
                self.network_manager.sessions.remove_session(self.noise_session)
            self.close()

    def _handle_noise_response(self, data: bytes):
        """Procesa respuesta de Noise (lado cliente/iniciador)."""
        if not self.noise_session:
            self._log("❌ No hay sesión Noise activa")
            return
        
        try:
            # Consumir respuesta
            self.noise_session.consume_handshake_response(data)
            
            # Verificar identidad del servidor
            try:
                real_name, issuer = verify_peer_identity(
                    self.noise_session.rs_pub, 
                    self.noise_session.remote_proofs
                )
                self.peer_identity = real_name
            except Exception as e:
                self._log(f"⛔ SEGURIDAD: Fallo verificación par: {e}")
                self.network_manager.sessions.remove_session(self.noise_session)
                self.close()
                return
            
            # Actualizar sesión con identidad
            self.network_manager.sessions.update_session_identity(self.noise_session, real_name)
            
            # Verificar si ya existe una conexión entrante de este peer
            # (el peer pudo habernos conectado mientras nosotros le conectábamos)
            # En el lado cliente, target_user_id ya debería estar asignado
            existing_proto = None
            if self.target_user_id:
                existing_proto = self.network_manager.active_connections.get(self.target_user_id)
                if existing_proto and existing_proto.is_authenticated and existing_proto is not self:
                    pass  # Hay conexión existente
                else:
                    existing_proto = None
            
            if existing_proto:
                # El peer ya nos conectó - esta conexión es redundante
                # Pero la usamos para enviar nuestros mensajes pendientes primero
                self._log(f"ℹ️ Conexión con {real_name} redundante - reutilizando entrante")
            else:
                self._log(f"🎉 Canal seguro establecido con {real_name} (Firmado por: {issuer})")
            
            # Marcar como autenticado
            self.is_authenticated = True
            self._register_connection()
            
            # Registrar clave pública en memoria (NO en DB, cambia cada sesión)
            peer_addr = normalize_addr(self._quic._network_paths[0].addr) if self._quic._network_paths else None
            if peer_addr and self.network_manager:
                # Buscar user_id por dirección o identidad
                uid = self.network_manager.addr_to_identity.get(peer_addr)
                if uid:
                    self.network_manager.peer_pubkeys[uid] = self.noise_session.rs_pub
            
            # Notificar a UI
            if self.network_manager.on_handshake_success:
                self.network_manager.on_handshake_success(
                    peer_addr, self.noise_session.rs_pub, real_name
                )
            
            # NO llamar a _flush_pending_messages() aquí - lo hará _connect_and_send
            # para evitar race conditions
            
        except Exception as e:
            import traceback
            self._log(f"❌ Error de autenticación: {type(e).__name__}")
            
            # Si el error es InvalidTag, la clave del peer cambió
            # Debemos invalidar la clave que tenemos y esperar nueva vía mDNS
            # Marcar que necesitamos actualizar la clave de este peer
            if self.network_manager and self.target_pub_key:
                # Buscar qué user_id tiene esta clave
                for uid, pub in list(self.network_manager.peer_pubkeys.items()):
                    try:
                        if pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == \
                           self.target_pub_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
                            # Marcar para que se actualice con la próxima clave de mDNS
                            if not hasattr(self.network_manager, '_stale_keys'):
                                self.network_manager._stale_keys = set()
                            self.network_manager._stale_keys.add(uid)
                            break
                    except:
                        pass
            
            if self.noise_session:
                self.network_manager.sessions.remove_session(self.noise_session)
            self.close()

    def _handle_peer_disconnect(self):
        """Maneja notificación de desconexión del peer."""
        if self.peer_identity:
            self._log(f"📴 {self.peer_identity} se desconectó")
        self._cleanup()

    def _handle_chat_data(self, stream_id: int, data: bytes, end_stream: bool):
        """Procesa datos de chat recibidos (Descifrado ChaCha20Poly1305 WireGuard-style)."""
        if not self.is_authenticated or not self.noise_session:
            return
        
        try:
            # 1. Extraer el Nonce (los primeros 12 bytes)
            if len(data) < 12:
                self._log("❌ Mensaje muy corto, ignorando")
                return
            
            received_nonce = data[:12]
            ciphertext = data[12:]
            
            # 2. Protección Anti-Replay con Ventana Deslizante (WireGuard-style)
            # Extraer el contador del nonce (primeros 8 bytes, Little Endian)
            counter = struct.unpack('<Q', received_nonce[:8])[0]
            
            # Verificar si el contador es válido usando ventana deslizante
            if not self._check_replay(counter):
                self._log(f"⚠️ Paquete rechazado por anti-replay (contador: {counter})")
                return
            
            # 3. Descifrar usando el decryptor de la sesión
            # Si el descifrado falla (Poly1305 no coincide), lanzará excepción
            # protegiendo automáticamente contra modificaciones
            plaintext = self.noise_session.decryptor.decrypt(received_nonce, ciphertext, None)
            
            # 4. Actualizar ventana anti-replay DESPUÉS de descifrado exitoso
            self._update_replay_window(counter)
            
            # 5. Parsear el JSON (ahora ya es texto plano seguro)
            msg_struct = json.loads(plaintext.decode('utf-8'))
            
            # Verificación de integridad del mensaje (Hash Check de aplicación)
            if 'text' in msg_struct and 'hash' in msg_struct:
                content = msg_struct['text']
                local_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                msg_struct['integrity'] = (local_hash == msg_struct['hash'])
            
            # Añadir identidad del remitente
            msg_struct['sender_identity'] = self.peer_identity
            
            # Añadir user_id del remitente para desambiguación (nombres duplicados)
            msg_struct['sender_user_id'] = self.target_user_id
            
            # Notificar a la capa superior
            # IMPORTANTE: Usar la dirección del servidor del peer (puerto anunciado),
            # no el puerto efímero de la conexión entrante
            if self.network_manager and self.network_manager.on_message:
                # Buscar la dirección correcta usando peer_identity
                correct_addr = self.network_manager.peer_addresses.get(self.peer_identity)
                if not correct_addr:
                    # Fallback: usar la IP de la conexión pero con puerto del servidor
                    raw_addr = normalize_addr(self._quic._network_paths[0].addr) if self._quic._network_paths else None
                    if raw_addr:
                        # Intentar buscar por IP (normalizada)
                        for uid, addr in self.network_manager.peer_addresses.items():
                            if addr[0] == raw_addr[0]:  # Misma IP
                                correct_addr = addr
                                break
                        if not correct_addr:
                            correct_addr = raw_addr
                
                self.network_manager.on_message(correct_addr, msg_struct)
                
                # Enviar ACK al emisor
                if 'id' in msg_struct:
                    self._send_msg_ack(msg_struct['id'])
                
        except json.JSONDecodeError as e:
            self._log(f"❌ Error en mensaje recibido (JSON inválido)")
        except Exception as e:
            self._log(f"❌ Error descifrando o procesando mensaje: {e}")

    def _handle_connection_closed(self, event: ConnectionTerminated):
        """Maneja el cierre de conexión."""
        # Si la conexión se cerró sin completar autenticación y éramos cliente,
        # puede ser que usamos una clave obsoleta del peer
        if not self.is_authenticated and self._quic._is_client and self.target_pub_key:
            pass  # Silencioso - se reintentará automáticamente
            # Buscar qué user_id tiene esta clave
            if self.network_manager:
                for uid, pub in list(self.network_manager.peer_pubkeys.items()):
                    try:
                        if pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == \
                           self.target_pub_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
                            if not hasattr(self.network_manager, '_stale_keys'):
                                self.network_manager._stale_keys = set()
                            self.network_manager._stale_keys.add(uid)
                            break
                    except:
                        pass
        
        self._cleanup()

    def _cleanup(self):
        """Limpia recursos de la conexión."""
        # Recuperar mensajes sin ACK para reenvío
        # IMPORTANTE: Usar user_id (mDNS ID), no peer_identity (nombre certificado)
        # para que coincida con las claves usadas en update_peer_location
        
        # Prioridad 1: usar target_user_id si fue asignado explícitamente
        cleanup_user_id = self.target_user_id
        
        # Prioridad 2: buscar en active_connections
        if not cleanup_user_id and self.network_manager:
            for uid, proto in list(self.network_manager.active_connections.items()):
                if proto is self:
                    cleanup_user_id = uid
                    break
        
        # Prioridad 3: buscar por clave pública
        if not cleanup_user_id and self.target_pub_key and self.network_manager:
            for uid, pub in list(self.network_manager.peer_pubkeys.items()):
                try:
                    if pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == \
                       self.target_pub_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
                        cleanup_user_id = uid
                        break
                except:
                    pass
        
        # Prioridad 4: usar peer_identity si es un user_id corto (no un nombre)
        if not cleanup_user_id and self.peer_identity:
            # peer_identity cortos (ej: f2fd0120) son user_ids, nombres largos no
            if len(self.peer_identity) <= 16 and ' ' not in self.peer_identity:
                cleanup_user_id = self.peer_identity
        
        if self.network_manager and cleanup_user_id:
            unacked_msgs = list(self._unacked_messages.values())
            pending_msgs = list(self._pending_messages)
            all_pending = unacked_msgs + pending_msgs
            
            if all_pending:
                # Guardar en la cola global del NetworkManager para reenvío
                if not hasattr(self.network_manager, '_recovery_queue'):
                    self.network_manager._recovery_queue = {}
                if cleanup_user_id not in self.network_manager._recovery_queue:
                    self.network_manager._recovery_queue[cleanup_user_id] = []
                self.network_manager._recovery_queue[cleanup_user_id].extend(all_pending)
            
            # Remover de conexiones activas
            if cleanup_user_id in self.network_manager.active_connections:
                del self.network_manager.active_connections[cleanup_user_id]
        
        if self.peer_identity and self.network_manager:
            if self.peer_identity in self.network_manager.active_connections:
                del self.network_manager.active_connections[self.peer_identity]
        
        if self.noise_session and self.network_manager:
            self.network_manager.sessions.remove_session(self.noise_session)
        
        self._unacked_messages.clear()
        self._pending_messages.clear()
        self.is_authenticated = False
        self.peer_identity = None

    def _register_connection(self):
        """
        Registra esta conexión como activa en el NetworkManager.
        
        Usa target_user_id (hash del serial DNIe) como clave, que es lo que
        usa send_message() para buscar conexiones existentes.
        """
        if not self.network_manager:
            return
        
        # Determinar la clave de registro (preferir user_id sobre peer_identity)
        registration_key = self.target_user_id or self.peer_identity
        if not registration_key:
            return
        
        # Si ya existe una conexión con este peer, reemplazarla
        old_proto = self.network_manager.active_connections.get(registration_key)
        if old_proto and old_proto is not self:
            # Cerrar la conexión antigua de forma limpia
            old_proto._close_redundant()
        
        self.network_manager.active_connections[registration_key] = self

    def _close_redundant(self):
        """Cierra esta conexión de forma limpia (es redundante)."""
        try:
            # Limpiar sesión Noise
            if self.noise_session:
                self.network_manager.sessions.remove_session(self.noise_session)
                self.noise_session = None
            # Cerrar conexión QUIC sin notificar desconeción
            self._quic.close()
            self.transmit()
        except:
            pass

    def _send_signal(self, signal_type: int, payload: bytes):
        """Envía un paquete de señalización por Stream 0.
        
        Formato: [tipo 1B][longitud 4B][payload NB]
        """
        header = bytes([signal_type]) + struct.pack('<I', len(payload))
        data = header + payload
        self._quic.send_stream_data(0, data, end_stream=False)
        self.transmit()

    def send_chat_message(self, msg_struct: dict) -> bool:
        """
        Envía un mensaje de chat.
        
        Cifrado WireGuard-style: El mensaje se cifra con ChaCha20Poly1305
        usando la clave de sesión Noise antes de enviarlo por QUIC.
        Esto proporciona cifrado de capa de aplicación independiente de TLS.
        """
        if not self.is_authenticated or not self.noise_session:
            # Encolar para cuando se autentique
            self._pending_messages.append(msg_struct)
            return False
        
        try:
            # 1. Serializar el JSON a bytes
            json_bytes = json.dumps(msg_struct).encode('utf-8')
            
            # 2. Obtener y preparar el Nonce (12 bytes: 8 bytes contador + 4 bytes padding ceros)
            # Usamos 'Little Endian' (<) para el contador de 64 bits (Q)
            nonce = struct.pack('<Q', self.noise_session.tx_nonce) + b'\x00\x00\x00\x00'
            
            # 3. Cifrar usando el encryptor de la sesión
            # El encryptor ya tiene la clave de sesión (k1) configurada desde el handshake
            ciphertext = self.noise_session.encryptor.encrypt(nonce, json_bytes, None)
            
            # 4. Incrementar el contador local para el siguiente mensaje
            self.noise_session.tx_nonce += 1
            
            # 5. Empaquetar para envío: Enviamos [Nonce (12B)] + [Ciphertext]
            # Es vital enviar el nonce para que el receptor sepa cuál usar
            final_payload = nonce + ciphertext
            
            # 6. Enviar por el stream de QUIC
            stream_id = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(stream_id, final_payload, end_stream=True)
            self.transmit()
            
            # Guardar mensaje como pendiente de ACK (usando msg_struct original)
            if 'id' in msg_struct:
                self._unacked_messages[msg_struct['id']] = msg_struct.copy()
            
            return True
        except Exception as e:
            self._log(f"❌ Error cifrando/enviando mensaje: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _check_replay(self, counter: int) -> bool:
        """
        Verifica si un contador de paquete es válido (protección anti-replay).
        
        Implementa ventana deslizante estilo WireGuard:
        - Si counter > rx_nonce: Es un paquete nuevo (válido)
        - Si counter <= rx_nonce - window_size: Es demasiado antiguo (rechazar)
        - Si counter está en la ventana: Verificar bitmap para ver si ya se usó
        
        Returns:
            True si el paquete es válido (no es replay), False si debe rechazarse.
        """
        if not self.noise_session:
            return False
        
        rx_nonce = self.noise_session.rx_nonce
        window_size = self.noise_session.replay_window_size
        bitmap = self.noise_session.replay_bitmap
        
        # Caso 1: Paquete más nuevo que cualquiera visto
        if counter > rx_nonce:
            return True
        
        # Caso 2: Paquete demasiado antiguo (fuera de la ventana)
        if counter + window_size <= rx_nonce:
            return False
        
        # Caso 3: Paquete dentro de la ventana - verificar bitmap
        # El bit en posición (rx_nonce - counter) indica si ya se recibió
        bit_position = rx_nonce - counter
        if bitmap & (1 << bit_position):
            # Ya se recibió este paquete - es un replay
            return False
        
        return True

    def _update_replay_window(self, counter: int):
        """
        Actualiza la ventana anti-replay después de un descifrado exitoso.
        
        - Si counter > rx_nonce: Desliza la ventana y marca el bit 0
        - Si counter está en la ventana: Marca el bit correspondiente
        """
        if not self.noise_session:
            return
        
        rx_nonce = self.noise_session.rx_nonce
        window_size = self.noise_session.replay_window_size
        bitmap = self.noise_session.replay_bitmap
        
        if counter > rx_nonce:
            # Nuevo paquete más alto - deslizar ventana
            shift = counter - rx_nonce
            if shift >= window_size:
                # Gran salto - reiniciar bitmap
                bitmap = 1
            else:
                # Deslizar bitmap y marcar posición 0
                bitmap = (bitmap << shift) | 1
                # Mantener solo los bits dentro de la ventana
                bitmap &= (1 << window_size) - 1
            
            # Actualizar contador máximo
            self.noise_session.rx_nonce = counter
        else:
            # Paquete dentro de la ventana - marcar su bit
            bit_position = rx_nonce - counter
            bitmap |= (1 << bit_position)
        
        self.noise_session.replay_bitmap = bitmap

    def _send_msg_ack(self, msg_id: str):
        """Envía ACK de recepción de mensaje."""
        self._send_signal(SIGNAL_MSG_ACK, msg_id.encode('utf-8'))

    def _handle_msg_ack(self, payload: bytes):
        """Procesa ACK de mensaje recibido del peer."""
        try:
            msg_id = payload.decode('utf-8')
            
            # Remover de mensajes sin ACK
            if msg_id in self._unacked_messages:
                del self._unacked_messages[msg_id]
            
            # Notificar a la capa superior
            if self.network_manager and self.network_manager.on_ack_received:
                # Obtener dirección correcta del peer
                peer_addr = None
                if self.peer_identity:
                    peer_addr = self.network_manager.peer_addresses.get(self.peer_identity)
                if not peer_addr:
                    raw_addr = normalize_addr(self._quic._network_paths[0].addr) if self._quic._network_paths else None
                    if raw_addr:
                        for uid, addr in self.network_manager.peer_addresses.items():
                            if addr[0] == raw_addr[0]:
                                peer_addr = addr
                                break
                        if not peer_addr:
                            peer_addr = raw_addr
                
                self.network_manager.on_ack_received(peer_addr, msg_id)
        except Exception as e:
            pass  # ACK fallido, el mensaje se reenviará si es necesario

    def send_disconnect_notification(self):
        """Envía notificación de desconexión al peer."""
        self._send_signal(SIGNAL_DISCONNECT, b"")

    def _flush_pending_messages(self):
        """Envía mensajes que estaban esperando autenticación."""
        if not self._pending_messages:
            return
        
        for msg in self._pending_messages:
            self.send_chat_message(msg)
        self._pending_messages.clear()

    def _log(self, message: str):
        """Envía mensaje de log al NetworkManager."""
        if self.network_manager and self.network_manager.on_log:
            self.network_manager.on_log(message)
        else:
            print(message)


class QuicNetworkManager:
    """
    Gestor central de conexiones QUIC.
    
    Orquesta:
    1. Servidor QUIC para conexiones entrantes.
    2. Conexiones salientes a peers descubiertos.
    3. Enrutamiento de mensajes a las conexiones correctas.
    """
    
    def __init__(
        self,
        session_manager: SessionManager,
        cert_path: str,
        key_path: str,
        on_message: Callable = None,
        on_log: Callable = None,
        on_handshake_success: Callable = None,
        on_ack_received: Callable = None
    ):
        self.sessions = session_manager
        self.cert_path = cert_path
        self.key_path = key_path
        self.on_message = on_message
        self.on_log = on_log or (lambda x: None)
        self.on_handshake_success = on_handshake_success
        self.on_ack_received = on_ack_received  # Callback para ACKs (compatibilidad TUI)
        
        # Conexiones activas: user_id -> MeshQuicProtocol
        self.active_connections: Dict[str, MeshQuicProtocol] = {}
        
        # Direcciones conocidas: user_id -> (ip, port)
        self.peer_addresses: Dict[str, tuple] = {}
        self.addr_to_identity: Dict[tuple, str] = {}
        
        # Claves públicas conocidas: user_id -> X25519PublicKey
        self.peer_pubkeys: Dict[str, Any] = {}
        
        # Servidor QUIC
        self._server = None
        self._server_task = None
        
        # Configuraciones TLS
        self._server_config = None
        self._client_config = None
        
        # Buffer de deduplicación
        self.dedup_buffer = deque(maxlen=200)
        
        # Referencia al servicio de descubrimiento
        self.discovery_service = None
        
        # Tareas de conexión pendientes
        self._pending_connections: Dict[str, asyncio.Task] = {}
        
        # Callbacks de compatibilidad con la TUI (se configuran externamente)
        self.get_peer_addr_callback = None
        self.get_user_id_callback = None
        self.is_peer_online_callback = None

    def _create_server_config(self) -> QuicConfiguration:
        """Crea configuración TLS para el servidor."""
        config = QuicConfiguration(
            alpn_protocols=["dnie-mesh-v1"],
            is_client=False,
            max_datagram_frame_size=65536,
            idle_timeout=300.0,  # 5 minutos de timeout
        )
        config.load_cert_chain(self.cert_path, self.key_path)
        return config

    def _create_client_config(self) -> QuicConfiguration:
        """Crea configuración TLS para el cliente."""
        config = QuicConfiguration(
            alpn_protocols=["dnie-mesh-v1"],
            is_client=True,
            max_datagram_frame_size=65536,
            idle_timeout=300.0,  # 5 minutos de timeout
        )
        # No verificamos el certificado del servidor (usamos Noise para eso)
        config.verify_mode = False
        return config

    async def start_server(self, host: str, port: int):
        """Inicia el servidor QUIC."""
        self._server_config = self._create_server_config()
        self._client_config = self._create_client_config()
        
        self._server = await serve(
            host,
            port,
            configuration=self._server_config,
            create_protocol=self._create_server_protocol,
        )
        
        self.on_log(f"✅ Servidor QUIC iniciado en {host}:{port}")

    def _create_server_protocol(self, *args, **kwargs) -> MeshQuicProtocol:
        """Factory para crear protocolos de servidor."""
        proto = MeshQuicProtocol(*args, **kwargs)
        proto.set_network_manager(self)
        return proto

    async def connect_to(self, ip: str, port: int, target_pub_key, user_id: str = None) -> Optional[MeshQuicProtocol]:
        """
        Conecta activamente a un peer y mantiene la conexión.
        
        Args:
            ip: Dirección IP del peer
            port: Puerto del peer
            target_pub_key: Clave pública X25519 del peer (necesaria para Noise IK)
            user_id: Identificador opcional del usuario
            
        Returns:
            MeshQuicProtocol si la conexión se establece, None en caso contrario
        """
        if not self._client_config:
            self._client_config = self._create_client_config()
        
        try:
            # Crear protocolo con la clave pública inyectada
            def protocol_factory(*args, **kwargs):
                proto = MeshQuicProtocol(*args, **kwargs)
                proto.set_network_manager(self)
                proto.set_target_pub_key(target_pub_key)
                proto.target_user_id = user_id  # Guardar user_id para recovery_queue
                return proto
            
            # Usar connect de aioquic (devuelve un protocolo)
            async with connect(
                ip,
                port,
                configuration=self._client_config,
                create_protocol=protocol_factory,
            ) as protocol:
                # Mantener la conexión viva esperando que se cierre
                # El handshake Noise se iniciará automáticamente en HandshakeCompleted
                
                # Esperar un poco para que el handshake Noise se complete
                for _ in range(50):  # 5 segundos máximo
                    await asyncio.sleep(0.1)
                    if protocol.is_authenticated:
                        # Mantener la conexión viva (el context manager la cerrará al salir)
                        # Para conexiones persistentes, necesitamos evitar que salga del context
                        while protocol.is_authenticated:
                            await asyncio.sleep(1)
                        break
                
                return protocol
                
        except asyncio.CancelledError:
            return None
        except Exception as e:
            return None

    def update_peer_location(self, user_id: str, new_addr: tuple, pub_key_obj=None):
        """Actualiza la ubicación de un peer (llamado desde mDNS discovery)."""
        old_addr = self.peer_addresses.get(user_id)
        old_pub = self.peer_pubkeys.get(user_id)
        
        # Verificar si la clave estaba marcada como obsoleta (por un error InvalidTag previo)
        key_was_stale = hasattr(self, '_stale_keys') and user_id in self._stale_keys
        if key_was_stale and pub_key_obj:
            self._stale_keys.discard(user_id)
        
        # Detectar si la clave pública cambió (peer se reconectó con nueva sesión)
        pub_key_changed = False
        pub_key_is_new = pub_key_obj and not old_pub  # Primera vez que recibimos clave
        if pub_key_obj and old_pub:
            try:
                old_pub_bytes = old_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                new_pub_bytes = pub_key_obj.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                pub_key_changed = old_pub_bytes != new_pub_bytes
            except:
                pub_key_changed = True
        
        # Detectar cambio de IP
        ip_changed = old_addr and old_addr != new_addr
        
        # Los cambios de clave o IP se manejan silenciosamente
        
        # Si cambió IP o clave pública O la clave estaba obsoleta, invalidar conexiones y reencolar mensajes
        if pub_key_changed or ip_changed or key_was_stale:
            # Recopilar mensajes pendientes antes de cerrar
            pending_msgs = []
            
            # Mensajes en la cola global
            if hasattr(self, '_message_queue') and user_id in self._message_queue:
                pending_msgs.extend(self._message_queue[user_id])
                del self._message_queue[user_id]
            
            # Mensajes sin ACK recuperados de conexiones cerradas
            if hasattr(self, '_recovery_queue') and user_id in self._recovery_queue:
                pending_msgs.extend(self._recovery_queue[user_id])
                del self._recovery_queue[user_id]
            
            # Cerrar conexión antigua si existe
            if user_id in self.active_connections:
                old_proto = self.active_connections[user_id]
                # Recuperar mensajes pendientes de la conexión
                if old_proto._pending_messages:
                    pending_msgs.extend(old_proto._pending_messages)
                    old_proto._pending_messages.clear()
                # Recuperar mensajes sin ACK
                if old_proto._unacked_messages:
                    pending_msgs.extend(old_proto._unacked_messages.values())
                    old_proto._unacked_messages.clear()
                try:
                    if old_proto.noise_session:
                        old_proto.noise_session.zeroize_session()
                    old_proto.close()
                except:
                    pass
                del self.active_connections[user_id]
            
            # Cancelar conexión pendiente si existe
            if user_id in self._pending_connections:
                # Recuperar mensajes de la cola de reenvío pendiente
                if hasattr(self, '_pending_resend_messages') and user_id in self._pending_resend_messages:
                    resend_msgs = self._pending_resend_messages[user_id]
                    pending_msgs.extend(resend_msgs)
                    del self._pending_resend_messages[user_id]
                self._pending_connections[user_id].cancel()
                del self._pending_connections[user_id]
            
            # Deduplicar mensajes por ID
            seen_ids = set()
            unique_msgs = []
            for msg in pending_msgs:
                msg_id = msg.get('id')
                if msg_id and msg_id not in seen_ids:
                    seen_ids.add(msg_id)
                    unique_msgs.append(msg)
                elif not msg_id:
                    unique_msgs.append(msg)
            pending_msgs = unique_msgs
            
            # Si hay mensajes pendientes, decidir qué hacer
            if pending_msgs:
                # IMPORTANTE: Si cambió la IP pero NO tenemos nueva clave pública,
                # NO intentar reenviar aún - la clave antigua ya no es válida.
                # Guardar mensajes y esperar a que llegue la nueva clave vía mDNS.
                if ip_changed and not pub_key_obj:
                    # Guardar en _message_queue para cuando llegue la nueva clave
                    if not hasattr(self, '_message_queue'):
                        self._message_queue = {}
                    if user_id not in self._message_queue:
                        self._message_queue[user_id] = []
                    self._message_queue[user_id].extend(pending_msgs)
                    # Invalidar la clave antigua
                    if user_id in self.peer_pubkeys:
                        del self.peer_pubkeys[user_id]
                else:
                    # Tenemos la nueva clave, podemos reenviar
                    # Guardar mensajes para recuperación si se cancela
                    if not hasattr(self, '_pending_resend_messages'):
                        self._pending_resend_messages = {}
                    self._pending_resend_messages[user_id] = pending_msgs.copy()
                    # Programar reenvío de mensajes a la nueva dirección
                    asyncio.create_task(self._resend_pending_messages(user_id, new_addr, pub_key_obj, pending_msgs))
        
        # Si nada cambió (misma dirección, misma clave o sin clave nueva), verificar si hay mensajes pendientes
        if old_addr == new_addr and not pub_key_changed and not pub_key_is_new:
            # Aunque no cambió nada, verificar si hay mensajes en recovery_queue para este peer
            # (pueden haber quedado de una conexión cerrada por timeout)
            if pub_key_obj and hasattr(self, '_recovery_queue') and user_id in self._recovery_queue:
                pending_msgs = self._recovery_queue[user_id]
                del self._recovery_queue[user_id]
                if pending_msgs:
                    if not hasattr(self, '_pending_resend_messages'):
                        self._pending_resend_messages = {}
                    self._pending_resend_messages[user_id] = pending_msgs.copy()
                    asyncio.create_task(self._resend_pending_messages(user_id, new_addr, pub_key_obj, pending_msgs))
            # También verificar _message_queue
            if pub_key_obj and hasattr(self, '_message_queue') and user_id in self._message_queue:
                pending_msgs = self._message_queue[user_id]
                del self._message_queue[user_id]
                if pending_msgs:
                    if not hasattr(self, '_pending_resend_messages'):
                        self._pending_resend_messages = {}
                    self._pending_resend_messages[user_id] = pending_msgs.copy()
                    asyncio.create_task(self._resend_pending_messages(user_id, new_addr, pub_key_obj, pending_msgs))
            return
        
        if old_addr and old_addr in self.addr_to_identity:
            del self.addr_to_identity[old_addr]
        
        self.peer_addresses[user_id] = new_addr
        self.addr_to_identity[new_addr] = user_id
        
        # Actualizar clave pública en memoria (NO en DB, cambia cada sesión)
        if pub_key_obj:
            self.peer_pubkeys[user_id] = pub_key_obj
            
            # Recopilar todos los mensajes pendientes de las diferentes colas
            all_pending = []
            
            # Mensajes en _message_queue (esperando clave)
            if hasattr(self, '_message_queue') and user_id in self._message_queue:
                all_pending.extend(self._message_queue[user_id])
                del self._message_queue[user_id]
            
            # Mensajes en _recovery_queue (de conexiones cerradas)
            if hasattr(self, '_recovery_queue') and user_id in self._recovery_queue:
                all_pending.extend(self._recovery_queue[user_id])
                del self._recovery_queue[user_id]
            
            # Deduplicar por ID
            if all_pending:
                seen_ids = set()
                unique_msgs = []
                for msg in all_pending:
                    msg_id = msg.get('id')
                    if msg_id and msg_id not in seen_ids:
                        seen_ids.add(msg_id)
                        unique_msgs.append(msg)
                    elif not msg_id:
                        unique_msgs.append(msg)
                
                if unique_msgs:
                    if not hasattr(self, '_pending_resend_messages'):
                        self._pending_resend_messages = {}
                    self._pending_resend_messages[user_id] = unique_msgs.copy()
                    asyncio.create_task(self._resend_pending_messages(user_id, new_addr, pub_key_obj, unique_msgs))

    async def _resend_pending_messages(self, user_id: str, new_addr: tuple, pub_key, messages: list):
        """Reenvía mensajes pendientes a la nueva dirección del peer."""
        if not messages:
            return
        
        # Esperar un momento para que la nueva conexión se estabilice
        await asyncio.sleep(0.5)
        
        # Usar la nueva dirección y clave pública
        if pub_key:
            self.peer_pubkeys[user_id] = pub_key
        
        # Crear nueva conexión y enviar mensajes
        try:
            if not self._client_config:
                self._client_config = self._create_client_config()
            
            target_pub = self.peer_pubkeys.get(user_id)
            if not target_pub:
                return
            
            def protocol_factory(*args, **kwargs):
                proto = MeshQuicProtocol(*args, **kwargs)
                proto.set_network_manager(self)
                proto.set_target_pub_key(target_pub)
                proto.target_user_id = user_id  # Guardar user_id para recovery_queue
                # Pre-encolar todos los mensajes pendientes
                for msg in messages:
                    proto._pending_messages.append(msg)
                return proto
            
            task = asyncio.create_task(self._connect_and_send_with_factory(
                user_id, new_addr[0], new_addr[1], protocol_factory
            ))
            self._pending_connections[user_id] = task
            
        except Exception as e:
            pass  # Se reintentará automáticamente

    async def _connect_and_send_with_factory(self, user_id: str, ip: str, port: int, protocol_factory):
        """Conecta usando una factory de protocolo personalizada."""
        try:
            async with connect(
                ip,
                port,
                configuration=self._client_config,
                create_protocol=protocol_factory,
            ) as protocol:
                # Esperar autenticación (max 5 segundos)
                auth_timeout = 50
                for i in range(auth_timeout):
                    await asyncio.sleep(0.1)
                    if protocol.is_authenticated:
                        break
                
                if not protocol.is_authenticated:
                    return
                
                # Registrar conexión activa
                self.active_connections[user_id] = protocol
                
                # Forzar envío de mensajes pendientes
                if protocol._pending_messages:
                    protocol._flush_pending_messages()
                    # Limpiar _pending_resend_messages ya que los mensajes se enviaron
                    if hasattr(self, '_pending_resend_messages') and user_id in self._pending_resend_messages:
                        del self._pending_resend_messages[user_id]
                
                # Mantener conexión viva
                while protocol.is_authenticated:
                    await asyncio.sleep(1)
                    
                    # Verificar si hay mensajes nuevos encolados
                    if hasattr(self, '_message_queue') and user_id in self._message_queue:
                        for msg in self._message_queue[user_id]:
                            protocol._pending_messages.append(msg)
                        del self._message_queue[user_id]
                        if protocol._pending_messages:
                            protocol._flush_pending_messages()
                    
        except Exception as e:
            pass
        finally:
            if user_id in self._pending_connections:
                del self._pending_connections[user_id]
            if user_id in self.active_connections:
                del self.active_connections[user_id]

    async def send_message(self, user_id: str, content: str, is_disconnect: bool = False, forced_msg_id: str = None) -> Optional[str]:
        """
        Envía un mensaje a un usuario.
        
        Si no hay conexión activa, intenta establecerla.
        """
        msg_id = forced_msg_id or str(uuid.uuid4())
        
        if is_disconnect:
            # Mensaje de desconexión - enviar a todas las conexiones activas
            if user_id in self.active_connections:
                try:
                    self.active_connections[user_id].send_disconnect_notification()
                except:
                    pass
            return msg_id
        
        # Verificar si tenemos conexión activa y autenticada
        proto = self.active_connections.get(user_id)
        if proto and proto.is_authenticated:
            # Enviar mensaje directamente
            msg_struct = {
                "id": msg_id,
                "timestamp": time.time(),
                "text": content,
                "hash": hashlib.sha256(content.encode('utf-8')).hexdigest()
            }
            
            if proto.send_chat_message(msg_struct):
                return msg_id
            else:
                # Limpiar conexión fallida
                del self.active_connections[user_id]
                proto = None
        
        # No hay conexión activa, necesitamos establecer una
        target_addr = self.peer_addresses.get(user_id)
        target_pub = self.peer_pubkeys.get(user_id)
        
        # Si la clave está marcada como obsoleta, no la usamos
        if hasattr(self, '_stale_keys') and user_id in self._stale_keys:
            target_pub = None
        
        # Si no tenemos los datos en memoria, intentar obtenerlos del callback de la TUI
        if not target_addr and self.get_peer_addr_callback:
            target_addr = self.get_peer_addr_callback(user_id)
            if target_addr:
                self.peer_addresses[user_id] = target_addr
        
        # Las claves públicas solo vienen de mDNS, NO de la DB (cambian cada sesión)
        
        if not target_addr or not target_pub:
            missing = []
            if not target_addr:
                missing.append("dirección")
            if not target_pub:
                # Encolar el mensaje para cuando llegue la clave vía mDNS
                if not hasattr(self, '_message_queue'):
                    self._message_queue = {}
                if user_id not in self._message_queue:
                    self._message_queue[user_id] = []
                self._message_queue[user_id].append({
                    "id": msg_id,
                    "timestamp": time.time(),
                    "text": content,
                    "hash": hashlib.sha256(content.encode('utf-8')).hexdigest()
                })
                return msg_id  # Retornamos el ID aunque no se haya enviado aún
            return None
        
        # Verificar si ya hay una conexión pendiente
        if user_id in self._pending_connections:
            # La conexión pendiente tiene los mensajes en su cola
            task = self._pending_connections[user_id]
            if not task.done():
                # Añadir el mensaje a una cola global temporal
                if not hasattr(self, '_message_queue'):
                    self._message_queue = {}
                if user_id not in self._message_queue:
                    self._message_queue[user_id] = []
                self._message_queue[user_id].append({
                    "id": msg_id,
                    "timestamp": time.time(),
                    "text": content,
                    "hash": hashlib.sha256(content.encode('utf-8')).hexdigest()
                })
                return msg_id
        
        # Crear mensaje para encolar
        msg_struct = {
            "id": msg_id,
            "timestamp": time.time(),
            "text": content,
            "hash": hashlib.sha256(content.encode('utf-8')).hexdigest()
        }
        
        # Lanzar conexión en background
        task = asyncio.create_task(self._connect_and_send(
            user_id, target_addr[0], target_addr[1], target_pub, msg_struct
        ))
        self._pending_connections[user_id] = task
        
        return msg_id

    async def _connect_and_send(self, user_id: str, ip: str, port: int, pub_key, initial_message: dict):
        """
        Conecta a un peer, realiza handshake y envía mensajes pendientes.
        Mantiene la conexión abierta para futuros mensajes.
        """
        try:
            if not self._client_config:
                self._client_config = self._create_client_config()
            
            # Crear protocolo con mensaje inicial
            pending_messages = [initial_message]
            
            def protocol_factory(*args, **kwargs):
                proto = MeshQuicProtocol(*args, **kwargs)
                proto.set_network_manager(self)
                proto.set_target_pub_key(pub_key)
                proto.target_user_id = user_id  # Guardar user_id para recovery_queue
                # Pre-encolar mensajes
                for msg in pending_messages:
                    proto._pending_messages.append(msg)
                return proto
            
            # Conectar con timeout
            try:
                # Usar wait_connected=True (valor por defecto) para que aioquic
                # llame a transmit() automáticamente y envíe el Client Hello.
                # Envolvemos todo en un timeout para no bloquear indefinidamente.
                connection = connect(
                    ip,
                    port,
                    configuration=self._client_config,
                    create_protocol=protocol_factory,
                    wait_connected=True,  # IMPORTANTE: Debe ser True para que se transmita el handshake
                )
                
                # Timeout de 10 segundos para establecer conexión TLS completa
                protocol = await asyncio.wait_for(
                    connection.__aenter__(),
                    timeout=10.0
                )
                self.on_log(f"🔗 Conexión QUIC/TLS establecida con {ip}:{port}")
                
            except asyncio.TimeoutError:
                self.on_log(f"⏰ Timeout conectando a {ip}:{port} (10s)")
                return
            except Exception as conn_err:
                self.on_log(f"❌ Error conectando a {ip}:{port}: {conn_err}")
                return
            
            try:
                
                # Esperar autenticación Noise (max 5 segundos)
                auth_timeout = 50
                for i in range(auth_timeout):
                    await asyncio.sleep(0.1)
                    if protocol.is_authenticated:
                        self.on_log(f"✅ Conexión autenticada con {user_id}")
                        break
                
                if not protocol.is_authenticated:
                    self.on_log(f"⏰ Timeout esperando autenticación Noise con {user_id}")
                    await connection.__aexit__(None, None, None)
                    return
                
                # Registrar conexión activa
                self.active_connections[user_id] = protocol
                
                # IMPORTANTE: Forzar envío de mensajes pendientes ahora
                if protocol._pending_messages:
                    self.on_log(f"📤 Enviando {len(protocol._pending_messages)} mensajes pendientes...")
                    protocol._flush_pending_messages()
                
                # Añadir cualquier mensaje que se haya encolado mientras conectábamos
                if hasattr(self, '_message_queue') and user_id in self._message_queue:
                    for msg in self._message_queue[user_id]:
                        protocol._pending_messages.append(msg)
                    del self._message_queue[user_id]
                    if protocol._pending_messages:
                        protocol._flush_pending_messages()
                
                # Mantener conexión viva mientras esté autenticada
                while protocol.is_authenticated:
                    await asyncio.sleep(1)
                    
                    # Verificar si hay mensajes nuevos encolados
                    if hasattr(self, '_message_queue') and user_id in self._message_queue:
                        for msg in self._message_queue[user_id]:
                            protocol._pending_messages.append(msg)
                        del self._message_queue[user_id]
                        if protocol._pending_messages:
                            protocol._flush_pending_messages()
                
                self.on_log(f"🔌 Conexión con {user_id} cerrada")
                
            finally:
                # Cerrar la conexión
                try:
                    await connection.__aexit__(None, None, None)
                except:
                    pass
                    
        except Exception as e:
            self.on_log(f"❌ Error en connect_and_send a {user_id}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Limpiar estado
            if user_id in self._pending_connections:
                del self._pending_connections[user_id]
            if user_id in self.active_connections:
                del self.active_connections[user_id]

    async def broadcast_disconnect(self):
        """Notifica a todos los peers que nos desconectamos."""
        for user_id, proto in list(self.active_connections.items()):
            try:
                proto.send_disconnect_notification()
            except Exception:
                pass

    async def close(self):
        """Cierra el servidor y todas las conexiones."""
        # Cancelar conexiones pendientes
        for task in self._pending_connections.values():
            task.cancel()
        self._pending_connections.clear()
        
        # Cerrar conexiones activas
        for proto in list(self.active_connections.values()):
            try:
                proto.close()
            except Exception:
                pass
        
        self.active_connections.clear()
        
        # Cerrar servidor
        if self._server:
            self._server.close()
            self._server = None


# --- DESCUBRIMIENTO DE RED (mDNS) ---

class RawSniffer(asyncio.DatagramProtocol):
    """
    Protocolo de escucha mDNS de bajo nivel optimizado.
    """
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
        except:
            pass
        self.join_multicast_groups()

    def join_multicast_groups(self):
        """Se une al grupo multicast 224.0.0.251 para escuchar tráfico mDNS."""
        if not self.sock:
            return
        group = socket.inet_aton('224.0.0.251')
        try:
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except:
            pass
        
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        if ip == '127.0.0.1':
                            continue
                        try:
                            local = socket.inet_aton(ip)
                            mreq = struct.pack('4s4s', group, local)
                            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                        except:
                            pass
        except Exception:
            pass

    def datagram_received(self, data, addr):
        """Analiza paquetes mDNS."""
        if b"_dni-im" not in data:
            return
        
        user_id_found = None
        port_found = 0
        props = {}
        
        # Extracción rápida de clave pública
        pub_idx = data.find(b'pub=')
        if pub_idx != -1:
            if pub_idx + 4 + 64 <= len(data):
                try:
                    props['pub'] = data[pub_idx + 4: pub_idx + 4 + 64].decode('utf-8')
                except:
                    pass
        
        # Extracción de usuario y puerto
        match_name = RE_USER_PORT.search(data)
        if match_name:
            try:
                user_id_found = match_name.group(1).decode('utf-8', errors='ignore')
                port_found = int(match_name.group(2).decode('utf-8'))
            except:
                pass
        
        if RE_STAT_EXIT.search(data):
            props['stat'] = 'exit'

        if user_id_found:
            if user_id_found == self.service.unique_instance_id and port_found == self.service.port:
                return
            if addr[0].startswith('127.'):
                return
            self.service.on_found(user_id_found, addr[0], port_found, props)


class DiscoveryService:
    """
    Servicio de Alto Nivel para Descubrimiento de Pares.
    
    Adaptado para trabajar con QuicNetworkManager.
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
        self.network_manager: Optional[QuicNetworkManager] = None

    def set_network_manager(self, manager: QuicNetworkManager):
        """
        Vincula el servicio de descubrimiento con el gestor de red QUIC.
        
        Establece una referencia bidireccional para que el descubrimiento
        pueda actualizar las direcciones de los peers en el NetworkManager.
        
        Args:
            manager: Instancia de QuicNetworkManager.
        """
        self.network_manager = manager
        manager.discovery_service = self

    async def start(self, username, bind_ip=None):
        """Inicia el anuncio y la escucha."""
        self.loop = asyncio.get_running_loop()
        self.bind_ip = bind_ip
        clean_username = username.replace("User-", "")
        self.unique_instance_id = clean_username
        
        # Iniciar Sniffer
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except:
                pass
            sock.bind(('', 5353))
            
            self.sniffer_transport, self.sniffer_protocol = await self.loop.create_datagram_endpoint(
                lambda: RawSniffer(self), sock=sock
            )
            self.on_log("👂 Sniffer mDNS Activo")
        except Exception as e:
            self.on_log(f"⚠️ Fallo al iniciar Sniffer: {e}")

        # Iniciar Zeroconf
        interfaces = InterfaceChoice.All
        if bind_ip and bind_ip != "0.0.0.0":
            interfaces = [bind_ip]
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
        """Callback invocado por el Sniffer cuando detecta un par."""
        if self.on_found_callback:
            self.on_found_callback(user_id, ip, port, props)
        
        # Manejar desconexión voluntaria
        if props.get('stat') == 'exit':
            self.on_log(f"📴 Peer {user_id} anunció desconexión (stat=exit)")
            if self.network_manager:
                if user_id in self.network_manager.active_connections:
                    proto = self.network_manager.active_connections[user_id]
                    if proto.noise_session:
                        proto.noise_session.zeroize_session()
                    del self.network_manager.active_connections[user_id]
            return
        
        # Actualizar dirección IP en el NetworkManager
        if self.network_manager:
            try:
                pub_key_obj = None
                if 'pub' in props:
                    pub_bytes = bytes.fromhex(props['pub'])
                    pub_key_obj = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                
                self.network_manager.update_peer_location(user_id, (ip, port), pub_key_obj)
                
            except Exception:
                pass

    def broadcast_exit(self):
        """Envía manualmente un paquete mDNS 'stat=exit' para despedirse."""
        if not self.sniffer_transport:
            return
        try:
            fake_payload = (
                b'\x00' * 12 +
                b'_dni-im' +
                f'User-{self.unique_instance_id}_{self.port}'.encode('utf-8') +
                b'\x00fake\x00' +
                b'stat=exit'
            )
            self.sniffer_transport.sendto(fake_payload, ('224.0.0.251', 5353))
        except:
            pass

    async def stop(self):
        """Detiene el servicio de descubrimiento."""
        self.broadcast_exit()
        if hasattr(self, '_polling_task'):
            self._polling_task.cancel()
        if self.sniffer_transport:
            self.sniffer_transport.close()
        if hasattr(self, 'info') and hasattr(self, 'aiozc'):
            await self.aiozc.async_unregister_service(self.info)
        if hasattr(self, 'aiozc'):
            await self.aiozc.async_close()

    def get_local_ip(self):
        """Obtiene la IP local usada para conexiones externas."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    async def _active_polling_loop(self):
        """Monitoriza cambios de IP y mantiene viva la escucha."""
        while True:
            await asyncio.sleep(5)
            
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
                        try:
                            await self.aiozc.async_unregister_service(self.info)
                        except:
                            pass
                        try:
                            await self.aiozc.async_close()
                        except:
                            pass
                        
                        interfaces = [current_ip] if current_ip != "0.0.0.0" else InterfaceChoice.All
                        try:
                            self.aiozc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only)
                        except:
                            self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All)
                        
                        self.info.addresses = [current_ip_bytes]
                        await self.aiozc.async_register_service(self.info)
                        self.on_log(f"✅ Servicio mDNS reiniciado en {current_ip}")
                        
                        if self.sniffer_protocol:
                            self.sniffer_protocol.join_multicast_groups()
                        
                        if self.sniffer_transport:
                            for _ in range(3):
                                self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                                await asyncio.sleep(0.5)
                                
                    except Exception as e:
                        import traceback
                        self.on_log(f"⚠️ Error reiniciando mDNS: {type(e).__name__}: {e}")
            except:
                pass
            
            # Enviar query activa
            if self.sniffer_transport:
                try:
                    self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                except:
                    pass
