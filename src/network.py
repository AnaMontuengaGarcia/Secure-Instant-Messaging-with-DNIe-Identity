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
from datetime import datetime, timezone
from zeroconf import ServiceInfo, IPVersion, Zeroconf, InterfaceChoice, DNSIncoming
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from protocol import NoiseIKState
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


# =============================================================================
# CONSTANTES Y CONFIGURACIÓN GLOBAL
# =============================================================================
MDNS_TYPE = "_dni-im._udp.local."   # Identificador del servicio en la red local
# Paquete mDNS crudo para solicitar servicios (Query ANY)
RAW_MDNS_QUERY = (
    b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x07_dni-im\x04_udp\x05local\x00'
    b'\x00\x0c'
    b'\x00\x01'
)
TRUSTED_CERTS_DIR = "certs"

def load_trusted_cas():
    """
    Carga los certificados CA (Autoridades de Certificación) desde el disco.
    Estos son necesarios para validar que un DNIe es legítimo (emitido por la Policía).
    """
    trusted_cas = []
    if not os.path.exists(TRUSTED_CERTS_DIR):
        print(f"⚠️ Warning: '{TRUSTED_CERTS_DIR}' directory not found. No Chain of Trust verification possible.")
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

<<<<<<< HEAD
# Cache global para evitar lectura de disco en cada handshake
=======
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
GLOBAL_TRUST_STORE = load_trusted_cas()

# =============================================================================
# LÓGICA DE VERIFICACIÓN DE IDENTIDAD (DNIe)
# =============================================================================

def get_common_name(cert):
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return "Unknown Common Name"

def verify_peer_identity(x25519_pub_key, proofs):
<<<<<<< HEAD
    """
    Verifica criptográficamente la identidad de un peer remoto.
    
    Args:
        x25519_pub_key: La clave pública efímera de chat del usuario.
        proofs: Diccionario con 'cert' (DNIe público) y 'sig' (firma de la clave efímera).
        
    Retorna:
        (real_name, issuer_name) si es válido. Lanza excepción si no.
    """
=======
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
    if not proofs or 'cert' not in proofs or 'sig' not in proofs:
        raise Exception("No identity proofs provided by peer")

    try:
<<<<<<< HEAD
        # --- 0. Carga de datos, decodificación ---
=======
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
        cert_bytes = bytes.fromhex(proofs['cert'])
        signature_bytes = bytes.fromhex(proofs['sig'])
        peer_cert = x509.load_der_x509_certificate(cert_bytes)
        rsa_pub_key = peer_cert.public_key()    # Clave pública RSA del DNIe

<<<<<<< HEAD

        # --- 1. Validación de Fechas (UTC) (Vigencia del DNIe) ---
=======
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
        now = datetime.now(timezone.utc)
        if now < peer_cert.not_valid_before_utc:
            raise Exception("Certificate is NOT YET valid")
        if now > peer_cert.not_valid_after_utc:
            raise Exception("Certificate has EXPIRED")

<<<<<<< HEAD
        # --- 2. Validación de Key Usage ---
        # Verificamos que el cert sirva para firmar o no repudio (autenticación)
=======
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
        try:
            key_usage_ext = peer_cert.extensions.get_extension_for_class(x509.KeyUsage)
            usage = key_usage_ext.value
            if not (usage.digital_signature or usage.content_commitment):
                raise Exception("Certificate not allowed for Digital Signature/Authentication")
        except x509.ExtensionNotFound:
            pass

<<<<<<< HEAD
        # --- 3. Validación de Cadena de Confianza (Chain of Trust) ---
        # Verificamos si el certificado fue firmado por una CA en nuestra carpeta 'certs'
=======
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
        issuer_name = "Unknown CA (No Verification)"
        is_trusted = False
        
        if not GLOBAL_TRUST_STORE:
             print("⚠️  SECURITY WARNING: No CA certificates found. Skipping Chain of Trust check.")
             issuer_name = "UNTRUSTED/NO-STORE"
             is_trusted = True  # Permitimos continuar inseguro si no hay CAs cargadas
        else:
            for ca_cert in GLOBAL_TRUST_STORE:
                try:
                    ca_public_key = ca_cert.public_key()
                    # Verificación matemática de la firma del certificado
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

<<<<<<< HEAD
        # --- 4. Prueba de Posesión (Proof of Possession) ---
        # CRUCIAL: Verificamos que la firma enviada ('sig') coincide con la clave de chat ('x25519').
        # Esto prueba que quien envió la clave de chat POSEE la tarjeta DNIe correspondiente.
=======
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
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

# =============================================================================
# GESTIÓN DE SESIONES (Noise Protocol)
# =============================================================================
class SessionManager:
    def __init__(self, local_static_key, db, local_proofs):
        self.local_static_key = local_static_key    # Nuestras credenciales (Cert + Firma)
        self.local_proofs = local_proofs    # Diccionario {addr: SessionObject}
        self.sessions = {}
        self.db = db
        self.transport = None

    def get_session(self, addr):
        return self.sessions.get(addr)

    def create_initiator_session(self, addr, remote_pub_key):
        """Crea una sesión cuando NOSOTROS iniciamos la conversación."""
        session = NoiseIKState(
            self.local_static_key, 
            remote_pub_key, 
            initiator=True,
            local_proofs=self.local_proofs
        )
        session.initialize()
        self.sessions[addr] = session
        return session

    def create_responder_session(self, addr):
        """Crea una sesión cuando OTRO inicia la conversación con nosotros."""
        session = NoiseIKState(
            self.local_static_key, 
            initiator=False,
            local_proofs=self.local_proofs
        )
        session.initialize()
        self.sessions[addr] = session
        return session

# =============================================================================
# PROTOCOLO UDP (Capa de transporte)
# =============================================================================
class UDPProtocol(asyncio.DatagramProtocol):
    """
    Maneja el envío y recepción de paquetes UDP.
    Tipos de paquete:
    - 0x01: Handshake Init
    - 0x02: Handshake Response
    - 0x03: Mensaje de Datos (Cifrado)
    """
    def __init__(self, session_manager, on_message_received, on_log, on_handshake_success=None):
        self.sessions = session_manager
        self.on_message = on_message_received   # Callback para entregar mensaje a la UI
        self.on_log = on_log
        self.on_handshake_success = on_handshake_success
        self.transport = None
        self.pending_messages = {}  # Cola de mensajes esperando handshake

    def connection_made(self, transport):
        self.transport = transport
        self.sessions.transport = transport
        try:
            sock = transport.get_extra_info('socket')
            addr = sock.getsockname()
            self.on_log(f"✅ UDP Bound to {addr[0]}:{addr[1]}")
        except: pass

    def datagram_received(self, data, addr):
        """Enrutador principal de paquetes entrantes."""
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
        """Recibimos solicitud de conexión. Verificamos identidad y respondemos."""
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
            
            # Generar y enviar respuesta
            resp_data = session.create_handshake_response()
            self.transport.sendto(b'\x02' + resp_data, addr)
            self.on_log(f"🤝 Handshake Response sent to {addr}")
            
            # Registrar contacto en DB
            asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], remote_pub, real_name=real_name))
            
            if self.on_handshake_success:
                self.on_handshake_success(addr, remote_pub, real_name)
                
        except Exception as e:
            self.on_log(f"❌ Handshake failed: {e}")
            if addr in self.sessions.sessions: del self.sessions.sessions[addr]

    def handle_handshake_resp(self, data, addr):
        """Recibimos respuesta al handshake que iniciamos nosotros."""
        session = self.sessions.get_session(addr)
        if not session: return
        try:
            session.consume_handshake_response(data)
            try:
                real_name, issuer = verify_peer_identity(session.rs_pub, session.remote_proofs)
                self.on_log(f"✅ Verified Identity: {real_name}")
                self.on_log(f"   ↳ Signed by: {issuer}")
                
                asyncio.create_task(self.sessions.db.register_contact(addr[0], addr[1], session.rs_pub, real_name=real_name))
            except Exception as e:
                self.on_log(f"⛔ SECURITY ALERT: {e}")
                del self.sessions.sessions[addr]
                return

            self.on_log(f"🔒 Secure Session established with {real_name}")
            
            if self.on_handshake_success:
                self.on_handshake_success(addr, session.rs_pub, real_name)

            # Enviar mensajes que estaban en cola
            if addr in self.pending_messages:
                for content in self.pending_messages[addr]:
                    asyncio.create_task(self.send_message(addr, content))
                del self.pending_messages[addr]

        except Exception as e:
            self.on_log(f"❌ Handshake completion failed: {e}")

    def handle_data(self, data, addr):
        """Recibimos mensaje cifrado de chat."""
        session = self.sessions.get_session(addr)
        if not session: return
        try:
            plaintext = session.decrypt_message(data)
            msg_struct = json.loads(plaintext.decode('utf-8'))
            self.on_message(addr, msg_struct)
        except Exception as e:
            self.on_log(f"❌ Decryption failed: {e}")

    def _queue_message(self, addr, content):
        """Encola mensajes si no hay sesión activa."""
        if addr not in self.pending_messages:
            self.pending_messages[addr] = []
        self.pending_messages[addr].append(content)
        self.on_log(f"⏳ Message queued...")

<<<<<<< HEAD
    async def send_message(self, addr, content):
        """Intenta enviar un mensaje. Inicia handshake si es necesario."""
        session = self.sessions.get_session(addr)

        # Si no hay sesión, buscar clave pública e iniciar handshake
=======
    async def broadcast_disconnect(self):
        """Envía un mensaje de desconexión cifrado a todas las sesiones activas."""
        self.on_log("📡 Sending encrypted disconnect to active chats...")
        # Copia de las claves para iteración segura
        active_addresses = list(self.sessions.sessions.keys())
        
        tasks = []
        for addr in active_addresses:
            tasks.append(self.send_message(addr, content=None, is_disconnect=True))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_message(self, addr, content, is_disconnect=False):
        session = self.sessions.get_session(addr)
        
        # Si nos estamos desconectando y no hay sesión, no la creamos ahora
        if not session and is_disconnect:
            return

>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
        if not session:
            remote_pub = await self.sessions.db.get_pubkey_by_addr(addr[0], addr[1])
            if not remote_pub:
                self.on_log(f"❌ Cannot send: No public key for {addr}")
                return
            
            session = self.sessions.create_initiator_session(addr, remote_pub)
            hs_msg = session.create_handshake_message()
            self.transport.sendto(b'\x01' + hs_msg, addr)
            self.on_log(f"🔄 Initiating handshake with {addr}")
            if content:
                self._queue_message(addr, content)
            return
        
        # Si el handshake no ha terminado (encryptor no listo)
        if session.encryptor is None:
            if content:
                self._queue_message(addr, content)
            return

        # Enviar mensaje cifrado
        try:
            # Construcción del payload: Texto normal o señal de desconexión
            if is_disconnect:
                msg_struct = {
                    "timestamp": time.time(),
                    "disconnect": True
                }
            else:
                msg_struct = {
                    "timestamp": time.time(), 
                    "text": content
                }
            
            payload = json.dumps(msg_struct).encode('utf-8')
            ciphertext = session.encrypt_message(payload)
            self.transport.sendto(b'\x03' + ciphertext, addr)
        except Exception as e:
            self.on_log(f"❌ Send failed: {e}")

# =============================================================================
# DESCUBRIMIENTO DE SERVICIOS (mDNS / Zeroconf)
# =============================================================================
class RawSniffer(asyncio.DatagramProtocol):
    """
    Escucha paquetes mDNS crudos (Multicast UDP 5353).
    Necesario porque a veces las librerías de alto nivel omiten ciertos campos
    o para detectar anuncios en tiempo real de forma más agresiva.
    """
    def __init__(self, service):
        self.service = service

    def connection_made(self, transport):
        # Configuración de bajo nivel del socket Multicast
        self.transport = transport
        sock = transport.get_extra_info('socket')
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except: pass

        # Unirse al grupo Multicast 224.0.0.251
        group = socket.inet_aton('224.0.0.251')
        try:
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except: pass

        # Escuchar en todas las interfaces de red
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
<<<<<<< HEAD
        """Analiza paquetes mDNS entrantes buscando nuestro servicio '_dni-im'."""
=======
        # Filtro básico: Debe contener el identificador del protocolo
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
        if b"_dni-im" not in data: return
        
        try:
            found_info = None
<<<<<<< HEAD
            # Intenta parseo por Regex (rápido y sucio)
=======
            # 1. Intentar Regex simple para User-ID_Port
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
            try:
                match = re.search(rb'User-([^_\x00]+)_(\d+)', data)
                if match:
                    name = match.group(1).decode('utf-8', errors='ignore')
                    port = int(match.group(2).decode('utf-8'))
                    found_info = (name, port)
            except: pass

<<<<<<< HEAD
            # Si regex falla, intenta parseo DNS real
=======
            # 2. Intentar parsing completo DNS si regex falla
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
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
<<<<<<< HEAD
                # Ignorarnos a nosotros mismos
                if user_id_from_net == self.service.unique_instance_id:
                    return

                props = {'user': user_id_from_net}

                # Extraer clave pública del peer del paquete TXT
=======
                
                # Ignorar paquetes propios
                if user_id_from_net == self.service.unique_instance_id and port == self.service.port:
                    return

                props = {'user': user_id_from_net}
                
                # --- DETECCIÓN DE MENSAJE DE SALIDA CUSTOM (stat=exit) ---
                # Esta es nuestra "propia implementación" de mDNS goodbye.
                # Si encontramos 'stat=exit' en los bytes crudos, es una desconexión explícita.
                is_exit_msg = re.search(rb'stat=exit', data)
                if is_exit_msg:
                    props['stat'] = 'exit'
                    # Pasamos directamente al callback, no necesitamos la clave pública para desconectar
                    self.service.on_found(user_id_from_net, addr[0], port, props)
                    return
                # ---------------------------------------------------------

                # Si NO es un mensaje de salida, exigimos la clave pública
>>>>>>> daf96701fab225e13f2f706fd8896b1a6bf7c6af
                try:
                    pub_match = re.search(rb'pub=([a-fA-F0-9]+)', data)
                    if pub_match:
                        pub_str = pub_match.group(1).decode('utf-8')
                        if len(pub_str) != 64: return 
                        props['pub'] = pub_str
                    else:
                        return # Sin clave pública y sin stat=exit, ignoramos.
                except: return
                
                # Intentar sacar usuario del TXT si existe
                try:
                    user_match = re.search(rb'user=([^\x00]+)', data)
                    if user_match:
                        clean_user = user_match.group(1).decode('utf-8')
                        props['user'] = clean_user
                except: pass

                # Notificar al DiscoveryService
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
        self.bind_ip = None
        self.unique_instance_id = None 

    async def start(self, username, bind_ip=None):
        self.loop = asyncio.get_running_loop()
        self.bind_ip = bind_ip
        
        # Generar ID único para esta sesión de mDNS
        clean_username = username.replace("User-", "")
        self.unique_instance_id = clean_username
        
        # Iniciar Sniffer (Escucha pasiva)
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

        # Iniciar Zeroconf (Anuncio activo)
        interfaces = InterfaceChoice.All
        if bind_ip and bind_ip != "0.0.0.0": interfaces = [bind_ip]
        try:
            self.aiozc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only)
        except:
            self.aiozc = AsyncZeroconf(interfaces=InterfaceChoice.All)

        local_ip = bind_ip if (bind_ip and bind_ip != "0.0.0.0") else self.get_local_ip()
        service_name = f"User-{self.unique_instance_id}_{self.port}.{MDNS_TYPE}"
        
        # Propiedades TXT del registro mDNS (Clave pública + Usuario)
        desc = {'pub': self.pubkey_b64, 'user': clean_username}
        self.info = ServiceInfo(
            MDNS_TYPE, service_name, addresses=[socket.inet_aton(local_ip)],
            port=self.port, properties=desc, server=f"{socket.gethostname()}.local."
        )
        
        self.on_log(f"📢 Advertising: {service_name} @ {local_ip}")
        await self.aiozc.async_register_service(self.info)
        
        # Tarea de fondo para sondear la red periódicamente
        self._polling_task = asyncio.create_task(self._active_polling_loop())

    def broadcast_exit(self):
        """
        Envía un paquete UDP crudo al grupo multicast mDNS (224.0.0.251:5353)
        que contiene una estructura reconocible por nuestro sniffer con la flag 'stat=exit'.
        Esto fuerza a todos los clientes (incluso los que no tienen sesión activa)
        a marcarnos como Offline inmediatamente.
        """
        if not self.sniffer_transport: return
        
        try:
            # Construimos un paquete "Fake mDNS" que satisface las regex del RawSniffer
            # Contiene: _dni-im, User-{id}_{port} y el payload personalizado stat=exit
            # Rellenamos con nulos al principio para simular cabecera DNS
            
            fake_payload = (
                b'\x00' * 12 +     # Cabecera DNS falsa
                b'_dni-im' +       # Protocolo
                f'User-{self.unique_instance_id}_{self.port}'.encode('utf-8') + # Identificador
                b'\x00fake\x00' +  # Relleno
                b'stat=exit'       # Nuestra flag personalizada de desconexión
            )
            
            # Enviar al grupo multicast
            self.sniffer_transport.sendto(fake_payload, ('224.0.0.251', 5353))
            self.on_log("📡 Broadcasted custom 'stat=exit' mDNS packet.")
            
        except Exception as e:
            print(f"Error broadcasting exit: {e}")

    async def stop(self):
        # 1. Enviar nuestra señal de desconexión personalizada
        self.broadcast_exit()
        
        if hasattr(self, '_polling_task'): self._polling_task.cancel()
        if self.sniffer_transport: self.sniffer_transport.close()
        if hasattr(self, 'info') and hasattr(self, 'aiozc'): 
            await self.aiozc.async_unregister_service(self.info)
        if hasattr(self, 'aiozc'): await self.aiozc.async_close()

    def refresh(self):
        """Envía una consulta mDNS manual para redescubrir peers."""
        if self.sniffer_transport:
             try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
             except: pass

    async def _active_polling_loop(self):
        """Envía paquetes de query cada 5s para mantener la lista de vecinos actualizada."""
        while True:
            await asyncio.sleep(5)
            if self.sniffer_transport:
                 try: self.sniffer_transport.sendto(RAW_MDNS_QUERY, ('224.0.0.251', 5353))
                 except: pass

    def get_local_ip(self):
        """Intenta determinar la IP local principal conectándose a Google DNS."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 80)); IP = s.getsockname()[0]
        except: IP = '127.0.0.1'
        finally: s.close()
        return IP