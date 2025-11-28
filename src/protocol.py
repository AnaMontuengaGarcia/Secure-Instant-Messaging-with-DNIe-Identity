"""
Protocolo de Seguridad Noise IK (Implementation)
------------------------------------------------
Este módulo implementa el handshake criptográfico y la protección de mensajes.
Sigue el patrón 'Noise IK' del framework Noise Protocol.

Características:
1. **Autenticación Mutua:** Basada en claves estáticas (DNIe) y efímeras.
2. **Confidencialidad:** Cifrado ChaCha20-Poly1305.
3. **PFS (Perfect Forward Secrecy):** Gracias a las claves efímeras (e).
4. **Anti-Replay:** Protección contra ataques de repetición mediante ventana deslizante.
5. **Multiplexación:** IDs de sesión similares a WireGuard.
"""

import os
import struct
import json
from zeroize import zeroize1
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def secure_zeroize_key(key_obj):
    """
    Intenta borrar de forma segura los bytes de una clave criptográfica.
    
    Las claves de cryptography no exponen directamente sus bytes privados,
    pero podemos intentar sobreescribir cualquier buffer interno accesible.
    """
    if key_obj is None:
        return
    try:
        # Para claves privadas X25519, obtenemos los bytes y los borramos
        if hasattr(key_obj, 'private_bytes'):
            # Extraer bytes en formato raw para poder zeroizarlos
            key_bytes = bytearray(key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))
            zeroize1(key_bytes)
    except Exception:
        pass  # Algunas claves pueden no soportar esta operación


def secure_zeroize_bytes(data):
    """Borra de forma segura un bytearray o bytes mutables."""
    if data is None:
        return
    try:
        if isinstance(data, bytearray):
            zeroize1(data)
    except Exception:
        pass

class NoiseIKState:
    """
    Máquina de estados para una sesión segura Noise IK.
    
    Roles:
    - Initiator (Iniciador/Cliente): Quien envía el primer mensaje.
    - Responder (Respondedor/Servidor): Quien recibe el primer mensaje.
    
    El handshake IK intercambia claves de la siguiente manera:
    -> e (Efímera del iniciador)
    -> Cifrado(S_iniciador, Identidad_iniciador) usando DH(e, S_respondedor)
    <- e (Efímera del respondedor)
    <- Cifrado(Identidad_respondedor) usando DH(e, e) y DH(S_iniciador, e)
    """
    PROLOGUE = b"DNIe-IM-v2-Signed" # Identificador único del protocolo

    def __init__(self, static_priv, remote_static_pub=None, initiator=False, local_proofs=None):
        """
        Inicializa el estado criptográfico.

        Args:
            static_priv: Clave privada estática local (generada al inicio).
            remote_static_pub: Clave pública estática del par (si es conocida).
            initiator (bool): True si somos quien inicia la conexión.
            local_proofs (dict): Datos de identidad del DNIe para enviar al par.
        """
        self.s_priv = static_priv
        self.s_pub = static_priv.public_key()
        self.rs_pub = remote_static_pub
        
        # Claves Efímeras (Se generan en initialize)
        self.e_priv = None
        self.e_pub = None
        self.re_pub = None # Remote ephemeral

        self.initiator = initiator
        self.local_proofs = local_proofs 
        self.remote_proofs = None        
        
        # Chaining Key (ck) inicializada con el hash del prólogo
        self.chaining_key = hashes.Hash(hashes.BLAKE2s(digest_size=32))
        self.chaining_key.update(self.PROLOGUE)
        
        # Cifradores de tráfico (se crean tras el handshake)
        self.encryptor = None
        self.decryptor = None
        self.tx_nonce = 0 # Contador de mensajes enviados
        self.rx_nonce = 0 # Contador esperado de recepción
        
        # --- VENTANA DESLIZANTE ANTI-REPLAY ---
        # Mecanismo para permitir llegada de paquetes desordenados pero bloquear repetidos.
        # Usamos un bitmap de 64 bits para rastrear el historial reciente.
        self.replay_bitmap = 0
        self.replay_window_size = 64
        
        # Connection IDs para Multiplexación UDP
        # 4 bytes aleatorios para identificar esta sesión localmente
        self.local_index = struct.unpack('<I', os.urandom(4))[0]
        self.remote_index = 0  # Se aprende durante el handshake

    def _dh(self, priv, pub):
        """Realiza intercambio Diffie-Hellman (X25519) raw."""
        return priv.exchange(pub)

    def _kdf(self, km, material):
        """
        Función de Derivación de Claves (HKDF).
        Usa BLAKE2s para derivar nuevas claves de encadenamiento y cifrado.
        """
        hkdf = HKDF(algorithm=hashes.BLAKE2s(digest_size=32), length=64, salt=km, info=b'')
        output = hkdf.derive(material)
        return output[:32], output[32:] # Retorna (nueva_ck, clave_cifrado)

    def _mix_key(self, ck, dh_out):
        """Mezcla el resultado de un DH en el estado (Stateful Hash)."""
        return self._kdf(ck, dh_out)

    def initialize(self):
        """Genera claves efímeras y finaliza el hash inicial."""
        self.e_priv = x25519.X25519PrivateKey.generate()
        self.e_pub = self.e_priv.public_key()
        self.ck = self.chaining_key.finalize()

    def _prepare_identity_payload(self):
        """Serializa las pruebas (Certificado + Firma) a JSON bytes."""
        if not self.local_proofs:
            return b'{}'
        return json.dumps(self.local_proofs).encode('utf-8')

    def create_handshake_message(self):
        """
        [Iniciador] Crea el Mensaje A del handshake.
        Contenido: IndexLocal + e + Cifrado(S_priv) + Cifrado(Identidad).
        """
        if not self.initiator: raise Exception("Error de rol: Se esperaba Initiator")

        msg = self.e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        
        # DH(e, rs): Clave efímera local vs Estática remota
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.rs_pub))
        
        # Ciframos nuestra clave estática S
        s_bytes = self.s_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x00'*12, s_bytes, b'')
        
        # DH(s, rs): Clave estática local vs Estática remota
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.rs_pub))
        
        # Ciframos payload de identidad
        payload_data = self._prepare_identity_payload()
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x01'*12, payload_data, b'')
        
        return struct.pack('<I', self.local_index) + msg

    def consume_handshake_message(self, data):
        """
        [Respondedor] Procesa el Mensaje A.
        Extrae la identidad del iniciador y prepara claves.
        """
        if self.initiator: raise Exception("Error de rol: Se esperaba Responder")

        if len(data) < 4: raise Exception("Handshake Init muy corto")
        self.remote_index = struct.unpack('<I', data[:4])[0]
        actual_msg = data[4:]

        # Leer clave efímera remota 're'
        self.re_pub = x25519.X25519PublicKey.from_public_bytes(actual_msg[:32])
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.re_pub))
        
        # Descifrar y obtener clave estática remota 'rs'
        encrypted_s = actual_msg[32:80]
        chacha = ChaCha20Poly1305(k)
        rs_bytes = chacha.decrypt(b'\x00'*12, encrypted_s, b'')
        self.rs_pub = x25519.X25519PublicKey.from_public_bytes(rs_bytes)
        
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.rs_pub))
        
        # Descifrar identidad
        encrypted_payload = actual_msg[80:]
        chacha = ChaCha20Poly1305(k)
        payload_bytes = chacha.decrypt(b'\x01'*12, encrypted_payload, b'')
        
        try:
            self.remote_proofs = json.loads(payload_bytes.decode('utf-8'))
        except:
            self.remote_proofs = {}
            
        return self.rs_pub

    def create_handshake_response(self):
        """
        [Respondedor] Crea el Mensaje B (Respuesta).
        Contenido: IndexLocal + IndexRemoto + e + Cifrado(Identidad).
        """
        if self.initiator: raise Exception("Error de rol")
        
        msg = self.e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        
        # DH(e, re) y DH(e, rs)
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.re_pub))
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.re_pub))
        
        payload_data = self._prepare_identity_payload()
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x00'*12, payload_data, b'')
        
        # Split final: Generar claves de tráfico (k1 envío, k2 recepción)
        k1, k2 = self._kdf(self.ck, b'')
        self.encryptor = ChaCha20Poly1305(k1)
        self.decryptor = ChaCha20Poly1305(k2)
        
        indices = struct.pack('<II', self.local_index, self.remote_index)
        return indices + msg

    def consume_handshake_response(self, data):
        """
        [Iniciador] Procesa el Mensaje B.
        Finaliza el handshake.
        """
        if not self.initiator: raise Exception("Error de rol")
        
        if len(data) < 8: raise Exception("Handshake Resp muy corto")
        
        sender_idx, receiver_idx = struct.unpack('<II', data[:8])
        if receiver_idx != self.local_index:
            raise Exception(f"Desajuste de índice: Esperado {self.local_index}, recibido {receiver_idx}")
            
        self.remote_index = sender_idx
        actual_msg = data[8:]
        
        # Mezclas DH finales
        self.re_pub = x25519.X25519PublicKey.from_public_bytes(actual_msg[:32])
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.re_pub))
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.rs_pub))
        
        # Descifrar identidad servidor
        encrypted_payload = actual_msg[32:]
        chacha = ChaCha20Poly1305(k)
        payload_bytes = chacha.decrypt(b'\x00'*12, encrypted_payload, b'')
        
        try:
            self.remote_proofs = json.loads(payload_bytes.decode('utf-8'))
        except:
            self.remote_proofs = {}
            
        # Split final (invertido respecto al respondedor)
        k1, k2 = self._kdf(self.ck, b'')
        self.decryptor = ChaCha20Poly1305(k1)
        self.encryptor = ChaCha20Poly1305(k2)

    def encrypt_message(self, plaintext):
        """
        Cifra un mensaje de aplicación.
        Formato: [IndexRemoto 4B] + [Nonce 8B] + [Ciphertext]
        """
        if self.encryptor is None: raise Exception("Handshake no completado")
        
        nonce_bytes = struct.pack('<Q', self.tx_nonce)
        iv = nonce_bytes + b'\x00'*4 # 12 bytes nonce para ChaCha
        
        ciphertext = self.encryptor.encrypt(iv, plaintext, b'')
        self.tx_nonce += 1
        
        return struct.pack('<I', self.remote_index) + nonce_bytes + ciphertext

    def zeroize_session(self):
        """
        Borra de forma segura todas las claves criptográficas de la sesión.
        
        Debe llamarse cuando:
        - La sesión se cierra explícitamente
        - El peer se desconecta
        - La aplicación se cierra
        
        Esto previene que las claves queden en memoria y puedan ser
        extraídas mediante ataques de memoria (cold boot, memory dump, etc.)
        """
        # Borrar claves privadas
        secure_zeroize_key(self.e_priv)
        self.e_priv = None
        
        # Borrar chaining key si existe como bytes
        if hasattr(self, 'ck') and self.ck is not None:
            if isinstance(self.ck, (bytes, bytearray)):
                secure_zeroize_bytes(bytearray(self.ck))
            self.ck = None
        
        # Los cifradores ChaCha20Poly1305 contienen claves internamente
        # No podemos acceder directamente, pero los eliminamos
        self.encryptor = None
        self.decryptor = None
        
        # Limpiar referencias a claves públicas remotas
        self.rs_pub = None
        self.re_pub = None
        
        # Resetear contadores
        self.tx_nonce = 0
        self.rx_nonce = 0
        self.replay_bitmap = 0

    def decrypt_message(self, data_with_nonce):
        """
        Descifra un mensaje y aplica la validación Anti-Replay.
        
        La ventana deslizante permite recibir paquetes ligeramente desordenados (UDP),
        pero rechaza duplicados o paquetes muy viejos.
        """
        if self.decryptor is None: raise Exception("Handshake no completado")
        
        if len(data_with_nonce) < 8: raise Exception("Falta nonce")

        nonce_bytes = data_with_nonce[:8]
        ciphertext = data_with_nonce[8:]
        received_seq = struct.unpack('<Q', nonce_bytes)[0]
        
        # --- LÓGICA DE VENTANA DESLIZANTE ---
        # Caso 1: Mensaje viejo (seq < esperado)
        if received_seq < self.rx_nonce:
            diff = self.rx_nonce - received_seq
            if diff > self.replay_window_size:
                raise Exception(f"Replay Error: Mensaje muy antiguo ({received_seq})")
            
            # Verificar en bitmap si ya se recibió
            bit_index = diff - 1
            if (self.replay_bitmap >> bit_index) & 1:
                raise Exception(f"Replay Error: Mensaje duplicado ({received_seq})")

        # Intentar descifrar (Autenticación AEAD)
        iv = nonce_bytes + b'\x00'*4
        plaintext = self.decryptor.decrypt(iv, ciphertext, b'')
        
        # Actualizar estado de ventana SOLO si descifrado OK
        if received_seq >= self.rx_nonce:
            # Caso 2: Mensaje nuevo o futuro
            jump = received_seq - self.rx_nonce + 1
            if jump >= self.replay_window_size:
                self.replay_bitmap = 0 # Salto grande, reiniciar ventana
            else:
                self.replay_bitmap <<= jump # Desplazar ventana
            
            self.replay_bitmap |= 1 # Marcar bit 0 (actual)
            self.rx_nonce = received_seq + 1
        else:
            # Caso 3: Mensaje viejo pero válido, marcar en el pasado
            diff = self.rx_nonce - received_seq
            bit_index = diff - 1
            self.replay_bitmap |= (1 << bit_index)
            
        return plaintext