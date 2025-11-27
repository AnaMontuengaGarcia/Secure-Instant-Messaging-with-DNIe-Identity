import os
import struct
import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class NoiseIKState:
    """
    Protocolo Noise IK con Carga Útil de Identidad DNIe.
    Implementa Multiplexación (Connection IDs tipo WireGuard) y hash BLAKE2s.
    Proporciona confidencialidad, autenticación mutua y protección contra repetición.
    """
    PROLOGUE = b"DNIe-IM-v2-Signed"

    def __init__(self, static_priv, remote_static_pub=None, initiator=False, local_proofs=None):
        """
        Inicializa el estado del protocolo criptográfico.
        
        Cómo lo hace:
        Configura las claves estáticas locales, el rol (iniciador/respondedor)
        y pre-calcula el 'chaining_key' inicial usando el prólogo del protocolo.
        """
        self.s_priv = static_priv
        self.s_pub = static_priv.public_key()
        self.rs_pub = remote_static_pub
        
        self.e_priv = None
        self.e_pub = None
        self.re_pub = None

        self.initiator = initiator
        self.local_proofs = local_proofs 
        self.remote_proofs = None        
        
        self.chaining_key = hashes.Hash(hashes.BLAKE2s(digest_size=32))
        self.chaining_key.update(self.PROLOGUE)
        
        self.encryptor = None
        self.decryptor = None
        self.tx_nonce = 0
        self.rx_nonce = 0
        
        # --- VENTANA DESLIZANTE ANTI-REPLAY ---
        # Bitmap de 64 bits para rastrear paquetes recibidos en la ventana actual.
        # rx_nonce actuará como el "Próximo Secuencial Esperado" (Más alto visto + 1).
        self.replay_bitmap = 0
        self.replay_window_size = 64
        
        # Connection IDs para Multiplexación
        # Generamos un identificador local aleatorio de 4 bytes (32-bit int)
        self.local_index = struct.unpack('<I', os.urandom(4))[0]
        self.remote_index = 0  # Se aprende durante el handshake

    def _dh(self, priv, pub):
        """
        Realiza el intercambio de claves Diffie-Hellman (X25519).
        """
        return priv.exchange(pub)

    def _kdf(self, km, material):
        """
        Función de Derivación de Claves (HKDF).
        
        Cómo lo hace:
        Usa BLAKE2s como función hash subyacente para derivar dos claves nuevas
        a partir del material de entrada y la 'chaining key' actual.
        """
        hkdf = HKDF(algorithm=hashes.BLAKE2s(digest_size=32), length=64, salt=km, info=b'')
        output = hkdf.derive(material)
        return output[:32], output[32:]

    def _mix_key(self, ck, dh_out):
        """
        Mezcla el resultado de un DH en la cadena de claves actual (Stateful Hash).
        """
        return self._kdf(ck, dh_out)

    def initialize(self):
        """
        Prepara el estado para iniciar la conexión.
        
        Cómo lo hace:
        Genera un par de claves efímeras (e_priv, e_pub) para esta sesión
        y finaliza el cálculo inicial del chaining_key.
        """
        self.e_priv = x25519.X25519PrivateKey.generate()
        self.e_pub = self.e_priv.public_key()
        self.ck = self.chaining_key.finalize()

    def _prepare_identity_payload(self):
        """
        Serializa las pruebas de identidad local (certificado + firma).
        """
        if not self.local_proofs:
            return b'{}'
        return json.dumps(self.local_proofs).encode('utf-8')

    def create_handshake_message(self):
        """
        Genera el mensaje inicial del Handshake (Tipo 1).
        
        Cómo lo hace (Noise IK Pattern):
        1. Envía la clave pública efímera (e).
        2. Realiza DH(e, rs) y cifra la clave estática local (s).
        3. Realiza DH(s, rs) y cifra el payload de identidad.
        4. Retorna: [ÍndiceLocal] + [e] + [Cifrado S] + [Cifrado Identidad]
        """
        if not self.initiator: raise Exception("Error de rol")

        msg = self.e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.rs_pub))
        
        s_bytes = self.s_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x00'*12, s_bytes, b'')
        
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.rs_pub))
        
        payload_data = self._prepare_identity_payload()
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x01'*12, payload_data, b'')
        
        return struct.pack('<I', self.local_index) + msg

    def consume_handshake_message(self, data):
        """
        Procesa el mensaje inicial de Handshake recibido.
        
        Cómo lo hace:
        1. Extrae el índice del remitente remoto.
        2. Lee la clave efímera remota (re).
        3. Descifra la clave estática remota (rs).
        4. Descifra el payload de identidad y extrae las pruebas.
        5. Actualiza el estado de claves criptográficas.
        """
        if self.initiator: raise Exception("Error de rol")

        if len(data) < 4: raise Exception("Handshake Init muy corto")
        self.remote_index = struct.unpack('<I', data[:4])[0]
        actual_msg = data[4:]

        self.re_pub = x25519.X25519PublicKey.from_public_bytes(actual_msg[:32])
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.re_pub))
        
        encrypted_s = actual_msg[32:80]
        chacha = ChaCha20Poly1305(k)
        rs_bytes = chacha.decrypt(b'\x00'*12, encrypted_s, b'')
        self.rs_pub = x25519.X25519PublicKey.from_public_bytes(rs_bytes)
        
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.rs_pub))
        
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
        Genera la respuesta del Handshake (Tipo 2).
        
        Cómo lo hace:
        1. Envía la clave efímera (e).
        2. Realiza DH(e, re) y DH(e, rs).
        3. Cifra el payload de identidad local.
        4. Deriva las claves finales de tráfico (k1, k2).
        5. Retorna: [ÍndiceLocal] + [ÍndiceRemoto] + [e] + [Cifrado Identidad]
        """
        if self.initiator: raise Exception("Error de rol")
        
        msg = self.e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.re_pub))
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.re_pub))
        
        payload_data = self._prepare_identity_payload()
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x00'*12, payload_data, b'')
        
        k1, k2 = self._kdf(self.ck, b'')
        self.encryptor = ChaCha20Poly1305(k1)
        self.decryptor = ChaCha20Poly1305(k2)
        
        indices = struct.pack('<II', self.local_index, self.remote_index)
        return indices + msg

    def consume_handshake_response(self, data):
        """
        Procesa la respuesta del Handshake recibida.
        
        Cómo lo hace:
        1. Valida los índices de sesión.
        2. Lee la clave efímera remota (re).
        3. Realiza las mezclas DH restantes.
        4. Descifra el payload de identidad del servidor.
        5. Deriva las claves finales de tráfico (Traffic Keys).
        """
        if not self.initiator: raise Exception("Error de rol")
        
        if len(data) < 8: raise Exception("Handshake Resp muy corto")
        
        sender_idx, receiver_idx = struct.unpack('<II', data[:8])
        
        if receiver_idx != self.local_index:
            raise Exception(f"Desajuste de índice: Esperado {self.local_index}, recibido {receiver_idx}")
            
        self.remote_index = sender_idx
        actual_msg = data[8:]
        
        self.re_pub = x25519.X25519PublicKey.from_public_bytes(actual_msg[:32])
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.re_pub))
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.rs_pub))
        
        encrypted_payload = actual_msg[32:]
        chacha = ChaCha20Poly1305(k)
        payload_bytes = chacha.decrypt(b'\x00'*12, encrypted_payload, b'')
        
        try:
            self.remote_proofs = json.loads(payload_bytes.decode('utf-8'))
        except:
            self.remote_proofs = {}
            
        k1, k2 = self._kdf(self.ck, b'')
        self.decryptor = ChaCha20Poly1305(k1)
        self.encryptor = ChaCha20Poly1305(k2)

    def encrypt_message(self, plaintext):
        """
        Cifra un mensaje de datos usando las claves de tráfico.
        
        Cómo lo hace:
        1. Usa un nonce incremental (tx_nonce).
        2. Cifra con ChaCha20Poly1305.
        3. Retorna: [ÍndiceRemoto] + [Nonce (8B)] + [Texto Cifrado]
        """
        if self.encryptor is None:
            raise Exception("Handshake no completado")
        
        nonce_bytes = struct.pack('<Q', self.tx_nonce)
        iv = nonce_bytes + b'\x00'*4
        
        ciphertext = self.encryptor.encrypt(iv, plaintext, b'')
        self.tx_nonce += 1
        
        return struct.pack('<I', self.remote_index) + nonce_bytes + ciphertext

    def decrypt_message(self, data_with_nonce):
        """
        Descifra un mensaje y aplica protección contra ataques de repetición (Replay).
        
        Cómo lo hace:
        1. Extrae el nonce del paquete recibido.
        2. Comprueba si el nonce es válido usando una Ventana Deslizante (Bitmap).
           - Si el nonce es demasiado antiguo (fuera de ventana), lo rechaza.
           - Si el nonce ya está marcado en el bitmap, lo rechaza.
        3. Si pasa el chequeo, intenta descifrar el contenido.
        4. Si el descifrado es correcto, actualiza la ventana deslizante.
        """
        if self.decryptor is None:
            raise Exception("Handshake no completado")
        
        if len(data_with_nonce) < 8:
            raise Exception("Mensaje muy corto (falta nonce)")

        nonce_bytes = data_with_nonce[:8]
        ciphertext = data_with_nonce[8:]
        received_seq = struct.unpack('<Q', nonce_bytes)[0]
        
        # Validación Anti-Replay
        if received_seq < self.rx_nonce:
            diff = self.rx_nonce - received_seq
            if diff > self.replay_window_size:
                raise Exception(f"Error de Replay: Mensaje muy antiguo (seq {received_seq} < {self.rx_nonce - self.replay_window_size})")
            
            bit_index = diff - 1
            if (self.replay_bitmap >> bit_index) & 1:
                raise Exception(f"Error de Replay: Mensaje {received_seq} ya procesado")

        iv = nonce_bytes + b'\x00'*4
        plaintext = self.decryptor.decrypt(iv, ciphertext, b'')
        
        # Actualización de estado (solo si el descifrado fue exitoso)
        if received_seq >= self.rx_nonce:
            jump = received_seq - self.rx_nonce + 1
            if jump >= self.replay_window_size:
                self.replay_bitmap = 0
            else:
                self.replay_bitmap <<= jump
            self.replay_bitmap |= 1
            self.rx_nonce = received_seq + 1
        else:
            diff = self.rx_nonce - received_seq
            bit_index = diff - 1
            self.replay_bitmap |= (1 << bit_index)
            
        return plaintext