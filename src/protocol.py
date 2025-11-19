import os
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class NoiseIKState:
    """
    Implementación simplificada del protocolo Noise IK (Initiator Knows Responder).
    
    Pattern:
    <- s (Pre-conocido vía mDNS/TOFU)
    ...
    -> e, es, s, ss (Msg A)
    <- e, ee, se    (Msg B)
    
    Transport:
    -> Data
    <- Data
    """
    PROLOGUE = b"DNIe-IM-v1"

    def __init__(self, static_priv, remote_static_pub=None, initiator=False):
        self.s_priv = static_priv  # Mi clave estática privada
        self.s_pub = static_priv.public_key() # Mi clave estática pública
        self.rs_pub = remote_static_pub # Clave estática pública del remoto (Known for Initiator)
        
        self.e_priv = None # Mi clave efímera
        self.e_pub = None
        self.re_pub = None # Clave efímera del remoto

        self.initiator = initiator
        self.chaining_key = hashes.Hash(hashes.SHA256())
        self.chaining_key.update(self.PROLOGUE)
        
        # CipherStates
        self.encryptor = None
        self.decryptor = None
        
        # Nonces para fase de transporte
        self.tx_nonce = 0
        self.rx_nonce = 0

    def _dh(self, priv, pub):
        """Diffie-Hellman X25519"""
        shared = priv.exchange(pub)
        return shared

    def _kdf(self, km, material):
        """HKDF para derivar nuevas claves"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=km,
            info=b'',
        )
        output = hkdf.derive(material)
        return output[:32], output[32:] # new_ck, k

    def _mix_key(self, ck, dh_out):
        ck, k = self._kdf(ck, dh_out)
        return ck, k

    def _rekey(self, k):
        """Rotación de claves (opcional, simple implementación)"""
        return k 

    def initialize(self):
        """Genera claves efímeras"""
        self.e_priv = x25519.X25519PrivateKey.generate()
        self.e_pub = self.e_priv.public_key()
        
        # Inicializar Chaining Key con el hash del prólogo y claves pre-conocidas
        # En IK, el initiator conoce rs_pub. Hash rs_pub into prologue/h.
        # Simplificación: Usamos un HKDF inicial con el prólogo.
        digest = self.chaining_key.finalize() # Snapshot actual
        self.ck = digest 

    def create_handshake_message(self):
        """
        (Initiator) Crea el primer mensaje del handshake.
        -> e, es, s, ss
        """
        if not self.initiator:
            raise Exception("Only initiator creates msg 1")

        # 1. Token 'e' (enviar e_pub en claro)
        msg_buffer = self.e_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # 2. Token 'es': DH(e, rs)
        shared_es = self._dh(self.e_priv, self.rs_pub)
        self.ck, k = self._mix_key(self.ck, shared_es)
        # (Encryption of payload/nothing with k is skipped for length 0 in simplified version, 
        # but formally required for 's'. We simplify to secure channel establishment logic)

        # 3. Token 's' (encrypted static key)
        my_static_bytes = self.s_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        chacha = ChaCha20Poly1305(k)
        encrypted_s = chacha.encrypt(b'\x00'*12, my_static_bytes, b'') # Nonce 0 for handshake
        msg_buffer += encrypted_s

        # 4. Token 'ss': DH(s, rs)
        shared_ss = self._dh(self.s_priv, self.rs_pub)
        self.ck, k = self._mix_key(self.ck, shared_ss)
        
        # Payload encriptado (Empty auth tag)
        chacha = ChaCha20Poly1305(k)
        auth_tag = chacha.encrypt(b'\x01'*12, b'', b'') # Nonce 1
        msg_buffer += auth_tag

        return msg_buffer

    def consume_handshake_message(self, data):
        """
        (Responder) Procesa el primer mensaje.
        <- e, es, s, ss
        """
        if self.initiator:
            raise Exception("Initiator cannot consume msg 1")

        # 1. Leer 'e' (32 bytes)
        re_bytes = data[:32]
        self.re_pub = x25519.X25519PublicKey.from_public_bytes(re_bytes)
        
        # 2. 'es': DH(e, rs) -> DH(re, s) (since I am responder, my static is s)
        shared_es = self._dh(self.s_priv, self.re_pub)
        self.ck, k = self._mix_key(self.ck, shared_es)

        # 3. Leer 's' (encrypted) - 32 bytes + 16 tag = 48 bytes
        encrypted_s = data[32:80]
        chacha = ChaCha20Poly1305(k)
        try:
            rs_bytes = chacha.decrypt(b'\x00'*12, encrypted_s, b'')
            self.rs_pub = x25519.X25519PublicKey.from_public_bytes(rs_bytes)
        except:
            raise Exception("Handshake Decrypt Fail: Static Key")

        # 4. 'ss': DH(s, rs) -> DH(s, rs) (now we have rs)
        shared_ss = self._dh(self.s_priv, self.rs_pub)
        self.ck, k = self._mix_key(self.ck, shared_ss)

        # Verify payload auth tag
        encrypted_payload = data[80:]
        chacha = ChaCha20Poly1305(k)
        try:
            chacha.decrypt(b'\x01'*12, encrypted_payload, b'')
        except:
            raise Exception("Handshake Auth Fail")
            
        return self.rs_pub

    def create_handshake_response(self):
        """
        (Responder) Crea el segundo mensaje.
        <- e, ee, se
        """
        if self.initiator:
            raise Exception("Initiator cannot create response")
        
        # 1. Token 'e' (enviar e_pub en claro)
        msg_buffer = self.e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        # 2. Token 'ee': DH(e, re)
        shared_ee = self._dh(self.e_priv, self.re_pub)
        self.ck, k = self._mix_key(self.ck, shared_ee)

        # 3. Token 'se': DH(s, re) -> DH(s, re)
        shared_se = self._dh(self.s_priv, self.re_pub)
        self.ck, k = self._mix_key(self.ck, shared_se)

        # Payload (Empty auth)
        chacha = ChaCha20Poly1305(k)
        auth_tag = chacha.encrypt(b'\x00'*12, b'', b'')
        msg_buffer += auth_tag
        
        # Split keys for transport
        k1, k2 = self._kdf(self.ck, b'')
        self.encryptor = ChaCha20Poly1305(k1) # Responder sends with k1
        self.decryptor = ChaCha20Poly1305(k2) # Responder recvs with k2
        
        return msg_buffer

    def consume_handshake_response(self, data):
        """
        (Initiator) Procesa respuesta.
        -> e, ee, se
        """
        if not self.initiator:
            raise Exception("Responder cannot consume response")
        
        # 1. Leer 'e' (32 bytes)
        re_bytes = data[:32]
        self.re_pub = x25519.X25519PublicKey.from_public_bytes(re_bytes)

        # 2. 'ee': DH(e, re)
        shared_ee = self._dh(self.e_priv, self.re_pub)
        self.ck, k = self._mix_key(self.ck, shared_ee)

        # 3. 'se': DH(s, re) -> DH(rs, e) (Initiator knows rs, has e)
        shared_se = self._dh(self.e_priv, self.rs_pub)
        self.ck, k = self._mix_key(self.ck, shared_se)

        # Verify auth
        auth_tag = data[32:]
        chacha = ChaCha20Poly1305(k)
        try:
            chacha.decrypt(b'\x00'*12, auth_tag, b'')
        except:
            raise Exception("Handshake Response Auth Fail")

        # Split keys for transport (Must match responder split)
        k1, k2 = self._kdf(self.ck, b'')
        self.decryptor = ChaCha20Poly1305(k1) # Initiator recvs k1
        self.encryptor = ChaCha20Poly1305(k2) # Initiator sends k2

    def encrypt_message(self, plaintext):
        nonce = struct.pack('<Q', self.tx_nonce) + b'\x00'*4
        ciphertext = self.encryptor.encrypt(nonce, plaintext, b'')
        self.tx_nonce += 1
        return ciphertext

    def decrypt_message(self, ciphertext):
        nonce = struct.pack('<Q', self.rx_nonce) + b'\x00'*4
        plaintext = self.decryptor.decrypt(nonce, ciphertext, b'')
        self.rx_nonce += 1
        return plaintext