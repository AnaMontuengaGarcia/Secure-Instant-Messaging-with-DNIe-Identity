import os
import struct
import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class NoiseIKState:
    """
    Protocolo Noise IK con Payload de Identidad DNIe.
    """
    PROLOGUE = b"DNIe-IM-v2-Signed"

    def __init__(self, static_priv, remote_static_pub=None, initiator=False, local_proofs=None):
        self.s_priv = static_priv
        self.s_pub = static_priv.public_key()
        self.rs_pub = remote_static_pub
        
        self.e_priv = None
        self.e_pub = None
        self.re_pub = None

        self.initiator = initiator
        self.local_proofs = local_proofs 
        self.remote_proofs = None        
        
        self.chaining_key = hashes.Hash(hashes.SHA256())
        self.chaining_key.update(self.PROLOGUE)
        
        self.encryptor = None
        self.decryptor = None
        self.tx_nonce = 0
        self.rx_nonce = 0

    def _dh(self, priv, pub):
        return priv.exchange(pub)

    def _kdf(self, km, material):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=km, info=b'')
        output = hkdf.derive(material)
        return output[:32], output[32:]

    def _mix_key(self, ck, dh_out):
        return self._kdf(ck, dh_out)

    def initialize(self):
        self.e_priv = x25519.X25519PrivateKey.generate()
        self.e_pub = self.e_priv.public_key()
        self.ck = self.chaining_key.finalize()

    def _prepare_identity_payload(self):
        if not self.local_proofs:
            return b'{}'
        return json.dumps(self.local_proofs).encode('utf-8')

    def create_handshake_message(self):
        if not self.initiator: raise Exception("Role error")

        msg = self.e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.rs_pub))
        
        s_bytes = self.s_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x00'*12, s_bytes, b'')
        
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.rs_pub))
        
        payload_data = self._prepare_identity_payload()
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x01'*12, payload_data, b'')
        
        return msg

    def consume_handshake_message(self, data):
        if self.initiator: raise Exception("Role error")

        self.re_pub = x25519.X25519PublicKey.from_public_bytes(data[:32])
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.re_pub))
        
        encrypted_s = data[32:80]
        chacha = ChaCha20Poly1305(k)
        rs_bytes = chacha.decrypt(b'\x00'*12, encrypted_s, b'')
        self.rs_pub = x25519.X25519PublicKey.from_public_bytes(rs_bytes)
        
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.rs_pub))
        
        encrypted_payload = data[80:]
        chacha = ChaCha20Poly1305(k)
        payload_bytes = chacha.decrypt(b'\x01'*12, encrypted_payload, b'')
        
        try:
            self.remote_proofs = json.loads(payload_bytes.decode('utf-8'))
        except:
            self.remote_proofs = {}
            
        return self.rs_pub

    def create_handshake_response(self):
        if self.initiator: raise Exception("Role error")
        
        msg = self.e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.re_pub))
        self.ck, k = self._mix_key(self.ck, self._dh(self.s_priv, self.re_pub))
        
        payload_data = self._prepare_identity_payload()
        chacha = ChaCha20Poly1305(k)
        msg += chacha.encrypt(b'\x00'*12, payload_data, b'')
        
        k1, k2 = self._kdf(self.ck, b'')
        self.encryptor = ChaCha20Poly1305(k1)
        self.decryptor = ChaCha20Poly1305(k2)
        
        return msg

    def consume_handshake_response(self, data):
        if not self.initiator: raise Exception("Role error")
        
        self.re_pub = x25519.X25519PublicKey.from_public_bytes(data[:32])
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.re_pub))
        self.ck, k = self._mix_key(self.ck, self._dh(self.e_priv, self.rs_pub))
        
        encrypted_payload = data[32:]
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
        """Cifra un mensaje de datos post-handshake"""
        if self.encryptor is None:
            raise Exception("Handshake not complete")
        nonce = struct.pack('<Q', self.tx_nonce) + b'\x00'*4
        ciphertext = self.encryptor.encrypt(nonce, plaintext, b'')
        self.tx_nonce += 1
        return ciphertext

    def decrypt_message(self, ciphertext):
        """Descifra un mensaje de datos post-handshake"""
        if self.decryptor is None:
            raise Exception("Handshake not complete")
        nonce = struct.pack('<Q', self.rx_nonce) + b'\x00'*4
        plaintext = self.decryptor.decrypt(nonce, ciphertext, b'')
        self.rx_nonce += 1
        return plaintext