import platform
import pkcs11
import sys
import os
from pkcs11 import Mechanism, ObjectClass, Attribute
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Símbolos adaptativos
if sys.platform == 'win32' and 'WT_SESSION' not in os.environ:
    CHECK, CROSS, WARNING, INFO = '[OK]', '[X]', '[!]', '[i]'
else:
    CHECK, CROSS, WARNING, INFO = '✓', '✗', '⚠', 'ℹ'

class DNIeCardError(Exception):
    pass

class DNIeCard:
    """Interfaz para operaciones con DNIe (PKCS#11)"""
    
    def __init__(self):
        self.lib = None
        self.token = None
        self.session = None
        
        system = platform.system()
        if system == "Windows":
            self.lib_path = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
        elif system == "Linux":
            self.lib_path = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
        elif system == "Darwin":
            self.lib_path = "/usr/local/lib/opensc-pkcs11.so"
        else:
            raise DNIeCardError(f"Unsupported OS: {system}")
    
    def connect(self):
        try:
            self.lib = pkcs11.lib(self.lib_path)
            slots = list(self.lib.get_slots(token_present=True))
            if not slots:
                raise DNIeCardError("No smart card detected.")
            self.token = slots[0].get_token()
            self.session = self.token.open(rw=False)
            return True
        except Exception as e:
            raise DNIeCardError(f"Connection failed: {e}")

    def get_serial_hash(self):
        """Obtiene identificador único de la tarjeta"""
        if not self.token: raise DNIeCardError("Not connected")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        ser = self.token.serial
        # Manejo robusto de serial (bytes vs str)
        data_to_hash = ser.encode('utf-8') if isinstance(ser, str) else ser
        digest.update(data_to_hash)
        return digest.finalize().hex()

    def authenticate(self, pin):
        """Valida el PIN (Login)"""
        try:
            if self.session: self.session.close()
            self.session = self.token.open(user_pin=pin)
        except pkcs11.exceptions.PinIncorrect:
            raise DNIeCardError("Incorrect PIN.")
        except Exception as e:
            raise DNIeCardError(f"Auth error: {e}")

    def _get_label(self, obj):
        """Helper seguro para obtener etiqueta como string"""
        val = obj[Attribute.LABEL]
        if val is None:
            return ""
        if isinstance(val, bytes):
            return val.decode('utf-8', 'ignore')
        return str(val)

    def get_certificate(self):
        """
        Extrae el certificado público de AUTENTICACIÓN del DNIe.
        Returns: bytes (DER format)
        """
        if not self.session: raise DNIeCardError("Session not open")
        
        # Buscar objetos de clase CERTIFICATE
        certs = list(self.session.get_objects({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
        }))
        
        target_cert = None
        
        # 1. Búsqueda por etiqueta (Prioritario)
        for cert in certs:
            label = self._get_label(cert)
            # El cert de autenticación suele tener keywords específicas
            if "Autenticacion" in label or "Authentication" in label or "Kpub" in label:
                target_cert = cert
                break
        
        # 2. Fallback: Usar el primer certificado disponible si no encontramos etiqueta clara
        if not target_cert and certs:
            target_cert = certs[0]
            
        if target_cert:
            return target_cert[Attribute.VALUE]
            
        raise DNIeCardError("No certificate found on card")

    def sign_data(self, data_bytes):
        """
        Firma datos arbitrarios con la clave privada de AUTENTICACIÓN.
        Args: data_bytes (bytes) - Datos a firmar
        Returns: bytes - Firma digital (SHA256-RSA-PKCS)
        """
        if not self.session: raise DNIeCardError("Session not open")
        
        # Buscar clave privada correspondiente
        priv_keys = list(self.session.get_objects({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: pkcs11.KeyType.RSA
        }))
        
        target_key = None
        
        # Intentar encontrar la clave de autenticación
        for k in priv_keys:
            label = self._get_label(k)
            if "Autenticacion" in label or "Authentication" in label:
                target_key = k
                break
        
        # Fallback
        if not target_key and priv_keys:
            target_key = priv_keys[0]
            
        if not target_key:
            raise DNIeCardError("No private key found")
            
        # Firmar
        signature = target_key.sign(
            data_bytes,
            mechanism=Mechanism.SHA256_RSA_PKCS
        )
        return bytes(signature)
    
    def disconnect(self):
        try:
            if self.session: self.session.close()
        except: pass