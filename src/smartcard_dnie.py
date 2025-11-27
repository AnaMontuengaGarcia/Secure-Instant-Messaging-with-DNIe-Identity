import platform
import pkcs11
import sys
import os
from pkcs11 import Mechanism, ObjectClass, Attribute
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class DNIeCardError(Exception):
    pass

class DNIeCard:
    """Interfaz para operaciones con DNIe (PKCS#11)"""
    
    # OPTIMIZACIÓN: Variable de clase para almacenar la referencia a la librería cargada.
    # Esto actúa como un Singleton, evitando que 'pkcs11.lib(path)' cargue la DLL/SO
    # desde el disco cada vez que se instancia la clase.
    _shared_lib = None
    
    def __init__(self):
        """
        Inicializa la instancia detectando el sistema operativo.
        
        Cómo lo hace:
        Verifica si se ejecuta en Windows, Linux o macOS y define la ruta
        a la librería dinámica 'opensc-pkcs11' correspondiente.
        """
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
            raise DNIeCardError(f"SO no soportado: {system}")

    @classmethod
    def _get_library_singleton(cls, lib_path):
        """
        Gestiona la carga única de la librería PKCS#11 (Singleton).
        
        Cómo lo hace:
        Si _shared_lib es None, carga la librería desde disco.
        Si ya existe, devuelve la referencia en memoria.
        Esto es vital para el rendimiento en bucles de chequeo (polling).
        """
        if cls._shared_lib is None:
            try:
                cls._shared_lib = pkcs11.lib(lib_path)
            except Exception as e:
                # Si falla la carga inicial, permitimos reintentar en el futuro
                # (quizás el usuario instale el driver mientras la app corre)
                raise DNIeCardError(f"No se pudo cargar la librería OpenSC en {lib_path}. Asegúrese de tener los drivers del DNIe instalados. Error: {e}")
        return cls._shared_lib
    
    def connect(self):
        """
        Establece conexión con el lector de tarjetas inteligentes.
        
        Cómo lo hace:
        1. Obtiene la librería (usando el Singleton optimizado).
        2. Busca slots con token presente (tarjeta insertada).
        3. Abre una sesión inicial de solo lectura sin PIN.
        """
        try:
            # Usamos el getter del Singleton en lugar de pkcs11.lib() directo
            self.lib = self._get_library_singleton(self.lib_path)
            
            slots = list(self.lib.get_slots(token_present=True))
            if not slots:
                raise DNIeCardError("No se detectó tarjeta inteligente.")
            self.token = slots[0].get_token()
            self.session = self.token.open(rw=False)
            return True
        except Exception as e:
            # Relanzamos como error propio para manejo limpio en UI
            raise DNIeCardError(f"Conexión fallida: {e}")

    def get_serial(self):
        """
        Obtiene el número de serie físico de la tarjeta.
        
        Cómo lo hace:
        Lee el atributo 'serial' del token conectado.
        """
        if not self.token: raise DNIeCardError("No conectado")
        return self.token.serial

    def get_serial_hash(self):
        """
        Genera un identificador único anonimizado para la tarjeta.
        
        Cómo lo hace:
        Calcula el hash SHA-256 del número de serie de la tarjeta.
        Esto se usa como 'User ID' en la red.
        """
        if not self.token: raise DNIeCardError("No conectado")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        ser = self.token.serial
        data_to_hash = ser.encode('utf-8') if isinstance(ser, str) else ser
        digest.update(data_to_hash)
        return digest.finalize().hex()

    def authenticate(self, pin):
        """
        Autentica al usuario frente a la tarjeta (Login).
        
        Cómo lo hace:
        Cierra la sesión pública anterior y abre una nueva sesión protegida
        proporcionando el PIN del usuario.
        """
        try:
            if self.session: self.session.close()
            self.session = self.token.open(user_pin=pin)
        except pkcs11.exceptions.PinIncorrect:
            raise DNIeCardError("PIN Incorrecto.")
        except Exception as e:
            raise DNIeCardError(f"Error de Auth: {e}")

    def _get_label(self, obj):
        """
        Helper para obtener la etiqueta (Label) de un objeto PKCS#11.
        
        Cómo lo hace:
        Lee el atributo LABEL y lo decodifica de bytes a string UTF-8 de forma segura.
        """
        val = obj[Attribute.LABEL]
        if val is None:
            return ""
        if isinstance(val, bytes):
            return val.decode('utf-8', 'ignore')
        return str(val)

    def get_certificate(self):
        """
        Extrae el certificado público de AUTENTICACIÓN del DNIe.
        
        Cómo lo hace:
        1. Busca todos los objetos de clase CERTIFICATE en la tarjeta.
        2. Filtra buscando palabras clave como "Autenticacion", "Authentication" o "Kpub" en la etiqueta.
        3. Si no encuentra uno específico, usa el primero disponible como fallback.
        4. Retorna los bytes del certificado en formato DER.
        """
        if not self.session: raise DNIeCardError("Sesión no abierta")
        
        certs = list(self.session.get_objects({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
        }))
        
        target_cert = None
        
        for cert in certs:
            label = self._get_label(cert)
            if "Autenticacion" in label or "Authentication" in label or "Kpub" in label:
                target_cert = cert
                break
        
        if not target_cert and certs:
            target_cert = certs[0]
            
        if target_cert:
            return target_cert[Attribute.VALUE]
            
        raise DNIeCardError("No se encontró certificado en la tarjeta")

    def sign_data(self, data_bytes):
        """
        Genera una firma digital utilizando la clave privada del DNIe.
        
        Cómo lo hace:
        1. Busca la clave privada (PRIVATE_KEY) correspondiente al certificado de Autenticación.
        2. Invoca la operación de firma hardware usando el mecanismo SHA256_RSA_PKCS.
        3. Retorna la firma en bytes.
        """
        if not self.session: raise DNIeCardError("Sesión no abierta")
        
        priv_keys = list(self.session.get_objects({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: pkcs11.KeyType.RSA
        }))
        
        target_key = None
        
        for k in priv_keys:
            label = self._get_label(k)
            if "Autenticacion" in label or "Authentication" in label:
                target_key = k
                break
        
        if not target_key and priv_keys:
            target_key = priv_keys[0]
            
        if not target_key:
            raise DNIeCardError("No se encontró clave privada")
            
        signature = target_key.sign(
            data_bytes,
            mechanism=Mechanism.SHA256_RSA_PKCS
        )
        return bytes(signature)
    
    def disconnect(self):
        """
        Cierra la sesión con la tarjeta de forma segura.
        """
        try:
            if self.session: self.session.close()
        except: pass