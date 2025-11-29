"""
Interfaz de Hardware DNIe (PKCS#11)
-----------------------------------
Este módulo abstrae la comunicación compleja con la tarjeta inteligente.
Utiliza la librería `opensc-pkcs11` para interactuar con el DNIe.

Responsabilidades:
1. Cargar dinámicamente el driver PKCS#11 correcto según el SO.
2. Gestionar la conexión/desconexión física con la tarjeta.
3. Solicitar el PIN y abrir sesión segura.
4. Localizar el certificado específico de "AUTENTICACIÓN" (no Firma).
5. Realizar firmas criptográficas hardware (SHA256-RSA).
"""

import platform
import pkcs11
import sys
import os
from pkcs11 import Mechanism, ObjectClass, Attribute
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class DNIeCardError(Exception):
    """Excepción personalizada para errores específicos del DNIe."""
    pass

class DNIeCard:
    """Clase controladora para operaciones PKCS#11 con el DNIe."""
    
    # Patrón Singleton para la librería cargada. Evita recargar la DLL/SO
    # múltiples veces, lo cual puede causar crashes en OpenSC.
    _shared_lib = None
    
    def __init__(self):
        """
        Inicializa la configuración de rutas según el Sistema Operativo.
        No conecta con la tarjeta todavía.
        """
        self.lib = None
        self.token = None
        self.session = None
        
        system = platform.system()
        # Rutas estándar de OpenSC
        if system == "Windows":
            self.lib_path = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
        elif system == "Linux":
            self.lib_path = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
        elif system == "Darwin":
            self.lib_path = "/usr/local/lib/opensc-pkcs11.so"
        else:
            raise DNIeCardError(f"Sistema Operativo no soportado: {system}")

    @classmethod
    def _get_library_singleton(cls, lib_path):
        """
        Carga la librería dinámica PKCS#11 de forma segura (Singleton).
        """
        if cls._shared_lib is None:
            try:
                cls._shared_lib = pkcs11.lib(lib_path)
            except Exception as e:
                raise DNIeCardError(f"No se pudo cargar OpenSC en {lib_path}. ¿Drivers instalados? Error: {e}")
        return cls._shared_lib
    
    def connect(self):
        """
        Intenta conectar con una tarjeta insertada en el lector.
        
        Returns:
            bool: True si hay tarjeta y conexión exitosa.
        """
        try:
            self.lib = self._get_library_singleton(self.lib_path)
            
            # Buscar slots con token presente
            slots = list(self.lib.get_slots(token_present=True))
            if not slots:
                raise DNIeCardError("No se detectó ninguna tarjeta inteligente insertada.")
            
            self.token = slots[0].get_token()
            # Abrimos sesión inicial (Pública/Lectura)
            self.session = self.token.open(rw=False)
            return True
        except Exception as e:
            raise DNIeCardError(f"Error de conexión con lector: {e}")

    def get_serial(self):
        """Obtiene el número de serie físico del chip."""
        if not self.token: raise DNIeCardError("No conectado")
        return self.token.serial

    def get_serial_hash(self):
        """
        Genera un identificador anonimizado (Hash SHA256) del número de serie.
        Este hash se usa como ID público en la red, protegiendo el número real.
        """
        if not self.token: raise DNIeCardError("No conectado")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        ser = self.token.serial
        data_to_hash = ser.encode('utf-8') if isinstance(ser, str) else ser
        digest.update(data_to_hash)
        return digest.finalize().hex()

    def authenticate(self, pin, max_retries=3):
        """
        Realiza el 'Login' en la tarjeta usando el PIN del usuario.
        Esto eleva privilegios para permitir operaciones de firma.
        
        Incluye reintentos para manejar problemas intermitentes de
        comunicación PKCS#11 con la tarjeta.
        """
        import time
        
        last_error = None
        for attempt in range(max_retries):
            try:
                # Cerrar sesión previa si existe
                if self.session:
                    try:
                        self.session.close()
                    except:
                        pass
                    self.session = None
                
                # Pequeña pausa entre reintentos para dar tiempo al hardware
                if attempt > 0:
                    time.sleep(0.3)
                
                # Abrir sesión autenticada
                self.session = self.token.open(user_pin=pin)
                return  # Éxito, salir del bucle
                
            except pkcs11.exceptions.PinIncorrect:
                raise DNIeCardError("PIN Incorrecto.")
            except pkcs11.exceptions.PinLocked:
                raise DNIeCardError("PIN Bloqueado. Contacte con la policía para desbloquearlo.")
            except pkcs11.exceptions.UserAlreadyLoggedIn:
                # Ya hay una sesión activa, intentar usarla o cerrarla
                try:
                    if self.session:
                        self.session.close()
                        self.session = None
                except:
                    pass
                last_error = "Sesión previa activa"
                continue
            except pkcs11.exceptions.DeviceRemoved:
                raise DNIeCardError("La tarjeta fue retirada del lector.")
            except pkcs11.exceptions.TokenNotPresent:
                raise DNIeCardError("No se detecta la tarjeta en el lector.")
            except pkcs11.exceptions.SessionClosed:
                # La sesión se cerró inesperadamente, reintentar
                last_error = "Sesión cerrada inesperadamente"
                continue
            except Exception as e:
                # Capturar el tipo de excepción para mejor diagnóstico
                error_type = type(e).__name__
                error_msg = str(e).strip() if str(e).strip() else error_type
                last_error = f"{error_type}: {error_msg}" if error_msg != error_type else error_type
                continue
        
        # Si llegamos aquí, fallaron todos los reintentos
        raise DNIeCardError(f"Error de Autenticación tras {max_retries} intentos. {last_error or 'Error desconocido'}")

    def _get_label(self, obj):
        """Decodifica de forma segura la etiqueta (Label) de un objeto PKCS#11."""
        val = obj[Attribute.LABEL]
        if val is None: return ""
        if isinstance(val, bytes):
            return val.decode('utf-8', 'ignore')
        return str(val)

    def get_certificate(self):
        """
        Busca y retorna el certificado X.509 de AUTENTICACIÓN.
        
        El DNIe tiene varios certificados (Firma, Autenticación, CA Intermedia).
        Filtramos por etiqueta (Label) para encontrar el correcto.
        
        Returns:
            bytes: Certificado en formato DER.
        """
        if not self.session: raise DNIeCardError("Sesión no abierta")
        
        certs = list(self.session.get_objects({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
        }))
        
        target_cert = None
        
        for cert in certs:
            label = self._get_label(cert)
            # Palabras clave comunes en las versiones del DNIe (3.0, 4.0)
            if "Autenticacion" in label or "Authentication" in label or "Kpub" in label:
                target_cert = cert
                break
        
        # Fallback: Si no encontramos etiqueta conocida, tomamos el primero
        if not target_cert and certs:
            target_cert = certs[0]
            
        if target_cert:
            return target_cert[Attribute.VALUE]
            
        raise DNIeCardError("No se encontró certificado válido en la tarjeta")

    def sign_data(self, data_bytes):
        """
        Firma datos arbitrarios usando la clave privada de Autenticación.
        La operación criptográfica ocurre DENTRO del chip del DNIe. La clave privada
        nunca sale de la tarjeta.
        
        Args:
            data_bytes (bytes): Datos a firmar.
            
        Returns:
            bytes: Firma digital RSA.
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
            raise DNIeCardError("No se encontró clave privada adecuada")
            
        # Firmar usando PKCS#1 v1.5 padding y SHA256
        signature = target_key.sign(
            data_bytes,
            mechanism=Mechanism.SHA256_RSA_PKCS
        )
        return bytes(signature)
    
    def disconnect(self):
        """Cierra la sesión y libera recursos."""
        try:
            if self.session: self.session.close()
        except: pass