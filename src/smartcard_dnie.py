"""
DNIe Smart Card Integration Module
Handles authentication and key derivation using Spanish DNIe smart card.
"""
import platform
import pkcs11
import sys
import os
from pkcs11 import Mechanism, ObjectClass, Attribute
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Símbolos adaptativos según el terminal
if sys.platform == 'win32' and 'WT_SESSION' not in os.environ:
    # cmd.exe tradicional - usar ASCII
    CHECK = '[OK]'
    CROSS = '{CROSS}'
    WARNING = '{WARNING}'
    INFO = '[i]'
else:
    # Windows Terminal, Linux, Mac - usar Unicode
    CHECK = '✓'
    CROSS = '✗'
    WARNING = '⚠'
    INFO = 'ℹ'

class DNIeCardError(Exception):
    """Base exception for DNIe card operations"""
    pass


class DNIeCard:
    """Interface for Spanish DNIe smart card operations"""
    
    def __init__(self):
        """Initialize DNIe card interface"""
        self.lib = None
        self.token = None
        self.session = None
        
        # Determine PKCS#11 library path based on OS
        system = platform.system()
        if system == "Windows":
            self.lib_path = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
        elif system == "Linux":
            self.lib_path = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
        elif system == "Darwin":  # macOS
            self.lib_path = "/usr/local/lib/opensc-pkcs11.so"
        else:
            raise DNIeCardError(f"Unsupported operating system: {system}")
    
    def connect(self):
        """Connect to DNIe card and open session"""
        try:
            # Load PKCS#11 library
            self.lib = pkcs11.lib(self.lib_path)
            
            # Get token (DNIe card)
            slots = list(self.lib.get_slots(token_present=True))
            if not slots:
                raise DNIeCardError("No smart card detected. Please insert your DNIe.")
            
            self.token = slots[0].get_token()
            
            # Verify it's a DNIe (relaxed check)
            token_info = f"{self.token.label} {self.token.manufacturer_id}"
            if "DNI" not in token_info and "FNMT" not in token_info and "DGP" not in token_info:
                print(f"{WARNING} Warning: Card may not be a DNIe: {self.token.label}")
            
            # Open read-only session (no PIN yet)
            self.session = self.token.open(rw=False)
            
            return True
            
        except FileNotFoundError:
            raise DNIeCardError(f"PKCS#11 library not found at: {self.lib_path}")
        except Exception as e:
            raise DNIeCardError(f"Failed to connect to DNIe: {e}")
    
    # Constante de separación de dominio específica de la aplicación
    DOMAIN_SEPARATOR = b"PasswordManager-DNIe-v1.0"
    
    def get_serial_hash(self):
        '''
        Obtiene el hash SHA-256 del número de serie con domain separator.
        
        Returns:
            str: Hash hexadecimal (64 caracteres)
        '''
        if not self.token:
            raise DNIeCardError("Not connected to card")
        
        card_serial = self.token.serial
        serial_bytes = card_serial.encode('utf-8') if isinstance(card_serial, str) else card_serial
        
        # Concatenar: DOMAIN_SEPARATOR || serial_bytes
        data_to_hash = self.DOMAIN_SEPARATOR + serial_bytes
        
        # Calcular SHA-256
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data_to_hash)
        hash_bytes = digest.finalize()
        
        return hash_bytes.hex()

    def authenticate(self, pin):
        """
        Authenticate with PIN using signature challenge.
        """
        try:
            if not self.session:
                raise DNIeCardError("Not connected to card. Call connect() first.")
            
            # CORREGIDO: Verificar si la sesión sigue siendo válida antes de cerrarla
            try:
                # Intentar cerrar la sesión de solo lectura si existe
                if self.session:
                    self.session.close()
                    self.session = None
            except Exception as e:
                # Si falla al cerrar, la sesión ya estaba cerrada o inválida
                print(f"{WARNING} Warning: Could not close existing session: {e}")
                self.session = None
            
            # CORREGIDO: Abrir nueva sesión con PIN
            try:
                self.session = self.token.open(user_pin=pin)
            except Exception as e:
                # Si falla, intentar reconectar completamente a la tarjeta
                print(f"{WARNING} Failed to open session, attempting full reconnect...")
                
                # Desconectar completamente
                try:
                    if self.session:
                        self.session.close()
                except:
                    pass
                self.session = None
                self.token = None
                self.lib = None
                
                # Reconectar desde cero
                self.connect()
                
                # Intentar abrir sesión con PIN nuevamente
                self.session = self.token.open(user_pin=pin)
            
            # Create deterministic challenge
            card_serial = self.token.serial
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(b'password-manager-signature-challenge-v1:')
            digest.update(card_serial.encode('utf-8') if isinstance(card_serial, str) else card_serial)
            challenge = bytearray(digest.finalize())
            
            del card_serial
            
            try:
                # Find private key for authentication
                private_key = None
                possible_labels = [
                    "KprivAutenticacion",
                    "CITIZEN AUTHENTICATION KEY",
                    "Authentication Key",
                    None
                ]
                
                for label in possible_labels:
                    try:
                        if label:
                            keys = list(self.session.get_objects({
                                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
                                Attribute.LABEL: label
                            }))
                        else:
                            keys = list(self.session.get_objects({
                                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                Attribute.KEY_TYPE: pkcs11.KeyType.RSA
                            }))
                        
                        if keys:
                            private_key = keys[0]
                            print(f"{CHECK} Found private key" + (f": {label}" if label else ""))
                            break
                    except:
                        continue
                
                if not private_key:
                    raise DNIeCardError("No private key found on card for signature")
                
                # Sign the challenge
                print("Signing challenge with DNIe private key...")
                signature = bytearray(private_key.sign(
                    bytes(challenge),
                    mechanism=Mechanism.SHA256_RSA_PKCS
                ))
                
                del private_key
                print(f"{CHECK} Signature generated ({len(signature)} bytes)")
                
                try:
                    # Derive wrapping key from signature using HKDF
                    kdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=b'dnie-signature-wrapping-key-v1',
                        info=b'database-key-protection',
                        backend=default_backend()
                    )
                    wrapping_key = kdf.derive(bytes(signature))
                    
                    return wrapping_key
                finally:
                    # Limpiar signature con zeroize
                    try:
                        from zeroize import zeroize1
                        zeroize1(signature)
                    except:
                        pass
                    del signature
            finally:
                # Limpiar challenge con zeroize
                try:
                    from zeroize import zeroize1
                    zeroize1(challenge)
                except:
                    pass
                del challenge
        
        except pkcs11.exceptions.PinIncorrect:
            raise DNIeCardError("Incorrect PIN. Please try again.")
        except pkcs11.exceptions.PinLocked:
            raise DNIeCardError("PIN locked. Too many incorrect attempts.")
        except Exception as e:
            raise DNIeCardError(f"Authentication failed: {e}")

    
    def disconnect(self):
        """Close session and disconnect"""
        try:
            if self.session:
                try:
                    self.session.close()
                except Exception as e:
                    print(f"{WARNING} Warning: Error closing session: {e}")
                finally:
                    self.session = None
        except:
            pass
        
        # Limpiar referencias a token y lib
        try:
            self.token = None
            self.lib = None
        except:
            pass

    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

