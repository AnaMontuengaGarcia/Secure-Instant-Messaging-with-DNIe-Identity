import json
import os
import asyncio
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519

class Storage:
    """
    Sistema de almacenamiento cifrado.
    Mantiene los datos en memoria plana (RAM) y los cifra con AES (Fernet) al escribir en disco.
    """
    def __init__(self, key_bytes, data_dir="data"):
        """
        Inicializa el gestor de almacenamiento.
        
        Cómo lo hace:
        Recibe una clave simétrica de 32 bytes (derivada del DNIe), configura el cifrador Fernet
        y prepara las rutas de archivo y estructuras de memoria.
        """
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        self.contacts_file = os.path.join(data_dir, "contacts.json")
        self.messages_file = os.path.join(data_dir, "messages.json")
        
        # Inicializa cifrado Fernet (Requiere clave base64 url-safe)
        self.fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
        
        # ALMACENES EN MEMORIA (Texto Plano / Objetos)
        self.ram_contacts = []
        self.ram_messages = {}
        self.ephemeral_keys = {} # (ip, puerto) -> X25519PublicKey
        
        self.dirty = False
        
        self.lock = asyncio.Lock()
        self.bg_task = None
        self.running = False

    async def init(self):
        """
        Carga y descifra los datos desde el disco a la memoria RAM.
        
        Cómo lo hace:
        1. Lee los archivos cifrados de contactos y mensajes.
        2. Descifra el contenido usando Fernet.
        3. Parsea el JSON resultante a objetos Python.
        4. Inicia la tarea en segundo plano para guardado periódico.
        """
        # Cargar Contactos
        if os.path.exists(self.contacts_file):
            try:
                encrypted_data = await self._read_file_bytes(self.contacts_file)
                if encrypted_data:
                    decrypted_json = self.fernet.decrypt(encrypted_data)
                    self.ram_contacts = json.loads(decrypted_json)
                else:
                    self.ram_contacts = []
            except Exception as e:
                print(f"⚠️ Error descifrando contactos (Archivo corrupto o clave cambió): {e}")
                self.ram_contacts = []
        else:
             self.ram_contacts = []

        # Cargar Mensajes
        if os.path.exists(self.messages_file):
            try:
                encrypted_data = await self._read_file_bytes(self.messages_file)
                if encrypted_data:
                    decrypted_json = self.fernet.decrypt(encrypted_data)
                    self.ram_messages = json.loads(decrypted_json)
                else:
                    self.ram_messages = {}
            except Exception as e:
                print(f"⚠️ Error descifrando mensajes: {e}")
                self.ram_messages = {}
        else:
            self.ram_messages = {}

        self.running = True
        self.bg_task = asyncio.create_task(self._background_saver())
        print("💾 Sistema de almacenamiento inicializado (Cifrado-en-Reposo / Plano-en-RAM)")

    async def _background_saver(self):
        """
        Tarea de guardado automático.
        
        Cómo lo hace:
        Se ejecuta cada 60 segundos. Si el flag 'dirty' está activo (hubo cambios), llama a save_to_disk.
        """
        while self.running:
            await asyncio.sleep(60)
            if self.dirty:
                print("💾 Auto-guardando base de datos cifrada...")
                await self.save_to_disk()

    async def save_to_disk(self):
        """
        Persiste el estado de la memoria al disco de forma segura.
        
        Cómo lo hace:
        1. Adquiere un lock para evitar condiciones de carrera.
        2. Serializa los objetos de RAM a JSON.
        3. Cifra el JSON resultante con Fernet.
        4. Escribe los bytes cifrados en el archivo correspondiente.
        """
        async with self.lock:
            try:
                # 1. Contactos
                json_contacts = json.dumps(self.ram_contacts, ensure_ascii=False).encode('utf-8')
                enc_contacts = self.fernet.encrypt(json_contacts)
                await self._write_file_bytes(self.contacts_file, enc_contacts)

                # 2. Mensajes
                json_msgs = json.dumps(self.ram_messages, ensure_ascii=False).encode('utf-8')
                enc_msgs = self.fernet.encrypt(json_msgs)
                await self._write_file_bytes(self.messages_file, enc_msgs)
                
                self.dirty = False
            except Exception as e:
                print(f"❌ Error guardando en disco: {e}")

    async def close(self):
        """
        Cierra el sistema de almacenamiento.
        
        Cómo lo hace:
        Detiene la tarea de fondo y fuerza un último guardado.
        """
        self.running = False
        if self.bg_task:
            self.bg_task.cancel()
        print("💾 Guardando estado final antes de salir...")
        await self.save_to_disk()

    # --- Métodos de Archivo Base ---

    async def _read_file_bytes(self, filepath):
        """Helper para lectura de archivos binarios asíncrona."""
        def read():
            with open(filepath, 'rb') as f:
                return f.read()
        return await asyncio.to_thread(read)

    async def _write_file_bytes(self, filepath, data):
        """Helper para escritura de archivos binarios asíncrona."""
        def write():
            with open(filepath, 'wb') as f:
                f.write(data)
        await asyncio.to_thread(write)

    # --- Lógica de Negocio (Opera sobre RAM) ---

    async def get_all_contacts(self):
        """Retorna la lista de contactos en memoria."""
        return self.ram_contacts

    async def register_contact(self, ip, port, pubkey_obj, user_id=None, real_name=None):
        """
        Añade o actualiza un contacto en la memoria.
        
        Cómo lo hace:
        1. Guarda la clave pública efímera en un diccionario separado.
        2. Busca si el contacto ya existe en la lista (por ID o IP/Puerto).
        3. Si existe, actualiza sus campos. Si no, crea una nueva entrada.
        4. Marca el flag 'dirty' para forzar guardado en disco posteriormente.
        """
        self.ephemeral_keys[(ip, port)] = pubkey_obj
        
        found_idx = -1
        for i, c in enumerate(self.ram_contacts):
            match_id = (user_id is not None) and (c.get('userID') == user_id)
            match_ip = (c['ip'] == ip and c['port'] == port)
            
            if match_id:
                found_idx = i
                break
            elif match_ip and found_idx == -1: 
                found_idx = i
        
        updated = False
        if found_idx != -1:
            c = self.ram_contacts[found_idx]
            if c['ip'] != ip or c['port'] != port:
                c['ip'] = ip; c['port'] = port
                updated = True
            if user_id and c.get('userID') != user_id:
                c['userID'] = user_id
                updated = True
            if real_name and c.get('real_name') != real_name:
                c['real_name'] = real_name
                updated = True
        else:
            new_contact = {
                "ip": ip, "port": port,
                "userID": user_id if user_id else "UnknownID",
                "real_name": real_name if real_name else None,
                "trusted": 1
            }
            self.ram_contacts.append(new_contact)
            updated = True
        
        if updated:
            self.dirty = True

    async def get_pubkey_by_addr(self, ip, port):
        """Recupera la clave pública efímera de una dirección dada."""
        return self.ephemeral_keys.get((ip, port))

    async def save_chat_message(self, user_id, direction, text, timestamp):
        """
        Guarda un mensaje de chat en el historial.
        
        Cómo lo hace:
        1. Crea la entrada del mensaje.
        2. La añade a la lista correspondiente al usuario.
        3. Ordena los mensajes por timestamp.
        4. Limita el historial a los últimos 5000 mensajes para no saturar la RAM.
        5. Marca 'dirty' para persistencia.
        """
        if not user_id: return

        msg_entry = {
            "direction": direction,
            "content": text,
            "timestamp": timestamp
        }

        if user_id not in self.ram_messages:
            self.ram_messages[user_id] = []
        
        self.ram_messages[user_id].append(msg_entry)
        self.ram_messages[user_id].sort(key=lambda x: x['timestamp'])
        
        # Limitar historial en RAM
        if len(self.ram_messages[user_id]) > 5000:
            self.ram_messages[user_id] = self.ram_messages[user_id][-5000:]
            
        self.dirty = True

    async def get_chat_history(self, user_id):
        """Retorna el historial de chat para un usuario específico."""
        if not user_id: return []
        return self.ram_messages.get(user_id, [])