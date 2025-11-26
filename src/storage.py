import json
import os
import asyncio
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519

class Storage:
    def __init__(self, key_bytes, data_dir="data"):
        """
        key_bytes: Clave simétrica de 32 bytes derivada del DNIe
        """
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        self.contacts_file = os.path.join(data_dir, "contacts.json")
        self.messages_file = os.path.join(data_dir, "messages.json")
        
        # Inicializamos cifrado Fernet (Requiere clave base64 url-safe)
        self.fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
        
        # ALMACENES EN MEMORIA (Texto Plano / Objetos)
        self.ram_contacts = []
        self.ram_messages = {}
        self.ephemeral_keys = {} # (ip, port) -> X25519PublicKey
        
        # Flag de "sucio" para saber si hay que escribir en disco
        self.dirty = False
        
        self.lock = asyncio.Lock()
        self.bg_task = None
        self.running = False

    async def init(self):
        """Carga inicial de datos descifrados a memoria e inicia tarea de fondo"""
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
                print(f"⚠️ Error decrypting contacts (File might be corrupted or key changed): {e}")
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
                print(f"⚠️ Error decrypting messages: {e}")
                self.ram_messages = {}
        else:
            self.ram_messages = {}

        # Iniciar tarea de guardado periódico
        self.running = True
        self.bg_task = asyncio.create_task(self._background_saver())
        print("💾 Storage system initialized (Encrypted-at-Rest / Plain-in-RAM)")

    async def _background_saver(self):
        """Tarea que se ejecuta cada 60 segundos"""
        while self.running:
            await asyncio.sleep(60)
            if self.dirty:
                print("💾 Auto-saving encrypted database to disk...")
                await self.save_to_disk()

    async def save_to_disk(self):
        """Cifra y guarda el estado actual de memoria a disco"""
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
                print(f"❌ Error saving to disk: {e}")

    async def close(self):
        """Cierra el sistema guardando cambios pendientes"""
        self.running = False
        if self.bg_task:
            self.bg_task.cancel()
        print("💾 Saving final state before exit...")
        await self.save_to_disk()

    # --- Métodos de Archivo Base ---

    async def _read_file_bytes(self, filepath):
        def read():
            with open(filepath, 'rb') as f:
                return f.read()
        return await asyncio.to_thread(read)

    async def _write_file_bytes(self, filepath, data):
        def write():
            with open(filepath, 'wb') as f:
                f.write(data)
        await asyncio.to_thread(write)

    # --- Lógica de Negocio (Opera sobre RAM) ---

    async def get_all_contacts(self):
        return self.ram_contacts

    async def register_contact(self, ip, port, pubkey_obj, user_id=None, real_name=None):
        # 1. Guardar clave en memoria (RAM, Efímera)
        self.ephemeral_keys[(ip, port)] = pubkey_obj
        
        # 2. Actualizar lista de contactos en RAM
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
        return self.ephemeral_keys.get((ip, port))

    async def save_chat_message(self, user_id, direction, text, timestamp):
        if not user_id: return

        msg_entry = {
            "direction": direction,
            "content": text,
            "timestamp": timestamp
        }

        if user_id not in self.ram_messages:
            self.ram_messages[user_id] = []
        
        self.ram_messages[user_id].append(msg_entry)
        # Ordenar (ligera sobrecarga en memoria, pero segura)
        self.ram_messages[user_id].sort(key=lambda x: x['timestamp'])
        
        # Limitar historial en RAM
        if len(self.ram_messages[user_id]) > 5000:
            self.ram_messages[user_id] = self.ram_messages[user_id][-5000:]
            
        self.dirty = True

    async def get_chat_history(self, user_id):
        if not user_id: return []
        return self.ram_messages.get(user_id, [])