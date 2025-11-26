import json
import os
import asyncio
from cryptography.hazmat.primitives.asymmetric import x25519

class Storage:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        self.contacts_file = os.path.join(data_dir, "contacts.json")
        self.messages_file = os.path.join(data_dir, "messages.json")
        
        # Lock para evitar conflictos de escritura concurrente en los JSON
        self.lock = asyncio.Lock()
        
        # ALMACÉN EN MEMORIA PARA CLAVES PÚBLICAS EFÍMERAS
        # Diccionario: (ip, port) -> Objeto X25519PublicKey
        # Estas claves se pierden al cerrar el programa, que es lo deseado.
        self.ephemeral_keys = {}

    async def init(self):
        """Inicializa los ficheros JSON si no existen"""
        async with self.lock:
            if not os.path.exists(self.contacts_file):
                await self._write_json(self.contacts_file, [])
            if not os.path.exists(self.messages_file):
                # Estructura base: Diccionario donde Key=UserID, Value=Lista de mensajes
                await self._write_json(self.messages_file, {})

    async def _read_json(self, filepath):
        """Lee JSON de forma asíncrona"""
        if not os.path.exists(filepath):
            return [] if "contacts" in filepath else {}
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return [] if "contacts" in filepath else {}

    async def _write_json(self, filepath, data):
        """Escribe JSON de forma asíncrona"""
        def write():
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        await asyncio.to_thread(write)

    async def get_all_contacts(self):
        """Devuelve la lista completa de contactos conocidos (solo metadatos)."""
        return await self._read_json(self.contacts_file)

    async def register_contact(self, ip, port, pubkey_obj, user_id=None, real_name=None):
        """
        Registra un contacto.
        - La Clave Pública se guarda SOLO EN MEMORIA.
        - Metadatos (IP, Nombre, ID) se guardan en DISCO (JSON).
        """
        # 1. Guardar clave en memoria (RAM)
        self.ephemeral_keys[(ip, port)] = pubkey_obj
        
        # 2. Guardar metadatos en disco
        async with self.lock:
            contacts = await asyncio.to_thread(self._read_sync, self.contacts_file, default=[])
            
            # Buscar si ya existe
            found_idx = -1
            for i, c in enumerate(contacts):
                match_id = (user_id is not None) and (c.get('userID') == user_id)
                match_ip = (c['ip'] == ip and c['port'] == port)
                
                if match_id:
                    found_idx = i
                    break
                elif match_ip and found_idx == -1: 
                    found_idx = i
            
            if found_idx != -1:
                c = contacts[found_idx]
                updated = False
                
                if c['ip'] != ip or c['port'] != port:
                    c['ip'] = ip
                    c['port'] = port
                    updated = True
                
                if user_id and c.get('userID') != user_id:
                    c['userID'] = user_id
                    updated = True
                
                if real_name and c.get('real_name') != real_name:
                    c['real_name'] = real_name
                    # print(f"DB: Identity Verified for {ip}:{port} -> {real_name}")
                    updated = True
                    
                if updated:
                    await self._write_json(self.contacts_file, contacts)
            
            else:
                new_contact = {
                    "ip": ip,
                    "port": port,
                    "userID": user_id if user_id else "UnknownID",
                    "real_name": real_name if real_name else None,
                    "trusted": 1
                }
                contacts.append(new_contact)
                await self._write_json(self.contacts_file, contacts)
                print(f"DB: New contact {ip}:{port} metadata saved.")

    async def get_pubkey_by_addr(self, ip, port):
        """Recupera la clave pública desde la MEMORIA RAM."""
        return self.ephemeral_keys.get((ip, port))

    # --- NUEVAS FUNCIONES DE PERSISTENCIA DE MENSAJES ---

    async def save_chat_message(self, user_id, direction, text, timestamp):
        """
        Guarda un mensaje en el historial del usuario especificado.
        user_id: ID único del interlocutor (DNIe hash).
        direction: "in" (recibido) o "out" (enviado).
        """
        if not user_id: return

        msg_entry = {
            "direction": direction,
            "content": text,
            "timestamp": timestamp
        }

        async with self.lock:
            # Leemos el diccionario completo de mensajes
            all_chats = await asyncio.to_thread(self._read_sync, self.messages_file, default={})
            
            # Si no existe historial para este usuario, lo creamos
            if user_id not in all_chats:
                all_chats[user_id] = []
            
            # Añadimos el mensaje
            all_chats[user_id].append(msg_entry)
            
            # Ordenamos por timestamp para asegurar consistencia
            all_chats[user_id].sort(key=lambda x: x['timestamp'])
            
            # Opcional: Limitar historial por usuario (ej. 5000 mensajes)
            if len(all_chats[user_id]) > 5000:
                all_chats[user_id] = all_chats[user_id][-5000:]
            
            await self._write_json(self.messages_file, all_chats)

    async def get_chat_history(self, user_id):
        """Recupera el historial de conversación con un usuario específico."""
        if not user_id: return []
        
        # No usamos lock aquí para lectura rápida, confiamos en atomicidad básica de lectura de archivo
        all_chats = await self._read_json(self.messages_file)
        return all_chats.get(user_id, [])

    # ----------------------------------------------------

    def _read_sync(self, filepath, default=None):
        """Lectura síncrona auxiliar para usar dentro de hilos"""
        if default is None: default = []
        if not os.path.exists(filepath): return default
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except: return default