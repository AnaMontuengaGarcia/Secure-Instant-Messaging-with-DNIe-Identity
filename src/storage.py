import json
import os
import asyncio
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class Storage:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        self.contacts_file = os.path.join(data_dir, "contacts.json")
        self.messages_file = os.path.join(data_dir, "messages.json")
        
        # Lock para evitar conflictos de escritura concurrente en los JSON
        self.lock = asyncio.Lock()

    async def init(self):
        """Inicializa los ficheros JSON si no existen"""
        async with self.lock:
            if not os.path.exists(self.contacts_file):
                await self._write_json(self.contacts_file, [])
            if not os.path.exists(self.messages_file):
                await self._write_json(self.messages_file, [])

    async def _read_json(self, filepath):
        """Lee JSON de forma asíncrona (en un hilo separado)"""
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    async def _write_json(self, filepath, data):
        """Escribe JSON de forma asíncrona (en un hilo separado)"""
        def write():
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        await asyncio.to_thread(write)

    async def get_static_key(self):
        key_path = os.path.join(self.data_dir, "identity.key")
        
        # Esta operación de archivo es pequeña y se hace solo al inicio,
        # pero para ser estrictos con async, la envolvemos también si se desea.
        # Por compatibilidad con el código existente, la dejamos fluida.
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                private_bytes = f.read()
                return x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        else:
            priv = x25519.X25519PrivateKey.generate()
            with open(key_path, "wb") as f:
                f.write(priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            return priv

    async def register_contact(self, ip, port, pubkey_obj, name="Unknown"):
        pub_hex = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        
        async with self.lock:
            contacts = await asyncio.to_thread(self._read_sync, self.contacts_file)
            
            # Buscar si ya existe
            found = False
            for c in contacts:
                if c['ip'] == ip and c['port'] == port:
                    found = True
                    if c['pubkey_hex'] != pub_hex:
                         print(f"🚨 SECURITY ALERT: Key changed for {ip}:{port}!")
                         return
                    # Actualizar nombre si ha cambiado
                    if name != "Unknown" and c.get('friendly_name') != name:
                        c['friendly_name'] = name
                        print(f"DB: Updated name for {ip}:{port}")
                        await self._write_json(self.contacts_file, contacts)
                    break
            
            if not found:
                new_contact = {
                    "ip": ip,
                    "port": port,
                    "pubkey_hex": pub_hex,
                    "friendly_name": name,
                    "trusted": 1
                }
                contacts.append(new_contact)
                await self._write_json(self.contacts_file, contacts)
                print(f"DB: Contact {ip}:{port} saved successfully (JSON).")

    async def get_pubkey_by_addr(self, ip, port):
        """Recupera la clave pública buscando en el JSON de contactos"""
        try:
            # Usamos to_thread para leer sin bloquear el loop
            contacts = await asyncio.to_thread(self._read_sync, self.contacts_file)
            
            for c in contacts:
                if c['ip'] == ip and c['port'] == port:
                    # print("DB: Key found in JSON!")
                    return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(c['pubkey_hex']))
            
            print("DB: Key NOT found in JSON.")
            return None
        except Exception as e:
            print(f"DB ERROR in get_pubkey_by_addr: {e}")
            return None

    async def log_msg(self, ip, port, direction, text):
        import time
        msg_entry = {
            "contact_ip": ip,
            "contact_port": port,
            "direction": direction,
            "content": text,
            "timestamp": time.time()
        }
        
        async with self.lock:
            messages = await asyncio.to_thread(self._read_sync, self.messages_file)
            messages.append(msg_entry)
            # Mantenemos solo los últimos 1000 mensajes para no saturar el JSON
            if len(messages) > 1000:
                messages = messages[-1000:]
            await self._write_json(self.messages_file, messages)

    # Helper síncrono para ser llamado dentro de to_thread
    def _read_sync(self, filepath):
        if not os.path.exists(filepath): return []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except: return []