import os
import base64
import aiosqlite
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

class Storage:
    """
    Sistema de almacenamiento persistente, cifrado y escalable basado en SQLite.
    """
    
    def __init__(self, key_bytes, data_dir="data"):
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        self.db_path = os.path.join(data_dir, "storage.db")
        self.fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
        self.db = None
        self.ephemeral_keys = {} 

    async def init(self):
        self.db = await aiosqlite.connect(self.db_path)
        await self.db.execute("PRAGMA journal_mode=WAL;")
        
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                user_id TEXT PRIMARY KEY,
                real_name BLOB,
                ip TEXT,
                port INTEGER,
                pub_key BLOB,
                trusted INTEGER DEFAULT 0
            )
        """)
        
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                direction TEXT,
                content BLOB,
                timestamp REAL,
                FOREIGN KEY(user_id) REFERENCES contacts(user_id)
            )
        """)
        
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_msg_userid ON messages(user_id)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(timestamp)")
        
        await self.db.commit()
        print(f"💾 Storage initialized at {self.db_path} (SQLite + Full Privacy Encryption)")

    async def close(self):
        if self.db:
            await self.db.close()
            print("💾 Database connection closed.")

    def _encrypt(self, text: str) -> bytes:
        if text is None: return b''
        return self.fernet.encrypt(text.encode('utf-8'))

    def _decrypt(self, data: bytes) -> str:
        if not data: return ""
        try:
            return self.fernet.decrypt(data).decode('utf-8')
        except Exception as e:
            return f"🚫 [Error Descifrando]"

    async def get_all_contacts(self):
        query = "SELECT user_id, real_name, ip, port, pub_key, trusted FROM contacts"
        async with self.db.execute(query) as cursor:
            rows = await cursor.fetchall()
            
        contacts = []
        for r in rows:
            decrypted_real_name = self._decrypt(r[1]) if r[1] else None
            contacts.append({
                "userID": r[0],
                "real_name": decrypted_real_name,
                "ip": r[2],
                "port": r[3],
                "trusted": r[5]
            })
            if r[4]: 
                try:
                    key_obj = x25519.X25519PublicKey.from_public_bytes(r[4])
                    self.ephemeral_keys[(r[2], r[3])] = key_obj
                except: pass
                    
        return contacts

    async def register_contact(self, ip, port, pubkey_obj, user_id=None, real_name=None):
        self.ephemeral_keys[(ip, port)] = pubkey_obj
        pub_bytes = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        encrypted_real_name = self._encrypt(real_name) if real_name else None
        target_uuid = None

        if user_id:
            async with self.db.execute("SELECT user_id FROM contacts WHERE user_id = ?", (user_id,)) as cursor:
                row = await cursor.fetchone()
                if row: target_uuid = row[0]
        
        if not target_uuid:
            async with self.db.execute("SELECT user_id FROM contacts WHERE ip = ? AND port = ?", (ip, port)) as cursor:
                row = await cursor.fetchone()
                if row: target_uuid = row[0]

        if target_uuid:
            update_sql = "UPDATE contacts SET ip=?, port=?, pub_key=?"
            params = [ip, port, pub_bytes]
            if real_name:
                update_sql += ", real_name=?"
                params.append(encrypted_real_name)
            update_sql += " WHERE user_id=?"
            params.append(target_uuid)
            await self.db.execute(update_sql, tuple(params))
        else:
            final_id = user_id if user_id else f"Unknown_{ip}_{port}"
            await self.db.execute("""
                INSERT INTO contacts (user_id, real_name, ip, port, pub_key, trusted)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (final_id, encrypted_real_name, ip, port, pub_bytes))
            
        await self.db.commit()

    async def get_pubkey_by_addr(self, ip, port):
        return self.ephemeral_keys.get((ip, port))

    async def save_chat_message(self, user_id, direction, text, timestamp):
        if not user_id: return
        encrypted_blob = self._encrypt(text)
        await self.db.execute("""
            INSERT INTO messages (user_id, direction, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (user_id, direction, encrypted_blob, timestamp))
        await self.db.commit()

    async def get_chat_history(self, user_id, limit=50, offset=0):
        """
        Recupera el historial de chat con soporte para paginación.
        
        Args:
            limit (int): Número máximo de mensajes a recuperar.
            offset (int): Número de mensajes a saltar (desde el más reciente hacia atrás).
        """
        if not user_id: return []
        
        # SQL Optimizado:
        # 1. Obtenemos los 'limit' mensajes saltando 'offset' ordenados por DESC (del más nuevo al más viejo).
        # 2. La subconsulta nos da el lote correcto del pasado.
        # 3. La consulta externa los reordena ASC (cronológicamente) para pintarlos en el chat.
        query = """
            SELECT direction, content, timestamp 
            FROM (
                SELECT direction, content, timestamp 
                FROM messages 
                WHERE user_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            ) 
            ORDER BY timestamp ASC
        """
        
        history = []
        async with self.db.execute(query, (user_id, limit, offset)) as cursor:
            async for row in cursor:
                direction, enc_content, ts = row
                plain_text = self._decrypt(enc_content)
                history.append({
                    "direction": direction,
                    "content": plain_text,
                    "timestamp": ts
                })
        
        return history