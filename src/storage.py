import aiosqlite
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

DB_PATH = "data/messenger.db"

class Storage:
    def __init__(self):
        if not os.path.exists('data'):
            os.makedirs('data')
            
    async def init(self):
        self.db = await aiosqlite.connect(DB_PATH)
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                ip TEXT PRIMARY KEY,
                pubkey_hex TEXT,
                friendly_name TEXT,
                trusted INTEGER DEFAULT 0
            )
        """)
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_ip TEXT,
                direction TEXT,
                content TEXT,
                timestamp REAL
            )
        """)
        await self.db.commit()

    async def get_static_key(self):
        """Carga o genera la clave de identidad X25519 del nodo local"""
        key_path = "data/identity.key"
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

    async def register_contact(self, ip, pubkey_obj, name="Unknown"):
        pub_hex = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        
        # TOFU: Si no existe, insertamos. Si existe y clave distinta, ALERTAR (aquí simplificado)
        async with self.db.execute("SELECT pubkey_hex FROM contacts WHERE ip = ?", (ip,)) as cursor:
            row = await cursor.fetchone()
            if row:
                if row[0] != pub_hex:
                    print(f"🚨 SECURITY ALERT: Key changed for {ip}!")
                    return
            else:
                await self.db.execute(
                    "INSERT INTO contacts (ip, pubkey_hex, friendly_name, trusted) VALUES (?, ?, ?, 1)",
                    (ip, pub_hex, name)
                )
                await self.db.commit()

    def get_pubkey_by_ip(self, ip):
        # Síncrono para uso rápido en callback de red (idealmente cachear en memoria)
        # Aquí simulamos caché o lectura
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT pubkey_hex FROM contacts WHERE ip = ?", (ip,))
        row = c.fetchone()
        conn.close()
        if row:
            return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(row[0]))
        return None

    async def log_msg(self, ip, direction, text):
        import time
        await self.db.execute(
            "INSERT INTO messages (contact_ip, direction, content, timestamp) VALUES (?, ?, ?, ?)",
            (ip, direction, text, time.time())
        )
        await self.db.commit()