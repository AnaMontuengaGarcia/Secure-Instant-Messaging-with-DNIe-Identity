import aiosqlite
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class Storage:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        self.db_path = os.path.join(data_dir, "messenger.db")
            
    async def init(self):
        self.db = await aiosqlite.connect(self.db_path)
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                ip TEXT,
                port INTEGER,
                pubkey_hex TEXT,
                friendly_name TEXT,
                trusted INTEGER DEFAULT 0,
                PRIMARY KEY (ip, port)
            )
        """)
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_ip TEXT,
                contact_port INTEGER,
                direction TEXT,
                content TEXT,
                timestamp REAL
            )
        """)
        await self.db.commit()

    async def get_static_key(self):
        key_path = os.path.join(self.data_dir, "identity.key")
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
        
        try:
            # DEBUG LOG
            print(f"DB: Registering contact {ip}:{port} name={name}")
            
            async with self.db.execute("SELECT pubkey_hex FROM contacts WHERE ip = ? AND port = ?", (ip, port)) as cursor:
                row = await cursor.fetchone()
                if row:
                    if row[0] != pub_hex:
                        print(f"🚨 SECURITY ALERT: Key changed for {ip}:{port}!")
                        return
                else:
                    await self.db.execute(
                        "INSERT INTO contacts (ip, port, pubkey_hex, friendly_name, trusted) VALUES (?, ?, ?, ?, 1)",
                        (ip, port, pub_hex, name)
                    )
                    await self.db.commit()
                    print(f"DB: Contact {ip}:{port} saved successfully.")
        except Exception as e:
            print(f"DB ERROR in register_contact: {e}")
            raise

    def get_pubkey_by_addr(self, ip, port):
        try:
            # Síncrono para uso rápido
            import sqlite3
            print(f"DB: Querying key for {ip}:{port}...")
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT pubkey_hex FROM contacts WHERE ip = ? AND port = ?", (ip, port))
            row = c.fetchone()
            conn.close()
            if row:
                print("DB: Key found!")
                return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(row[0]))
            print("DB: Key NOT found.")
            return None
        except Exception as e:
            print(f"DB ERROR in get_pubkey_by_addr: {e}")
            return None

    async def log_msg(self, ip, port, direction, text):
        import time
        await self.db.execute(
            "INSERT INTO messages (contact_ip, contact_port, direction, content, timestamp) VALUES (?, ?, ?, ?, ?)",
            (ip, port, direction, text, time.time())
        )
        await self.db.commit()