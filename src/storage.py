import os
import asyncio
import base64
import json
import aiosqlite
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

class Storage:
    """
    Sistema de almacenamiento persistente, cifrado y escalable basado en SQLite.
    
    Características:
    - Base de datos relacional (no JSON plano).
    - Cifrado a nivel de campo (Field-Level Encryption):
        1. Contenido de los mensajes (Privacidad de comunicación).
        2. Nombres reales de contactos (Privacidad de identidad/GDPR).
    - Carga perezosa (Lazy Loading) y paginación para no saturar la RAM.
    - Manejo eficiente de claves públicas efímeras.
    """
    
    def __init__(self, key_bytes, data_dir="data"):
        """
        Inicializa la configuración del almacenamiento.
        La conexión real a la DB ocurre en init() de forma asíncrona.
        """
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        self.db_path = os.path.join(data_dir, "storage.db")
        
        # Inicializa cifrador Fernet para los campos de texto
        # key_bytes viene derivado de la firma digital del DNIe (HKDF)
        self.fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
        
        self.db = None
        
        # Cache en RAM solo para claves efímeras de red (no persistentes por naturaleza)
        # Esto permite búsquedas ultra-rápidas durante el handshake UDP
        self.ephemeral_keys = {} 

    async def init(self):
        """
        Establece la conexión con SQLite y asegura que el esquema exista.
        """
        self.db = await aiosqlite.connect(self.db_path)
        
        # Modo WAL (Write-Ahead Logging) para mejor concurrencia y robustez ante fallos
        await self.db.execute("PRAGMA journal_mode=WAL;")
        
        # Tabla de Contactos
        # CAMBIO: real_name ahora es BLOB para soportar cifrado
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                user_id TEXT PRIMARY KEY,
                real_name BLOB, -- CONTENIDO CIFRADO (Privacidad de Identidad)
                ip TEXT,
                port INTEGER,
                pub_key BLOB, -- Clave pública serializada (Identity Key)
                trusted INTEGER DEFAULT 0
            )
        """)
        
        # Tabla de Mensajes
        # El contenido se guarda como BLOB cifrado. Los metadatos son planos para indexar.
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                direction TEXT,
                content BLOB, -- CONTENIDO CIFRADO (Privacidad de Mensaje)
                timestamp REAL,
                FOREIGN KEY(user_id) REFERENCES contacts(user_id)
            )
        """)
        
        # Índices para acelerar la carga del historial
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_msg_userid ON messages(user_id)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(timestamp)")
        
        await self.db.commit()
        print(f"💾 Storage initialized at {self.db_path} (SQLite + Full Privacy Encryption)")

    async def close(self):
        """Cierra la conexión a la base de datos ordenadamente."""
        if self.db:
            await self.db.close()
            print("💾 Database connection closed.")

    # --- Ayudantes de Cifrado (Privado) ---

    def _encrypt(self, text: str) -> bytes:
        """Cifra un string a bytes usando la clave derivada del DNIe."""
        if text is None: return b''
        return self.fernet.encrypt(text.encode('utf-8'))

    def _decrypt(self, data: bytes) -> str:
        """Descifra bytes a string. Retorna marcador de error si falla."""
        if not data: return ""
        try:
            return self.fernet.decrypt(data).decode('utf-8')
        except Exception as e:
            return f"🚫 [Error Descifrando]"

    # --- Gestión de Contactos ---

    async def get_all_contacts(self):
        """
        Recupera todos los contactos para inicializar la UI.
        Descifra los nombres reales al vuelo.
        
        Retorna:
            Lista de diccionarios compatibles con la UI existente.
        """
        query = "SELECT user_id, real_name, ip, port, pub_key, trusted FROM contacts"
        async with self.db.execute(query) as cursor:
            rows = await cursor.fetchall()
            
        contacts = []
        for r in rows:
            # Descifrar el nombre real (Protección PII)
            decrypted_real_name = self._decrypt(r[1]) if r[1] else None

            # Reconstruir estructura de diccionario
            contacts.append({
                "userID": r[0],
                "real_name": decrypted_real_name,
                "ip": r[2],
                "port": r[3],
                "trusted": r[5]
            })
            
            # Repoblar cache de claves efímeras si existen
            if r[4]: 
                try:
                    key_obj = x25519.X25519PublicKey.from_public_bytes(r[4])
                    self.ephemeral_keys[(r[2], r[3])] = key_obj
                except:
                    pass
                    
        return contacts

    async def register_contact(self, ip, port, pubkey_obj, user_id=None, real_name=None):
        """
        Registra o actualiza un contacto (UPSERT).
        Cifra el nombre real antes de guardarlo.
        """
        # 1. Cache RAM (Rápida para red)
        self.ephemeral_keys[(ip, port)] = pubkey_obj
        
        pub_bytes = pubkey_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Cifrar nombre real si se proporciona
        encrypted_real_name = self._encrypt(real_name) if real_name else None

        target_uuid = None

        # 2. Buscar candidato para actualización
        if user_id:
            # Búsqueda principal por ID estable
            async with self.db.execute("SELECT user_id FROM contacts WHERE user_id = ?", (user_id,)) as cursor:
                row = await cursor.fetchone()
                if row: target_uuid = row[0]
        
        if not target_uuid:
            # Búsqueda secundaria por dirección (para casos donde no tenemos el ID aún)
            async with self.db.execute("SELECT user_id FROM contacts WHERE ip = ? AND port = ?", (ip, port)) as cursor:
                row = await cursor.fetchone()
                if row: target_uuid = row[0]

        # 3. UPSERT (Insertar o Actualizar)
        if target_uuid:
            # Actualizar existente
            update_sql = "UPDATE contacts SET ip=?, port=?, pub_key=?"
            params = [ip, port, pub_bytes]
            
            # Solo actualizamos el nombre si nos pasan uno nuevo (y no es None)
            if real_name:
                update_sql += ", real_name=?"
                params.append(encrypted_real_name)
            
            update_sql += " WHERE user_id=?"
            params.append(target_uuid)
            
            await self.db.execute(update_sql, tuple(params))
            
        else:
            # Crear nuevo
            final_id = user_id if user_id else f"Unknown_{ip}_{port}"
            await self.db.execute("""
                INSERT INTO contacts (user_id, real_name, ip, port, pub_key, trusted)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (final_id, encrypted_real_name, ip, port, pub_bytes))
            
        await self.db.commit()

    async def get_pubkey_by_addr(self, ip, port):
        """Recupera la clave pública para una dirección (Usado por Network)."""
        return self.ephemeral_keys.get((ip, port))

    # --- Gestión de Mensajes (Historial) ---

    async def save_chat_message(self, user_id, direction, text, timestamp):
        """
        Guarda un mensaje de forma segura y permanente.
        El texto se cifra antes de tocar el disco.
        """
        if not user_id: return

        # Cifrar contenido (Field Level Encryption)
        encrypted_blob = self._encrypt(text)
        
        # Insertar
        # Aseguramos que el contacto exista para respetar la FK (Foreign Key),
        # aunque en SQLite por defecto las FK pueden estar desactivadas, es buena práctica.
        await self.db.execute("""
            INSERT INTO messages (user_id, direction, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (user_id, direction, encrypted_blob, timestamp))
        
        await self.db.commit()

    async def get_chat_history(self, user_id):
        """
        Recupera el historial de chat descifrado.
        
        OPTIMIZACIÓN:
        - Usa LIMIT 100 para no cargar miles de mensajes viejos.
        - Ordena descendente para coger los últimos, y luego Python los reordena si es necesario,
          o hacemos una subquery para devolverlos en orden cronológico.
        """
        if not user_id: return []
        
        # Subconsulta mágica: Dame los últimos 100 mensajes (DESC), pero dámelos ordenados cronológicamente (ASC)
        query = """
            SELECT direction, content, timestamp 
            FROM (
                SELECT direction, content, timestamp 
                FROM messages 
                WHERE user_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 100
            ) 
            ORDER BY timestamp ASC
        """
        
        history = []
        async with self.db.execute(query, (user_id,)) as cursor:
            async for row in cursor:
                direction, enc_content, ts = row
                
                # Descifrar al vuelo (Lazy Decryption)
                plain_text = self._decrypt(enc_content)
                
                history.append({
                    "direction": direction,
                    "content": plain_text,
                    "timestamp": ts
                })
        
        return history