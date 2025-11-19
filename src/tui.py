from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, ListView, ListItem, Label, Button, RichLog
from textual.binding import Binding
import asyncio

class ChatItem(ListItem):
    def __init__(self, name, ip):
        super().__init__()
        self.contact_name = name
        self.contact_ip = ip
        self.add_child(Label(f"{name} ({ip})"))

class MessengerTUI(App):
    CSS = """
    Screen { layout: grid; grid-size: 2; grid-columns: 30% 70%; }
    .sidebar { background: $surface; border-right: solid $primary; }
    .chat-area { layout: vertical; }
    .logs { height: 30%; border-top: solid $secondary; background: $surface-darken-1; }
    .messages { height: 60%; padding: 1; }
    Input { dock: bottom; }
    """
    
    BINDINGS = [("ctrl+q", "quit", "Quit")]

    def __init__(self, udp_protocol, discovery, storage):
        super().__init__()
        self.proto = udp_protocol
        self.discovery = discovery
        self.storage = storage
        self.current_chat_ip = None
        # Historial simple en memoria: IP -> lista de strings formateados
        self.message_history = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(classes="sidebar"):
            yield Label("  📡 Discovered Peers", id="lbl_peers")
            yield ListView(id="contact_list")
        with Vertical(classes="chat-area"):
            # Usamos RichLog para permitir scroll y append (.write)
            yield RichLog(highlight=True, markup=True, id="chat_box", classes="messages")
            yield RichLog(highlight=True, markup=True, id="log_box", classes="logs")
            yield Input(placeholder="Type secure message...", id="msg_input")
        yield Footer()

    def on_mount(self):
        self.title = "🇪🇸 DNIe Secure Messenger"
        # Hook up callbacks
        self.proto.on_log = self.add_log
        self.proto.on_message = self.receive_message
        self.discovery.on_found = self.add_peer
        
        # Mensajes iniciales
        self.query_one("#chat_box", RichLog).write("Select a contact to chat")
        self.query_one("#log_box", RichLog).write("System Logs...")

    def add_log(self, text):
        """Agrega un log. Se llama desde el mismo loop de eventos, actualización directa."""
        # CORREGIDO: Eliminado call_from_thread
        log_box = self.query_one("#log_box", RichLog)
        log_box.write(text)

    def add_peer(self, name, ip, props):
        """Agrega un peer descubierto. Actualización directa."""
        # CORREGIDO: Eliminado call_from_thread
        lst = self.query_one("#contact_list", ListView)
        
        # Registrar clave pública si viene en el descubrimiento
        pub_hex = props.get('pub', '')
        if pub_hex:
            try:
                import cryptography.hazmat.primitives.asymmetric.x25519 as x25519
                pub_bytes = bytes.fromhex(pub_hex)
                pub_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                # Lanzamos tarea asíncrona para guardar en DB
                asyncio.create_task(self.storage.register_contact(ip, pub_key, props.get('user', name)))
            except:
                pass

        # Evitar duplicados visuales
        for child in lst.children:
            if child.contact_ip == ip: return
        
        item = ChatItem(props.get('user', name), ip)
        lst.append(item)
        self.add_log(f"🔎 Found peer: {name} at {ip}")

    def on_list_view_selected(self, event: ListView.Selected):
        item = event.item
        self.current_chat_ip = item.contact_ip
        chat_box = self.query_one("#chat_box", RichLog)
        chat_box.clear()
        chat_box.write(f"Chatting with {item.contact_name}...\n")
        
        # Restaurar historial si existe
        if self.current_chat_ip in self.message_history:
            for line in self.message_history[self.current_chat_ip]:
                chat_box.write(line)

    async def on_input_submitted(self, event: Input.Submitted):
        if not self.current_chat_ip:
            self.add_log("⚠️ Select a contact first!")
            return
        
        text = event.value
        event.input.value = ""
        
        # Formatear y guardar mensaje propio
        formatted_msg = f"[bold green][You]:[/] {text}"
        self._save_history(self.current_chat_ip, formatted_msg)
        
        # Actualizar UI
        chat = self.query_one("#chat_box", RichLog)
        chat.write(formatted_msg)
        
        # Enviar por red
        self.proto.send_message((self.current_chat_ip, 443), text)

    def receive_message(self, addr, msg):
        """Recibe mensaje. Actualización directa."""
        # CORREGIDO: Eliminado call_from_thread
        ip = addr[0]
        text = msg.get('text', '')
        formatted_msg = f"[bold yellow][Peer]:[/] {text}"
        
        self._save_history(ip, formatted_msg)
        
        if self.current_chat_ip == ip:
            chat = self.query_one("#chat_box", RichLog)
            chat.write(formatted_msg)
        else:
            self.add_log(f"📨 New message from {ip}")

    def _save_history(self, ip, line):
        if ip not in self.message_history:
            self.message_history[ip] = []
        self.message_history[ip].append(line)