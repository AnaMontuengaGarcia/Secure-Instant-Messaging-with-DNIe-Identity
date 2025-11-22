from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, ListView, ListItem, Label, Button, RichLog
from textual.screen import ModalScreen
from textual.binding import Binding
import asyncio
import pyperclip
import cryptography.hazmat.primitives.asymmetric.x25519 as x25519

class QuitScreen(ModalScreen):
    CSS = """
    QuitScreen { align: center middle; }
    #dialog { grid-size: 2; grid-gutter: 1 2; grid-rows: 1fr 3; padding: 0 1; width: 60; height: 11; border: thick $background 80%; background: $surface; }
    #question { column-span: 2; height: 1fr; width: 1fr; content-align: center middle; }
    Button { width: 100%; }
    """
    def compose(self) -> ComposeResult:
        yield Container(
            Label("Are you sure you want to quit?", id="question"),
            Button("Quit", variant="error", id="quit"),
            Button("Cancel", variant="primary", id="cancel"),
            id="dialog",
        )
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit": self.app.exit()
        else: self.app.pop_screen()

class ChatItem(ListItem):
    def __init__(self, user_id, real_name, ip, port):
        super().__init__()
        self.user_id = user_id
        self.real_name = real_name
        self.contact_ip = ip
        self.contact_port = port
        
        # Lógica de visualización: Nombre Real (verificado) > UserID (técnico)
        if self.real_name:
            self.display_label = f"👤 {self.real_name} ({ip})"
        else:
            self.display_label = f"❓ {self.user_id} ({ip})"

    def update_real_name(self, new_real_name):
        self.real_name = new_real_name
        self.display_label = f"👤 {self.real_name} ({self.contact_ip})"
        try:
            # Intentar refrescar la etiqueta si ya está montada
            self.query_one(Label).update(self.display_label)
        except: pass

    def compose(self) -> ComposeResult:
        yield Label(self.display_label)

class MessengerTUI(App):
    CSS = """
    Screen { layout: grid; grid-size: 2; grid-columns: 30% 70%; }
    .sidebar { background: $surface; border-right: solid $primary; }
    .chat-area { layout: vertical; }
    .logs { height: 30%; border-top: solid $secondary; background: $surface-darken-1; }
    .messages { height: 60%; padding: 1; }
    Input { dock: bottom; }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "request_quit", "Quit"),
        Binding("c", "copy_last_message", "Copy Msg"),
        Binding("l", "copy_logs", "Copy Logs"),
        Binding("r", "refresh_peers", "Refresh Network"),
    ]

    def __init__(self, udp_protocol, discovery, storage, user_id, bind_ip=None):
        super().__init__()
        self.proto = udp_protocol
        self.discovery = discovery
        self.storage = storage
        self.user_id = user_id 
        self.bind_ip = bind_ip 
        self.current_chat_addr = None 
        self.message_history = {}
        self.last_msg_content = ""
        self.log_buffer = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(classes="sidebar"):
            yield Label("  📡 Discovered Peers", id="lbl_peers")
            yield ListView(id="contact_list")
        with Vertical(classes="chat-area"):
            yield RichLog(highlight=True, markup=True, id="chat_box", classes="messages")
            yield RichLog(highlight=True, markup=True, id="log_box", classes="logs")
            yield Input(placeholder="Type secure message...", id="msg_input")
        yield Footer()

    async def on_mount(self):
        self.title = "🇪🇸 DNIe Secure Messenger"
        
        self.proto.on_log = self.add_log
        self.proto.on_message = self.receive_message
        self.proto.on_handshake_success = self.on_new_peer_handshake
        
        self.discovery.on_found = self.add_peer
        self.discovery.on_log = self.add_log 
        
        self.query_one("#chat_box", RichLog).write("Select a contact to chat")
        self.add_log(f"System initializing for {self.user_id}...")

        username = f"User-{self.user_id}"
        await self.discovery.start(username, bind_ip=self.bind_ip)

    def action_request_quit(self):
        self.push_screen(QuitScreen())

    def action_refresh_peers(self):
        self.add_log("🔄 Manual refresh...")
        self.discovery.refresh()

    def action_copy_last_message(self):
        if self.last_msg_content:
            try:
                pyperclip.copy(self.last_msg_content)
                self.notify("Copied!")
            except: self.add_log("❌ Clipboard error")

    def action_copy_logs(self):
        if self.log_buffer:
            try:
                pyperclip.copy("\n".join(self.log_buffer))
                self.notify("Logs copied!")
            except: pass

    def add_log(self, text):
        self.log_buffer.append(text)
        if len(self.log_buffer) > 1000: self.log_buffer.pop(0)
        try: self.query_one("#log_box", RichLog).write(text)
        except: pass

    def add_peer(self, user_id, ip, port, props):
        try:
            self.call_from_thread(self._add_peer_thread_safe, user_id, ip, port, props)
        except:
            self._add_peer_thread_safe(user_id, ip, port, props)

    def _add_peer_thread_safe(self, user_id, ip, port, props):
        try:
            lst = self.query_one("#contact_list", ListView)
            
            # REGISTRO DE USUARIO DESCUBIERTO (Aún sin nombre real confirmado)
            pub_hex = props.get('pub', '')
            if pub_hex:
                try:
                    pub_bytes = bytes.fromhex(pub_hex)
                    pub_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                    
                    # Registramos con user_id (ID técnico), real_name=None de momento
                    task = asyncio.create_task(self.storage.register_contact(ip, port, pub_key, user_id=user_id, real_name=None))
                    
                    def handle_db_result(t):
                        try: t.result()
                        except Exception as db_err:
                            print(f"DB ERROR: {db_err}")      
                    task.add_done_callback(handle_db_result)
                    
                except Exception as key_err:
                    self.add_log(f"⚠️ Key Error for {user_id}: {key_err}")

            # Evitar duplicados visuales
            for child in lst.children:
                if isinstance(child, ChatItem):
                    if child.contact_ip == ip and child.contact_port == port:
                        # Si ya existe y ahora tenemos un ID mejor, podríamos actualizarlo, pero por simplicidad retornamos
                        return
            
            # Crear item visual. user_id es el técnico, real_name es None inicialmente
            clean_id = user_id.split('.')[0]
            item = ChatItem(clean_id, None, ip, port)
            lst.append(item)
            self.add_log(f"🔎 Peer Found: {clean_id} ({ip})")
        except Exception as e:
            self.add_log(f"⚠️ UI Error adding peer: {e}")

    def on_new_peer_handshake(self, addr, pub_key, real_name=None):
        """Callback cuando se completa un handshake y verificamos identidad real"""
        try:
            self.call_from_thread(self._update_peer_identity_safe, addr, real_name)
        except:
            self._update_peer_identity_safe(addr, real_name)

    def _update_peer_identity_safe(self, addr, real_name):
        if not real_name: return
        
        lst = self.query_one("#contact_list", ListView)
        found = False
        for child in lst.children:
            if isinstance(child, ChatItem):
                if child.contact_ip == addr[0] and child.contact_port == addr[1]:
                    child.update_real_name(real_name)
                    child.refresh()
                    found = True
                    break
        
        if not found:
            # Si el peer hizo handshake pero no fue descubierto por mDNS antes
            self._add_peer_thread_safe(f"Unknown_{addr[0]}", addr[0], addr[1], {})
            # Luego recursivamente actualizamos su nombre
            self._update_peer_identity_safe(addr, real_name)

    def on_list_view_selected(self, event: ListView.Selected):
        item = event.item
        if not isinstance(item, ChatItem): return
        self.current_chat_addr = (item.contact_ip, item.contact_port)
        chat_box = self.query_one("#chat_box", RichLog)
        chat_box.clear()
        
        name_display = item.real_name if item.real_name else item.user_id
        chat_box.write(f"Chatting with {name_display}...\n")
        
        key = f"{item.contact_ip}:{item.contact_port}"
        if key in self.message_history:
            for line in self.message_history[key]: chat_box.write(line)

    async def on_input_submitted(self, event: Input.Submitted):
        if not self.current_chat_addr:
            self.add_log("⚠️ Select a contact first!")
            return
        text = event.value
        if not text: return
        event.input.value = ""
        
        formatted_msg = f"[bold green][You]:[/] {text}"
        self.last_msg_content = text
        
        key = f"{self.current_chat_addr[0]}:{self.current_chat_addr[1]}"
        self._save_history(key, formatted_msg)
        self.query_one("#chat_box", RichLog).write(formatted_msg)
        
        await self.proto.send_message(self.current_chat_addr, text)

    def receive_message(self, addr, msg):
        try:
            self.call_from_thread(self._receive_message_thread_safe, addr, msg)
        except:
            self._receive_message_thread_safe(addr, msg)

    def _receive_message_thread_safe(self, addr, msg):
        ip, port = addr
        
        # Asegurar que el peer existe en la lista
        lst = self.query_one("#contact_list", ListView)
        known = False
        peer_name = f"Peer_{ip}"
        
        for child in lst.children:
             if isinstance(child, ChatItem) and child.contact_ip == ip and child.contact_port == port:
                 known = True
                 peer_name = child.real_name if child.real_name else child.user_id
                 break
        if not known:
             self._add_peer_thread_safe(f"Peer_{ip}", ip, port, {})

        text = msg.get('text', '')
        self.last_msg_content = text
        formatted_msg = f"[bold yellow][{peer_name}]:[/] {text}"
        key = f"{ip}:{port}"
        self._save_history(key, formatted_msg)
        
        curr_ip = self.current_chat_addr[0] if self.current_chat_addr else None
        if curr_ip == ip:
            self.query_one("#chat_box", RichLog).write(formatted_msg)
        else:
            self.add_log(f"📨 New message from {peer_name}")

    def _save_history(self, key, line):
        if key not in self.message_history: self.message_history[key] = []
        self.message_history[key].append(line)