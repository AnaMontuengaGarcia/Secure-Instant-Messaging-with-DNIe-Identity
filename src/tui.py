from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, ListView, ListItem, Label, Button, RichLog, TextArea
from textual.screen import ModalScreen
from textual.binding import Binding
from textual import events
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
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
        
        if self.real_name:
            self.display_label = f"👤 {self.real_name} ({ip})"
        else:
            self.display_label = f"❓ {self.user_id} ({ip})"

    def update_real_name(self, new_real_name):
        self.real_name = new_real_name
        self.display_label = f"👤 {self.real_name} ({self.contact_ip})"
        try:
            self.query_one(Label).update(self.display_label)
        except: pass

    def compose(self) -> ComposeResult:
        yield Label(self.display_label)

class ChatInput(TextArea):
    """
    Widget de entrada simplificado.
    Solo intercepta Enter para enviar. 
    Los saltos de línea se manejan vía botón de la interfaz.
    """
    BINDINGS = [
        # Enter siempre envía. priority=True evita que TextArea inserte un salto de línea normal.
        Binding("enter", "submit_message", "Send Message", show=True, priority=True),
    ]

    async def action_submit_message(self):
        """Acción vinculada a la tecla Enter: Enviar mensaje"""
        await self.app.submit_message()

class MessengerTUI(App):
    CSS = """
    Screen { layout: grid; grid-size: 2; grid-columns: 30% 70%; }
    .sidebar { background: $surface; border-right: solid $primary; }
    .chat-area { layout: vertical; }
    .logs { height: 30%; border-top: solid $secondary; background: $surface-darken-1; }
    .messages { height: 60%; padding: 1; }
    
    /* Contenedor inferior para input y controles */
    .input-container { 
        dock: bottom; 
        height: 6; 
        layout: horizontal;
        padding: 0 1 1 1;
    }
    
    ChatInput { 
        width: 1fr; 
        height: 100%; 
        border: solid $accent;
    } 
    
    /* Botón de enviar (a la derecha) */
    #btn_send {
        height: 100%;
        width: 12;
        margin-left: 1;
        background: $primary;
        color: $text;
    }

    /* Botón pequeño de salto de línea (a la izquierda) */
    #btn_newline {
        height: 100%;
        width: 5;          /* Ancho aumentado a 5 */
        min-width: 5;      
        padding: 0;        
        margin-right: 1;   /* Margen derecho para separar del input */
        background: $secondary;
        color: $text;
        text-align: center;
        content-align: center middle;
    }
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
            yield RichLog(highlight=True, markup=True, id="chat_box", classes="messages", wrap=True)
            yield RichLog(highlight=True, markup=True, id="log_box", classes="logs")
            
            with Horizontal(classes="input-container"):
                # Botón pequeño para salto de línea (IZQUIERDA)
                yield Button("↵", id="btn_newline", tooltip="Insert Line Break")
                # Cuadro de texto (CENTRO)
                yield ChatInput(show_line_numbers=False, id="msg_input")
                # Botón grande para enviar (DERECHA)
                yield Button("SEND", id="btn_send")
                
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

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_send":
            await self.submit_message()
        
        elif event.button.id == "btn_newline":
            # Lógica manual para insertar salto de línea
            inp = self.query_one("#msg_input", ChatInput)
            inp.insert("\n")
            # Devolver el foco al input para seguir escribiendo
            inp.focus()

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
            
            pub_hex = props.get('pub', '')
            if pub_hex:
                try:
                    pub_bytes = bytes.fromhex(pub_hex)
                    pub_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                    
                    task = asyncio.create_task(self.storage.register_contact(ip, port, pub_key, user_id=user_id, real_name=None))
                    
                    def handle_db_result(t):
                        try: t.result()
                        except Exception as db_err:
                            print(f"DB ERROR: {db_err}")      
                    task.add_done_callback(handle_db_result)
                    
                except Exception as key_err:
                    self.add_log(f"⚠️ Key Error for {user_id}: {key_err}")

            for child in lst.children:
                if isinstance(child, ChatItem):
                    if child.contact_ip == ip and child.contact_port == port:
                        return
            
            clean_id = user_id.split('.')[0]
            item = ChatItem(clean_id, None, ip, port)
            lst.append(item)
            self.add_log(f"🔎 Peer Found: {clean_id} ({ip})")
        except Exception as e:
            self.add_log(f"⚠️ UI Error adding peer: {e}")

    def on_new_peer_handshake(self, addr, pub_key, real_name=None):
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
            self._add_peer_thread_safe(f"Unknown_{addr[0]}", addr[0], addr[1], {})
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
            for msg_renderable in self.message_history[key]: 
                chat_box.write(msg_renderable)

    async def submit_message(self):
        ta = self.query_one("#msg_input", ChatInput)
        text = ta.text.strip()
        if not text: return
        
        ta.text = "" 
        
        if not self.current_chat_addr:
            self.add_log("⚠️ Select a contact first!")
            return

        self.last_msg_content = text
        msg_panel = self._create_message_panel(text, "You", is_me=True)
        key = f"{self.current_chat_addr[0]}:{self.current_chat_addr[1]}"
        self._save_history(key, msg_panel)
        self.query_one("#chat_box", RichLog).write(msg_panel)
        
        await self.proto.send_message(self.current_chat_addr, text)

    def receive_message(self, addr, msg):
        try:
            self.call_from_thread(self._receive_message_thread_safe, addr, msg)
        except:
            self._receive_message_thread_safe(addr, msg)

    def _receive_message_thread_safe(self, addr, msg):
        ip, port = addr
        
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
        
        msg_panel = self._create_message_panel(text, peer_name, is_me=False)
        
        key = f"{ip}:{port}"
        self._save_history(key, msg_panel)
        
        curr_ip = self.current_chat_addr[0] if self.current_chat_addr else None
        if curr_ip == ip:
            self.query_one("#chat_box", RichLog).write(msg_panel)
        else:
            self.add_log(f"📨 New message from {peer_name}")

    def _create_message_panel(self, text, title, is_me):
        color = "green" if is_me else "yellow"
        align_side = "left" 
        
        return Align(
            Panel(
                Text(text),
                title=title,
                title_align="left",
                border_style=color,
                box=box.ROUNDED,
                padding=(0, 1),
                expand=False 
            ),
            align=align_side
        )

    def _save_history(self, key, item):
        if key not in self.message_history: self.message_history[key] = []
        self.message_history[key].append(item)