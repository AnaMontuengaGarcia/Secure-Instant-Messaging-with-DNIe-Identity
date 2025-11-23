from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center, Middle
from textual.widgets import Header, Footer, Static, Input, ListView, ListItem, Label, Button, RichLog, TextArea, LoadingIndicator
from textual.screen import ModalScreen
from textual.binding import Binding
from textual import work
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
import asyncio
import pyperclip
import cryptography.hazmat.primitives.asymmetric.x25519 as x25519

# Importamos la tarjeta para usarla en la pantalla de login
from smartcard_dnie import DNIeCard

# --- PANTALLAS MODALES ---

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

# --- WIDGETS CHAT ---

class ChatItem(ListItem):
    def __init__(self, user_id, real_name, ip, port, verified=False):
        super().__init__()
        self.user_id = user_id
        self.real_name = real_name
        self.contact_ip = ip
        self.contact_port = port
        self.verified = verified
        
        self.update_label()

    def update_label(self):
        """Actualiza el texto mostrado basándose en el estado de verificación."""
        if self.real_name:
            if self.verified:
                # Nombre verificado (Handshake completo)
                self.display_label = f"👤 {self.real_name} ({self.contact_ip})"
            else:
                # Nombre conocido de DB pero no verificado en esta sesión
                self.display_label = f"❓ {self.real_name} (?) ({self.contact_ip})"
        else:
            # Solo tenemos el ID (Hash)
            self.display_label = f"👾 {self.user_id} ({self.contact_ip})"
            
        try:
            self.query_one(Label).update(self.display_label)
        except: pass

    def set_verified_identity(self, new_real_name):
        self.real_name = new_real_name
        self.verified = True
        self.update_label()

    def compose(self) -> ComposeResult:
        yield Label(self.display_label)

class ChatInput(TextArea):
    """
    Widget de entrada simplificado.
    Solo intercepta Enter para enviar. 
    Los saltos de línea se manejan vía Ctrl+N.
    """
    BINDINGS = [
        Binding("enter", "submit_message", "Send Message", show=True, priority=True),
        Binding("ctrl+n", "insert_newline", "Line Break (Ctrl+N)", show=True, priority=True),
        Binding("alt+enter", "insert_newline", "Line Break", show=False, priority=True),
        Binding("ctrl+enter", "insert_newline", "Line Break", show=False, priority=True),
    ]

    async def action_submit_message(self):
        await self.app.submit_message()

    def action_insert_newline(self):
        self.insert("\n")

# --- APP PRINCIPAL DE CHAT ---

class MessengerTUI(App):
    CSS = """
    Screen { layout: grid; grid-size: 2; grid-columns: 30% 70%; }
    .sidebar { background: $surface; border-right: solid $primary; }
    .chat-area { layout: vertical; }
    .logs { height: 30%; border-top: solid $secondary; background: $surface-darken-1; }
    .messages { height: 60%; padding: 1; }
    .input-container { dock: bottom; height: 6; layout: horizontal; padding: 0 1 1 1; }
    ChatInput { width: 1fr; height: 100%; border: solid $accent; } 
    #btn_send { height: 100%; width: 12; margin-left: 1; background: $primary; color: $text; }
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
        
        # Caché en memoria para nombres conocidos (ID -> Nombre Real)
        self.known_names = {} 

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(classes="sidebar"):
            yield Label("  📡 Discovered Peers", id="lbl_peers")
            yield ListView(id="contact_list")
        with Vertical(classes="chat-area"):
            yield RichLog(highlight=True, markup=True, id="chat_box", classes="messages", wrap=True)
            yield RichLog(highlight=True, markup=True, id="log_box", classes="logs")
            with Horizontal(classes="input-container"):
                yield ChatInput(show_line_numbers=False, id="msg_input")
                yield Button("SEND", id="btn_send")
        yield Footer()

    async def on_mount(self):
        self.title = "🇪🇸 DNIe Secure Messenger"
        
        # Cargar contactos conocidos para reconocer IDs
        contacts = await self.storage.get_all_contacts()
        for c in contacts:
            uid = c.get('userID')
            name = c.get('real_name')
            if uid and name:
                self.known_names[uid] = name
        
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

    def action_request_quit(self):
        self.push_screen(QuitScreen())

    def action_refresh_peers(self):
        self.add_log("🔄 Manual refresh...")
        self.discovery.refresh()

    def action_copy_last_message(self):
        if self.last_msg_content:
            try: pyperclip.copy(self.last_msg_content)
            except: self.add_log("❌ Clipboard error")

    def action_copy_logs(self):
        if self.log_buffer:
            try: pyperclip.copy("\n".join(self.log_buffer))
            except: pass

    def add_log(self, text):
        self.log_buffer.append(text)
        if len(self.log_buffer) > 1000: self.log_buffer.pop(0)
        try: self.query_one("#log_box", RichLog).write(text)
        except: pass

    def add_peer(self, user_id, ip, port, props):
        try: self.call_from_thread(self._add_peer_thread_safe, user_id, ip, port, props)
        except: self._add_peer_thread_safe(user_id, ip, port, props)

    def _add_peer_thread_safe(self, user_id, ip, port, props):
        try:
            lst = self.query_one("#contact_list", ListView)
            pub_hex = props.get('pub', '')
            
            # --- LIMPIEZA DE ID (SIMPLIFICADA) ---
            # Como network.py ya no añade sufijo, usamos el user_id tal cual
            stable_id = user_id
            
            # --- RESOLUCIÓN DE NOMBRE ---
            display_name = None
            verified_state = False
            
            if stable_id in self.known_names:
                display_name = self.known_names[stable_id]
            
            if pub_hex:
                try:
                    pub_bytes = bytes.fromhex(pub_hex)
                    pub_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                    task = asyncio.create_task(self.storage.register_contact(ip, port, pub_key, user_id=stable_id, real_name=None))
                except Exception: pass
            
            for child in lst.children:
                if isinstance(child, ChatItem) and child.contact_ip == ip and child.contact_port == port: return
            
            item = ChatItem(stable_id, display_name, ip, port, verified=verified_state)
            lst.append(item)
            
            log_msg = f"🔎 Peer Found: {stable_id}"
            if display_name:
                log_msg += f" (Known as: {display_name})"
            log_msg += f" @ {ip}"
            self.add_log(log_msg)
            
        except: pass

    def on_new_peer_handshake(self, addr, pub_key, real_name=None):
        try: self.call_from_thread(self._update_peer_identity_safe, addr, real_name)
        except: self._update_peer_identity_safe(addr, real_name)

    def _update_peer_identity_safe(self, addr, real_name):
        if not real_name: return
        lst = self.query_one("#contact_list", ListView)
        found = False
        
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == addr[0] and child.contact_port == addr[1]:
                # Actualizar item a VERIFICADO
                child.set_verified_identity(real_name)
                self.known_names[child.user_id] = real_name
                found = True
                
                # --- ACTUALIZACIÓN AUTOMÁTICA DEL HEADER ---
                if self.current_chat_addr == (child.contact_ip, child.contact_port):
                    self._refresh_chat_view(child)
                break
        
        if not found:
            self._add_peer_thread_safe(f"Unknown_{addr[0]}", addr[0], addr[1], {})
            self._update_peer_identity_safe(addr, real_name)

    def on_list_view_selected(self, event: ListView.Selected):
        item = event.item
        if not isinstance(item, ChatItem): return
        self.current_chat_addr = (item.contact_ip, item.contact_port)
        self._refresh_chat_view(item)

    def _refresh_chat_view(self, item: ChatItem):
        """Helper para renderizar el chat de un contacto específico."""
        chat_box = self.query_one("#chat_box", RichLog)
        chat_box.clear()
        
        target_name = item.real_name if item.real_name else item.user_id
        # Aquí se decide si mostrar Verified o Unverified
        status = "(Verified)" if item.verified else "(Unverified)"
        
        chat_box.write(f"Chatting with {target_name} {status}...\n")
        
        key = f"{item.contact_ip}:{item.contact_port}"
        if key in self.message_history:
            for msg in self.message_history[key]: chat_box.write(msg)

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
        try: self.call_from_thread(self._receive_message_thread_safe, addr, msg)
        except: self._receive_message_thread_safe(addr, msg)

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
        
        if not known: self._add_peer_thread_safe(f"Peer_{ip}", ip, port, {})
        
        text = msg.get('text', '')
        msg_panel = self._create_message_panel(text, peer_name, is_me=False)
        key = f"{ip}:{port}"
        self._save_history(key, msg_panel)
        curr_ip = self.current_chat_addr[0] if self.current_chat_addr else None
        if curr_ip == ip: self.query_one("#chat_box", RichLog).write(msg_panel)
        else: self.add_log(f"📨 New message from {peer_name}")

    def _create_message_panel(self, text, title, is_me):
        color = "green" if is_me else "yellow"
        return Align(Panel(Text(text), title=title, title_align="left", border_style=color, box=box.ROUNDED, padding=(0, 1), expand=False), align="left")

    def _save_history(self, key, item):
        if key not in self.message_history: self.message_history[key] = []
        self.message_history[key].append(item)

# --- NUEVA APP DE LOGIN DNIe (MEJORADA) ---

class DNIeLoginApp(App):
    CSS = """
    Screen { align: center middle; background: $surface; }
    .login-box { 
        width: 60; 
        height: auto; 
        border: thick $primary; 
        background: $surface-lighten-1;
        padding: 2;
    }
    #title { text-align: center; color: $secondary; text-style: bold; margin-bottom: 2; }
    #status { text-align: center; color: $text-muted; margin-bottom: 1; }
    
    /* Estilos para el estado del lector */
    #card-status { text-align: center; margin-bottom: 2; text-style: bold; }
    .card-missing { color: $error; }
    .card-present { color: $success; }
    
    #error-msg { text-align: center; color: $error; margin-top: 1; text-style: bold; display: none; }
    Input { margin-bottom: 2; }
    Button { width: 100%; }
    LoadingIndicator { height: 1; margin: 1 0; display: none; }
    """

    def __init__(self, key_to_sign_bytes):
        super().__init__()
        self.key_to_sign_bytes = key_to_sign_bytes
        self.return_data = None 
        self.is_logging_in = False # Flag para evitar conflictos con el detector

    def compose(self) -> ComposeResult:
        with Container(classes="login-box"):
            yield Label("🔐 DNIe Identity Access", id="title")
            
            # Indicadores de estado de la tarjeta
            yield Label("Buscando lector...", id="card-status", classes="card-missing")
            
            yield Label("Introduzca su PIN:", id="status")
            yield LoadingIndicator(id="loading")
            
            # Input y Botón desactivados por defecto hasta detectar tarjeta
            yield Input(placeholder="PIN del DNIe", password=True, id="pin", disabled=True)
            yield Button("Acceder", variant="primary", id="btn_login", disabled=True)
            yield Label("", id="error-msg")

    def on_mount(self):
        # Iniciamos el detector en bucle (cada 1.5s)
        self.set_interval(1.5, self.check_card_presence)
        # Check inicial inmediato
        self.check_card_presence()

    @work(thread=True)
    def check_card_presence(self):
        # Si el usuario está intentando loguearse, no tocamos el lector
        if self.is_logging_in: return

        is_present = False
        try:
            # Check rápido de conexión
            card = DNIeCard()
            if card.connect():
                is_present = True
                card.disconnect()
        except:
            is_present = False
        
        # Actualizar UI desde el hilo principal
        self.call_from_thread(self.update_card_ui, is_present)

    def update_card_ui(self, is_present: bool):
        # Si el usuario ya pulsó login, ignoramos actualizaciones
        if self.is_logging_in: return

        lbl = self.query_one("#card-status", Label)
        btn = self.query_one("#btn_login", Button)
        inp = self.query_one("#pin", Input)
        
        if is_present:
            if "card-present" not in lbl.classes:
                lbl.update("✅ TARJETA DETECTADA")
                lbl.remove_class("card-missing")
                lbl.add_class("card-present")
                btn.disabled = False
                inp.disabled = False
                if inp.value == "": inp.focus() # Auto-foco
        else:
            if "card-missing" not in lbl.classes:
                lbl.update("❌ NO SE DETECTA DNIe")
                lbl.remove_class("card-present")
                lbl.add_class("card-missing")
                btn.disabled = True
                inp.disabled = True

    def on_input_submitted(self, event: Input.Submitted):
        if not self.query_one("#btn_login", Button).disabled:
            self.action_login()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn_login":
            self.action_login()
    
    def action_login(self):
        pin = self.query_one("#pin", Input).value
        if not pin:
            self.show_error("⚠️ El PIN no puede estar vacío.")
            return
        
        self.is_logging_in = True # Bloqueamos el detector

        # UI Update
        self.query_one("#btn_login", Button).disabled = True
        self.query_one("#pin", Input).disabled = True
        self.query_one("#loading", LoadingIndicator).display = True
        self.query_one("#status", Label).update("Conectando con tarjeta inteligente...")
        self.query_one("#error-msg").display = False
        
        self.run_dnie_operation(pin)

    @work(exclusive=True, thread=True)
    def run_dnie_operation(self, pin):
        try:
            card = DNIeCard()
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Autenticando PIN..."))
            
            card.connect()
            card.authenticate(pin)
            
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Leyendo certificado..."))
            cert_der = card.get_certificate()
            
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Firmando identidad de red..."))
            signature = card.sign_data(self.key_to_sign_bytes)
            
            proofs = {'cert': cert_der.hex(), 'sig': signature.hex()}
            user_id = card.get_serial_hash()[:8]
            
            self.return_data = (user_id, proofs)
            self.call_from_thread(self.exit_success)
            
        except Exception as e:
            self.call_from_thread(lambda: self.show_error(f"❌ Error: {str(e)}"))
        finally:
            try: card.disconnect()
            except: pass

    def exit_success(self):
        self.exit(result=self.return_data)

    def show_error(self, msg):
        self.is_logging_in = False # Reactivamos el detector

        self.query_one("#loading", LoadingIndicator).display = False
        self.query_one("#status", Label).update("Introduzca su PIN:")
        
        btn = self.query_one("#btn_login", Button)
        btn.disabled = False
        
        inp = self.query_one("#pin", Input)
        inp.disabled = False
        inp.value = ""
        inp.focus()
        
        err_lbl = self.query_one("#error-msg", Label)
        err_lbl.update(msg)
        err_lbl.display = True