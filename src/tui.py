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
import time  # Necesario para controlar el tiempo (timestamp)
from datetime import datetime
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
    def __init__(self, user_id, real_name, ip, port, verified=False, online=False):
        super().__init__()
        self.user_id = user_id
        self.real_name = real_name
        self.contact_ip = ip
        self.contact_port = port
        self.verified = verified
        self.online = online  # Estado de conexión
        
        self.update_label()

    def set_online_status(self, is_online):
        """Actualiza el estado online/offline y refresca la etiqueta visualmente"""
        if self.online != is_online:
            self.online = is_online
            self.update_label()

    def update_address(self, new_ip, new_port):
        """Actualiza la dirección IP/Puerto si cambia por DHCP"""
        self.contact_ip = new_ip
        self.contact_port = new_port
        self.update_label()

    def update_label(self):
        """Actualiza el texto mostrado basándose en el estado de verificación y conexión."""
        
        # Determinar el color y símbolo del estado
        if self.online:
            status_icon = "[green]●[/]" # Círculo verde para online
            status_text = "Online"
        else:
            status_icon = "[grey50]●[/]" # Círculo gris para offline
            status_text = "Offline"

        # Construcción del nombre a mostrar
        if self.real_name:
            if self.verified:
                # Nombre verificado (Handshake completo)
                display_name = f"{self.real_name}"
            else:
                # Nombre conocido de DB pero no verificado en esta sesión
                display_name = f"{self.real_name} (?)"
        else:
            # Solo tenemos el ID (Hash)
            display_name = f"{self.user_id}"

        # Composición final usando Rich Text markup
        # Formato: ● Nombre (IP)
        # Mostramos siempre la IP actual conocida
        self.display_label = f"{status_icon} {display_name} [dim]({self.contact_ip})[/]"
            
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
        
        # Diccionario para rastrear la última vez que vimos un paquete mDNS
        # Key: user_id, Value: timestamp (time.time())
        self.peer_last_seen = {}

        # Diccionario para ignorar paquetes mDNS temporales tras desconexión explícita
        # Key: user_id, Value: timestamp de desconexión
        self.recently_disconnected = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(classes="sidebar"):
            yield Label("  📡 Contactos", id="lbl_peers")
            yield ListView(id="contact_list")
        with Vertical(classes="chat-area"):
            yield RichLog(highlight=True, markup=True, id="chat_box", classes="messages", wrap=True)
            yield RichLog(highlight=True, markup=True, id="log_box", classes="logs")
            with Horizontal(classes="input-container"):
                yield ChatInput(show_line_numbers=False, id="msg_input")
                yield Button("SEND", id="btn_send")
        yield Footer()

    async def on_mount(self):
        self.title = "DNIe Secure Messenger"
        
        # 1. Cargar contactos guardados desde disco
        await self.load_saved_contacts()
        
        # Configurar callbacks
        self.proto.on_log = self.add_log
        self.proto.on_message = self.receive_message
        self.proto.on_handshake_success = self.on_new_peer_handshake
        self.discovery.on_found = self.add_peer
        self.discovery.on_log = self.add_log 
        
        self.query_one("#chat_box", RichLog).write("Selecciona un contacto para chatear.")
        self.add_log(f"System initializing for {self.user_id}...")
        
        # Iniciar servicio de descubrimiento
        username = f"User-{self.user_id}"
        await self.discovery.start(username, bind_ip=self.bind_ip)
        
        # Iniciar temporizador para comprobar estado Online/Offline cada 5 segundos
        self.set_interval(5.0, self.check_peer_status)

    async def load_saved_contacts(self):
        """Carga contactos del JSON y los añade a la lista como Offline inicialmente."""
        contacts = await self.storage.get_all_contacts()
        lst = self.query_one("#contact_list", ListView)
        
        loaded_count = 0
        for c in contacts:
            uid = c.get('userID')
            name = c.get('real_name')
            ip = c.get('ip')
            port = c.get('port')
            
            # Filtro: Solo cargamos si existe un nombre real
            if uid and name:
                self.known_names[uid] = name
                # Comprobar duplicados antes de añadir (por seguridad)
                exists = False
                for child in lst.children:
                    if isinstance(child, ChatItem) and child.user_id == uid:
                        exists = True
                        break
                
                if not exists:
                    # Offline por defecto
                    item = ChatItem(uid, name, ip, port, verified=False, online=False)
                    lst.append(item)
                    loaded_count += 1
        
        self.add_log(f"📚 {loaded_count} Contactos verificados cargados.")

    def check_peer_status(self):
        """
        Se ejecuta periódicamente.
        Comprueba si han pasado más de 20 segundos desde el último mDNS de cada peer.
        """
        now = time.time()
        lst = self.query_one("#contact_list", ListView)
        
        for child in lst.children:
            if isinstance(child, ChatItem):
                last_seen = self.peer_last_seen.get(child.user_id, 0)
                # Si han pasado menos de 20s, está online. Si no, offline.
                is_online = (now - last_seen) < 20.0
                child.set_online_status(is_online)

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
        """
        Llamado cuando el DiscoveryService recibe un mDNS packet.
        """
        # FILTRO: Ignorar paquetes mDNS que provienen de la loopback (127.0.0.1)
        if ip == "127.0.0.1":
            return
        
        stable_id = user_id.strip()

        # FILTRO DE REBOTE DE DESCONEXIÓN:
        if stable_id in self.recently_disconnected:
            if time.time() - self.recently_disconnected[stable_id] < 5.0:
                return
            else:
                del self.recently_disconnected[stable_id]

        self.peer_last_seen[stable_id] = time.time()
        
        try: self.call_from_thread(self._add_peer_thread_safe, stable_id, ip, port, props)
        except: self._add_peer_thread_safe(stable_id, ip, port, props)

    def _add_peer_thread_safe(self, user_id, ip, port, props):
        try:
            lst = self.query_one("#contact_list", ListView)
            
            # --- MANEJO DE DESCONEXIÓN EXPLÍCITA (CUSTOM MDNS GOODBYE) ---
            # Si el paquete mDNS trae 'stat=exit', es nuestra implementación custom de desconexión.
            if props.get('stat') == 'exit':
                self.add_log(f"💤 Recibida señal de salida de {user_id} (Multicast)")
                
                # Buscar al usuario y ponerlo offline
                target_child = None
                for child in lst.children:
                    if isinstance(child, ChatItem) and child.user_id == user_id:
                        target_child = child
                        break
                
                if target_child:
                    # Registrar desconexión para evitar rebotes
                    self.recently_disconnected[user_id] = time.time()
                    self.peer_last_seen[user_id] = 0 # Forzar timeout inmediato
                    target_child.set_online_status(False)
                    
                    # Log en el chat si está activo
                    disconnect_panel = Align(Panel(Text(f"{target_child.real_name or user_id} se ha desconectado (Global)."), style="dim white"), align="left")
                    key = f"{ip}:{port}"
                    self._save_history(key, disconnect_panel)
                    if self.current_chat_addr == (ip, port):
                        self.query_one("#chat_box", RichLog).write(disconnect_panel)
                
                # Detenemos el procesamiento, no registramos nada.
                return
            # -------------------------------------------------------------

            pub_hex = props.get('pub', '')
            
            # --- 1. LLAMADA A STORAGE UNIFICADA ---
            # Solo registramos si NO es una señal de salida
            if pub_hex:
                try:
                    pub_bytes = bytes.fromhex(pub_hex)
                    pub_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                    asyncio.create_task(self.storage.register_contact(ip, port, pub_key, user_id=user_id, real_name=None))
                except Exception: pass

            # --- 2. ACTUALIZACIÓN VISUAL (UI) ---
            found_item = None
            for child in lst.children:
                if isinstance(child, ChatItem) and child.user_id == user_id:
                    found_item = child
                    break
            
            if found_item:
                # El usuario YA existe en la lista
                was_offline = not found_item.online

                if found_item.contact_ip != ip or found_item.contact_port != port:
                    old_addr = f"{found_item.contact_ip}:{found_item.contact_port}"
                    new_addr = f"{ip}:{port}"
                    self.add_log(f"🔄 Network Change: {user_id} moved {old_addr} -> {new_addr}")
                    found_item.update_address(ip, port)
                    
                    if self.current_chat_addr and (self.current_chat_addr[0] == old_addr.split(':')[0]):
                        self.current_chat_addr = (ip, port)
                        self._refresh_chat_view(found_item)
                        self.add_log("⚡ Active chat session rerouted to new IP.")
                    was_offline = True

                found_item.set_online_status(True)
                
                if was_offline:
                    try:
                        addr_tuple = (ip, port)
                        if addr_tuple in self.proto.sessions.sessions:
                            del self.proto.sessions.sessions[addr_tuple]
                            self.add_log(f"🔄 Session reset for {found_item.real_name or user_id} (Reconnected)")
                    except Exception as e:
                        print(f"Error resetting session: {e}")

                if not found_item.real_name:
                     display_name = self.known_names.get(user_id)
                     if display_name:
                         found_item.real_name = display_name
                         found_item.update_label()

            else:
                display_name = self.known_names.get(user_id)
                item = ChatItem(user_id, display_name, ip, port, verified=False, online=True)
                lst.append(item)
                
                log_msg = f"🔎 Peer Found: {user_id}"
                if display_name:
                    log_msg += f" (Known as: {display_name})"
                log_msg += f" @ {ip}"
                self.add_log(log_msg)
            
        except Exception as e: 
            self.add_log(f"Error updating UI peer: {e}")

    def on_new_peer_handshake(self, addr, pub_key, real_name=None):
        try: self.call_from_thread(self._update_peer_identity_safe, addr, real_name)
        except: self._update_peer_identity_safe(addr, real_name)

    def _update_peer_identity_safe(self, addr, real_name):
        if not real_name: return
        lst = self.query_one("#contact_list", ListView)
        found = False
        
        # Buscar por IP/Puerto para el handshake inicial
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == addr[0] and child.contact_port == addr[1]:
                child.set_verified_identity(real_name)
                self.known_names[child.user_id] = real_name
                found = True
                
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
        status = "(Verified)" if item.verified else "(Unverified)"
        conn_status = "[green]ONLINE[/]" if item.online else "[grey]OFFLINE[/]"
        
        chat_box.write(f"Chatting with {target_name} {status} - {conn_status}\n")
        
        # Recuperamos historial usando la combinación IP:Port actual
        key = f"{item.contact_ip}:{item.contact_port}"
        if key in self.message_history:
            for msg in self.message_history[key]: chat_box.write(msg)

    async def submit_message(self):
        ta = self.query_one("#msg_input", ChatInput)
        text = ta.text.strip()
        if not text: return
        
        if not self.current_chat_addr:
            self.add_log("⚠️ Select a contact first!")
            return
            
        # --- VERIFICACIÓN DE ESTADO ONLINE ---
        target_item = None
        lst = self.query_one("#contact_list", ListView)
        # Buscar el item seleccionado actualmente
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == self.current_chat_addr[0] and child.contact_port == self.current_chat_addr[1]:
                target_item = child
                break
        
        if target_item:
            if not target_item.online:
                self.add_log(f"⛔ Cannot send message: {target_item.real_name or target_item.user_id} is OFFLINE.")
                return
        else:
             self.add_log("❌ Error: Contact not found in list context.")
             return
        # --------------------------------------

        ta.text = "" 
        self.last_msg_content = text
        now_ts = time.time()
        msg_panel = self._create_message_panel(text, "You", is_me=True, timestamp=now_ts)
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
        
        target_child = None

        for child in lst.children:
             if isinstance(child, ChatItem) and child.contact_ip == ip and child.contact_port == port:
                 known = True
                 peer_name = child.real_name if child.real_name else child.user_id
                 target_child = child
                 break
        
        # Si no lo conocemos y es solo un mensaje de desconexión, ignoramos.
        if not known and msg.get('disconnect'):
            return

        if not known: 
            self._add_peer_thread_safe(f"Peer_{ip}", ip, port, {})
            # Recuperamos el child recién creado
            if lst.children:
                target_child = lst.children[-1]

        # --- LÓGICA DE DESCONEXIÓN (Mensaje cifrado UDP) ---
        if msg.get('disconnect') is True:
            if target_child:
                self.peer_last_seen[target_child.user_id] = 0
                self.recently_disconnected[target_child.user_id] = time.time()
                target_child.set_online_status(False)
                self.add_log(f"💤 {peer_name} has disconnected (Graceful exit).")
                
                disconnect_panel = Align(Panel(Text(f"{peer_name} se ha desconectado."), style="dim white"), align="left")
                key = f"{ip}:{port}"
                self._save_history(key, disconnect_panel)
                
                if self.current_chat_addr == (ip, port):
                    self.query_one("#chat_box", RichLog).write(disconnect_panel)
            return
        # -----------------------------
        
        if target_child:
            self.peer_last_seen[target_child.user_id] = time.time()
            target_child.set_online_status(True)
        
        text = msg.get('text', '')
        if not text: return # Protección extra

        ts = msg.get('timestamp') 
        msg_panel = self._create_message_panel(text, peer_name, is_me=False, timestamp=ts)
        key = f"{ip}:{port}"
        self._save_history(key, msg_panel)
        curr_ip = self.current_chat_addr[0] if self.current_chat_addr else None
        if curr_ip == ip: self.query_one("#chat_box", RichLog).write(msg_panel)
        else: self.add_log(f"📨 New message from {peer_name}")

    def _create_message_panel(self, text, title, is_me, timestamp=None):
        color = "green" if is_me else "yellow"
        
        # Si recibimos un timestamp, lo formateamos y añadimos al título
        if timestamp:
            # Formato: 14:30 (si quieres fecha completa usa "%d/%m/%Y %H:%M")
            ts_str = datetime.fromtimestamp(timestamp).strftime("%H:%M")
            title = f"{title} [{ts_str}]"
            
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