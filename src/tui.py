"""
Interfaz de Usuario en Terminal (TUI)
-------------------------------------
Implementada usando la librería `Textual` (Modern Python TUI).
Este módulo gestiona toda la presentación visual, pantallas modales y bucle de eventos UI.

Componentes:
1. MessengerTUI: La aplicación principal de chat.
2. DNIeLoginApp: La pantalla inicial de login y PIN.
3. Widgets personalizados para mensajes y listas de contactos.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Center, Middle
from textual.widgets import Header, Footer, Static, Input, ListView, ListItem, Label, Button, RichLog, TextArea, LoadingIndicator
from textual.screen import ModalScreen
from textual.binding import Binding
from textual import work
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich import box
import asyncio
import time 
import hashlib
from datetime import datetime
import pyperclip
import cryptography.hazmat.primitives.asymmetric.x25519 as x25519
from smartcard_dnie import DNIeCard

# --- PANTALLAS MODALES ---

class QuitScreen(ModalScreen):
    """Pantalla modal de confirmación para salir de la aplicación."""
    CSS = """
    QuitScreen { align: center middle; }
    #dialog { grid-size: 2; grid-gutter: 1 2; grid-rows: 1fr 3; padding: 0 1; width: 60; height: 11; border: thick $background 80%; background: $surface; }
    #question { column-span: 2; height: 1fr; width: 1fr; content-align: center middle; }
    Button { width: 100%; }
    """
    
    def compose(self) -> ComposeResult:
        yield Container(
            Label("¿Seguro que quieres salir?", id="question"),
            Button("Salir", variant="error", id="quit"),
            Button("Cancelar", variant="primary", id="cancel"),
            id="dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit": self.app.exit()
        else: self.app.pop_screen()

# --- WIDGETS CHAT ---

class ChatItem(ListItem):
    """
    Elemento de la lista de contactos.
    Muestra estado de conexión (punto verde/gris), nombre verificado e IP.
    """
    def __init__(self, user_id, real_name, ip, port, verified=False, online=False):
        super().__init__()
        self.user_id = user_id
        self.real_name = real_name
        self.contact_ip = ip
        self.contact_port = port
        self.verified = verified
        self.online = online  
        self.update_label()

    def set_online_status(self, is_online):
        """Actualiza visualmente si el contacto está conectado."""
        if self.online != is_online:
            self.online = is_online
            self.update_label()

    def update_address(self, new_ip, new_port):
        self.contact_ip = new_ip
        self.contact_port = new_port
        self.update_label()

    def update_label(self):
        """Re-renderiza el texto del widget usando Rich text."""
        if self.online:
            status_icon = "[green]●[/]" 
        else:
            status_icon = "[grey50]●[/]" 

        if self.real_name:
            if self.verified:
                display_name = f"{self.real_name}"
            else:
                display_name = f"{self.real_name} (?)"
        else:
            display_name = f"{self.user_id}"

        self.display_label = f"{status_icon} {display_name} [dim]({self.contact_ip})[/]"
            
        try:
            self.query_one(Label).update(self.display_label)
        except: pass

    def set_verified_identity(self, new_real_name):
        """Llamado cuando el handshake criptográfico confirma la identidad DNIe."""
        self.real_name = new_real_name
        self.verified = True
        self.update_label()

    def compose(self) -> ComposeResult:
        yield Label(self.display_label)

class ChatInput(TextArea):
    """Área de texto personalizada con manejo de Enter para enviar."""
    BINDINGS = [
        Binding("enter", "submit_message", "Enviar Mensaje", show=True, priority=True),
        Binding("ctrl+n", "insert_newline", "Salto de Línea (Ctrl+N)", show=True, priority=True),
    ]

    async def action_submit_message(self):
        await self.app.submit_message()

    def action_insert_newline(self):
        self.insert("\n")

# --- WIDGET DE MENSAJE MUTABLE ---

class MessageWidget(Static):
    """
    Burbuja de mensaje individual.
    Soporta copiar al portapapeles al hacer clic y cambios de estado (Entregado).
    """
    def __init__(self, text, title, is_me, timestamp, delivered=True, msg_id=None, **kwargs):
        css_id = f"msg-{msg_id}" if msg_id else None
        super().__init__(**kwargs, id=css_id)
        self.text_content = text
        self.title_text = title
        self.is_me = is_me
        self.timestamp = timestamp
        self.delivered = delivered
        self.msg_id = msg_id 

    def on_mount(self):
        self.update(self._create_panel())

    def on_click(self):
        """Copia el contenido del mensaje al portapapeles."""
        try:
            pyperclip.copy(self.text_content)
            self.app.add_log("📋 Mensaje copiado al portapapeles")
        except Exception as e:
            self.app.add_log(f"⚠️ No se pudo copiar: {e}")

    def set_delivered(self):
        """Cambia el color de la hora para indicar que llegó (ACK recibido)."""
        if not self.delivered:
            self.delivered = True
            self.update(self._create_panel())

    def _create_panel(self):
        color = "green" if self.is_me else "orange1"
        final_title = self.title_text
        
        if self.timestamp:
            ts_str = datetime.fromtimestamp(self.timestamp).strftime("%H:%M")
            if self.is_me:
                time_color = "green" if self.delivered else "grey37"
                final_title = f"{self.title_text} [{time_color}]\\[{ts_str}][/]"
            else:
                final_title = f"{self.title_text} [orange1]\\[{ts_str}][/]"
                
        return Align(
            Panel(
                Text(self.text_content), 
                title=final_title, 
                title_align="left", 
                border_style=color, 
                box=box.ROUNDED, 
                padding=(0, 1), 
                expand=False
            ), 
            align="left"
        )

class DateSeparator(Static):
    """Línea divisoria para separar mensajes de días diferentes."""
    def __init__(self, timestamp, **kwargs):
        super().__init__(**kwargs)
        self.timestamp = timestamp
    
    def on_mount(self):
        date_str = datetime.fromtimestamp(self.timestamp).strftime("%d / %m / %Y")
        self.update(Rule(title=f"📅 {date_str}", style="cyan"))

# --- APP PRINCIPAL DE CHAT ---

class MessengerTUI(App):
    """Aplicación principal de Terminal."""
    CSS = """
    Screen { layout: grid; grid-size: 2; grid-columns: 30% 70%; }
    .sidebar { background: $surface; border-right: solid $primary; }
    .chat-area { layout: vertical; }
    .logs { height: 20%; border-top: solid $secondary; background: $surface-darken-1; }
    
    #chat_header_container {
        height: 3;
        width: 100%;
        background: $surface;
        border-bottom: solid $primary;
    }
    
    #chat_header_label {
        width: 100%;
        text-align: left;
        text-style: bold;
        color: $text;
        padding-top: 1;
    }
    
    VerticalScroll.messages { height: 1fr; padding: 1; overflow-y: scroll; scrollbar-gutter: stable; }
    
    .input-container { dock: bottom; height: 6; layout: horizontal; padding: 0 1 1 1; }
    ChatInput { width: 1fr; height: 100%; border: solid $accent; } 
    #btn_send { height: 100%; width: 12; margin-left: 1; background: $primary; color: $text; }
    
    .load-more-btn {
        width: 100%;
        margin-bottom: 1;
        background: $surface-lighten-1;
        color: $text-muted;
    }
    .load-more-btn:hover {
        background: $primary-darken-2;
        color: $text;
    }
    
    MessageWidget:hover {
        opacity: 0.85;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "request_quit", "Salir"),
        Binding("l", "copy_logs", "Copiar Logs"),
    ]

    def __init__(self, udp_protocol, discovery, storage, user_id, bind_ip=None):
        super().__init__()
        self.proto = udp_protocol
        self.discovery = discovery
        self.storage = storage
        self.user_id = user_id 
        self.bind_ip = bind_ip 
        self.current_chat_addr = None 
        
        self.log_buffer = []
        self.known_names = {} 
        self.peer_last_seen = {}
        self.peer_known_pubkeys = {}  # user_id -> bytes de clave pública (para detectar reconexiones)
        self.recently_disconnected = {}
        self.pending_acks = {}
        self.peer_last_read = {}
        
        # Paginación
        self.current_chat_offset = 0
        self.current_chat_limit = 50

    def compose(self) -> ComposeResult:
        """Define la estructura visual inicial."""
        yield Header(show_clock=True)
        with Vertical(classes="sidebar"):
            yield Label("  📡 Contactos", id="lbl_peers")
            yield ListView(id="contact_list")
        with Vertical(classes="chat-area"):
            with Container(id="chat_header_container"):
                yield Label("Selecciona un contacto", id="chat_header_label")
            yield VerticalScroll(id="chat_box", classes="messages")
            yield RichLog(highlight=True, markup=True, id="log_box", classes="logs")
            with Horizontal(classes="input-container"):
                yield ChatInput(show_line_numbers=False, id="msg_input")
                yield Button("SEND", id="btn_send")
        yield Footer()

    async def on_mount(self):
        """Inicialización asíncrona tras montar la UI."""
        self.title = "DNIe Secure Messenger"
        
        await self.load_saved_contacts()
        
        # Conectar callbacks del protocolo a métodos de la UI
        self.proto.on_log = self.add_log
        self.proto.on_message = self.receive_message
        self.proto.on_handshake_success = self.on_new_peer_handshake
        self.proto.on_ack_received = self.on_ack_received
        
        self.proto.get_peer_addr_callback = self._get_peer_addr_from_list
        self.proto.get_user_id_callback = self._get_user_id_for_addr
        self.proto.is_peer_online_callback = self._is_peer_online
        
        self.discovery.on_found_callback = self.add_peer
        self.discovery.on_log = self.add_log 
        
        self.add_log(f"Sistema inicializando para {self.user_id}...")
        
        username = f"User-{self.user_id}"
        await self.discovery.start(username, bind_ip=self.bind_ip)
        
        # Timer para verificar desconexiones por timeout
        self.set_interval(5.0, self.check_peer_status)

    async def load_saved_contacts(self):
        """Carga contactos persistidos en DB al inicio."""
        contacts = await self.storage.get_all_contacts()
        lst = self.query_one("#contact_list", ListView)
        
        loaded_count = 0
        now = time.time()
        for c in contacts:
            uid = c.get('userID')
            name = c.get('real_name')
            ip = c.get('ip')
            port = c.get('port')
            
            if uid: 
                if name: self.known_names[uid] = name
                self.peer_last_read[uid] = now
                
                exists = False
                for child in lst.children:
                    if isinstance(child, ChatItem) and child.user_id == uid:
                        exists = True
                        break
                
                if not exists:
                    item = ChatItem(uid, name, ip, port, verified=False, online=False)
                    lst.append(item)
                    loaded_count += 1
        
        self.add_log(f"📚 {loaded_count} contactos cargados.")

    def check_peer_status(self):
        """Verifica si los peers siguen vivos (Heartbeat timeout 20s)."""
        now = time.time()
        lst = self.query_one("#contact_list", ListView)
        
        for child in lst.children:
            if isinstance(child, ChatItem):
                last_seen = self.peer_last_seen.get(child.user_id, 0)
                is_online = (now - last_seen) < 20.0
                child.set_online_status(is_online)

    def _invalidate_session_for_user(self, user_id: str, reason: str = "desconexión"):
        """Invalida la sesión criptográfica de un usuario para forzar un nuevo handshake."""
        session = self.proto.sessions.get_session(user_id)
        if session and session.encryptor:
            self.add_log(f"🔒 Sesión invalidada para {user_id} ({reason})")
            # Borrar de forma segura las claves de la sesión
            if hasattr(session, 'zeroize_session'):
                session.zeroize_session()
            else:
                # Fallback: solo invalidar los cifradores
                session.encryptor = None
                session.decryptor = None

    def _is_peer_online(self, user_id: str) -> bool:
        """Helper para el protocolo: ¿Debemos reintentar enviar?"""
        now = time.time()
        last_seen = self.peer_last_seen.get(user_id, 0)
        return (now - last_seen) < 20.0

    def _get_peer_addr_from_list(self, user_id):
        try:
            lst = self.query_one("#contact_list", ListView)
            for child in lst.children:
                if isinstance(child, ChatItem) and child.user_id == user_id:
                    if child.online:
                        return (child.contact_ip, child.contact_port)
                    else:
                        return None 
        except: pass
        return None

    def _get_user_id_for_addr(self, addr):
        try:
            lst = self.query_one("#contact_list", ListView)
            for child in lst.children:
                if isinstance(child, ChatItem):
                    if child.contact_ip == addr[0] and child.contact_port == addr[1]:
                        return child.user_id
        except: pass
        return None

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_send":
            await self.submit_message()
        elif event.button.id == "btn_load_older":
            await self.action_load_older_messages()

    def action_request_quit(self):
        self.push_screen(QuitScreen())

    def action_copy_logs(self):
        if self.log_buffer:
            try: pyperclip.copy("\n".join(self.log_buffer))
            except: pass

    # --- LÓGICA DE UI Y RED ---

    def add_log(self, text):
        self.log_buffer.append(text)
        if len(self.log_buffer) > 1000: self.log_buffer.pop(0)
        try: self.query_one("#log_box", RichLog).write(text)
        except: pass

    def add_peer(self, user_id, ip, port, props):
        """Callback cuando mDNS encuentra a alguien."""
        if ip == "127.0.0.1": return
        stable_id = user_id.strip()
        # Ignorar reconexiones muy rápidas tras una desconexión explícita
        if stable_id in self.recently_disconnected:
            if time.time() - self.recently_disconnected[stable_id] < 5.0: return
            else: del self.recently_disconnected[stable_id]
        self.peer_last_seen[stable_id] = time.time()
        self._add_peer_safe(stable_id, ip, port, props)

    def _add_peer_safe(self, user_id, ip, port, props):
        try:
            lst = self.query_one("#contact_list", ListView)
            if user_id not in self.peer_last_read:
                self.peer_last_read[user_id] = 0

            # Manejo de señal de salida 'stat=exit'
            if props.get('stat') == 'exit':
                self.add_log(f"💤 Salida detectada: {user_id}")
                target_child = None
                for child in lst.children:
                    if isinstance(child, ChatItem) and child.user_id == user_id:
                        target_child = child
                        break
                
                if target_child:
                    was_online = target_child.online
                    self.recently_disconnected[user_id] = time.time()
                    self.peer_last_seen[user_id] = 0 
                    target_child.set_online_status(False)
                    
                    # Invalidar la sesión criptográfica cuando se detecta desconexión explícita
                    self._invalidate_session_for_user(user_id, "desconexión explícita")
                    # Limpiar la clave pública conocida para que al reconectar se acepte la nueva
                    self.peer_known_pubkeys.pop(user_id, None)
                    
                    if was_online and self.current_chat_addr == (ip, port):
                        chat_box = self.query_one("#chat_box", VerticalScroll)
                        msg_widget = Static(Align(Panel(Text(f"{target_child.real_name or user_id} se ha desconectado."), style="dim white"), align="left"))
                        chat_box.mount(msg_widget)
                        chat_box.scroll_end(animate=True)
                return

            # Si trae clave pública en mDNS, registrarla y verificar si cambió
            pub_hex = props.get('pub', '')
            if pub_hex:
                try:
                    pub_bytes = bytes.fromhex(pub_hex)
                    pub_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                    
                    # Detectar cambio de clave pública (indica reconexión del peer)
                    old_pub_bytes = self.peer_known_pubkeys.get(user_id)
                    if old_pub_bytes is not None and old_pub_bytes != pub_bytes:
                        # El peer se reconectó con una nueva clave, invalidar sesión antigua
                        self._invalidate_session_for_user(user_id, "cambio de clave pública - reconexión detectada")
                    
                    # Actualizar la clave conocida
                    self.peer_known_pubkeys[user_id] = pub_bytes
                    
                    asyncio.create_task(self.storage.register_contact(ip, port, pub_key, user_id=user_id, real_name=None))
                except Exception: pass

            found_item = None
            for child in lst.children:
                if isinstance(child, ChatItem) and child.user_id == user_id:
                    found_item = child
                    break
            
            if found_item:
                was_offline = not found_item.online
                # Actualizar si cambió de IP (Roaming)
                if found_item.contact_ip != ip or found_item.contact_port != port:
                    old_addr = f"{found_item.contact_ip}:{found_item.contact_port}"
                    found_item.update_address(ip, port)
                    self.add_log(f"📍 Peer {user_id} cambió de {old_addr} a {ip}:{port}")
                    if self.current_chat_addr and (self.current_chat_addr[0] == old_addr.split(':')[0]):
                        self.current_chat_addr = (ip, port)
                        self.add_log("⚡ Sesión de chat redirigida a nueva IP.")
                    was_offline = True
                found_item.set_online_status(True)
                if not found_item.real_name:
                     display_name = self.known_names.get(user_id)
                     if display_name:
                         found_item.real_name = display_name
                         found_item.update_label()
            else:
                display_name = self.known_names.get(user_id)
                item = ChatItem(user_id, display_name, ip, port, verified=False, online=True)
                lst.append(item)
                log_msg = f"🔎 Peer encontrado: {user_id}"
                self.add_log(log_msg)
        except Exception as e: 
            self.add_log(f"Error actualizando peer en UI: {e}")

    def on_new_peer_handshake(self, addr, pub_key, real_name=None):
        self._update_peer_identity_safe(addr, real_name)

    def _update_peer_identity_safe(self, addr, real_name):
        if not real_name: return
        lst = self.query_one("#contact_list", ListView)
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == addr[0] and child.contact_port == addr[1]:
                child.set_verified_identity(real_name)
                self.known_names[child.user_id] = real_name
                
                if self.current_chat_addr == (child.contact_ip, child.contact_port):
                    target_name = child.real_name
                    status = "(Verificado)" if child.verified else "(No verificado)"
                    conn_status = "[green]EN LÍNEA[/]" if child.online else "[grey]DESCONECTADO[/]"
                    header_text = f"Chateando con {target_name} {status} - {conn_status}"
                    self.query_one("#chat_header_label", Label).update(header_text)
                break

    async def on_list_view_selected(self, event: ListView.Selected):
        item = event.item
        if not isinstance(item, ChatItem): return
        self.current_chat_addr = (item.contact_ip, item.contact_port)
        await self._load_and_refresh_chat_history(item)

    async def _load_and_refresh_chat_history(self, item: ChatItem):
        """Carga la vista inicial del chat (los 50 más recientes)."""
        chat_box = self.query_one("#chat_box", VerticalScroll)
        await chat_box.remove_children()
        
        self.current_chat_offset = 0
        
        target_name = item.real_name if item.real_name else item.user_id
        status = "(Verificado)" if item.verified else "(No verificado)"
        conn_status = "[green]EN LÍNEA[/]" if item.online else "[grey]DESCONECTADO[/]"
        
        header_text = f"Chateando con {target_name} {status} - {conn_status}"
        self.query_one("#chat_header_label", Label).update(header_text)
        
        history = await self.storage.get_chat_history(item.user_id, limit=self.current_chat_limit, offset=0)
        
        widgets_to_mount = []
        
        if len(history) == self.current_chat_limit:
            widgets_to_mount.append(Button("⬆ Cargar mensajes anteriores", id="btn_load_older", classes="load-more-btn"))

        last_read_ts = self.peer_last_read.get(item.user_id, 0)
        rule_drawn = False
        current_day = None 

        for msg in history:
            ts = msg.get('timestamp', 0)
            msg_date = datetime.fromtimestamp(ts).date() if ts else None
            if msg_date and msg_date != current_day:
                current_day = msg_date
                widgets_to_mount.append(DateSeparator(ts))
            
            direction = msg.get('direction')
            if not rule_drawn and ts > last_read_ts and direction == "in":
                widgets_to_mount.append(Static(Rule(style="red", title="Nuevos Mensajes")))
                rule_drawn = True

            text = msg.get('content')
            is_me = (direction == "out")
            sender_name = "Tú" if is_me else target_name
            
            widgets_to_mount.append(MessageWidget(text, sender_name, is_me, ts, delivered=True))
            
        # Añadir mensajes pendientes de envío
        pending_list = [v for k, v in self.pending_acks.items() if v['user_id'] == item.user_id]
        pending_list.sort(key=lambda x: x['timestamp'])

        for p_data in pending_list:
            original_msg_id = None
            for mid, mdata in self.pending_acks.items():
                if mdata == p_data:
                    original_msg_id = mid
                    break
            
            widgets_to_mount.append(MessageWidget(
                p_data['text'], "Tú", is_me=True, timestamp=p_data['timestamp'], 
                delivered=False, msg_id=original_msg_id 
            ))
        
        if widgets_to_mount:
            chat_box.mount(*widgets_to_mount)
        
        self.peer_last_read[item.user_id] = time.time()
        self.call_later(chat_box.scroll_end, animate=False)

    async def action_load_older_messages(self):
        """Paginación: Carga mensajes históricos más antiguos."""
        if not self.current_chat_addr: return
        
        current_uid = None
        lst = self.query_one("#contact_list", ListView)
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == self.current_chat_addr[0] and child.contact_port == self.current_chat_addr[1]:
                current_uid = child.user_id
                break
        
        if not current_uid: return

        self.current_chat_offset += self.current_chat_limit
        
        older_history = await self.storage.get_chat_history(
            current_uid, 
            limit=self.current_chat_limit, 
            offset=self.current_chat_offset
        )
        
        chat_box = self.query_one("#chat_box", VerticalScroll)
        try:
            btn = self.query_one("#btn_load_older", Button)
        except: return 
        
        if not older_history:
            btn.remove()
            self.add_log("No hay mensajes más antiguos.")
            return

        new_widgets = []
        current_day = None 
        target_name = self.known_names.get(current_uid, current_uid)

        for msg in older_history:
            ts = msg.get('timestamp', 0)
            msg_date = datetime.fromtimestamp(ts).date() if ts else None
            if msg_date and msg_date != current_day:
                current_day = msg_date
                new_widgets.append(DateSeparator(ts))

            text = msg.get('content')
            direction = msg.get('direction')
            is_me = (direction == "out")
            sender_name = "Tú" if is_me else target_name
            
            new_widgets.append(MessageWidget(text, sender_name, is_me, ts, delivered=True))
            
        chat_box.mount(*new_widgets, after=btn)
        
        if len(older_history) < self.current_chat_limit:
            btn.remove()
            chat_box.mount(Label("[dim]--- Fin del historial ---[/dim]"), after=new_widgets[-1] if new_widgets else None)

    async def submit_message(self):
        """Envía el mensaje escrito en el input."""
        ta = self.query_one("#msg_input", ChatInput)
        text = ta.text.strip()
        if not text: return
        if not self.current_chat_addr:
            self.add_log("⚠️ ¡Selecciona un contacto primero!")
            return
            
        target_item = None
        lst = self.query_one("#contact_list", ListView)
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == self.current_chat_addr[0] and child.contact_port == self.current_chat_addr[1]:
                target_item = child
                break
        
        if target_item:
            if not target_item.online:
                self.add_log(f"⛔ No se puede enviar: {target_item.real_name or target_item.user_id} está DESCONECTADO.")
                return
            self.peer_last_read[target_item.user_id] = time.time()
        else:
             self.add_log("❌ Error: Contacto no encontrado.")
             return

        ta.text = "" 
        now_ts = time.time()
        
        # Enviar mensaje usando el protocolo UDP
        msg_id = await self.proto.send_message(target_item.user_id, text)
        
        if msg_id:
            # Añadir a lista de espera de ACK
            self.pending_acks[msg_id] = {
                'text': text,
                'timestamp': now_ts,
                'user_id': target_item.user_id
            }
            chat_box = self.query_one("#chat_box", VerticalScroll)
            new_widget = MessageWidget(text, "Tú", is_me=True, timestamp=now_ts, delivered=False, msg_id=msg_id)
            chat_box.mount(new_widget)
            chat_box.scroll_end(animate=True)

    def on_ack_received(self, addr, ack_id):
        self._handle_ack_safe(addr, ack_id)

    def _handle_ack_safe(self, addr, ack_id):
        """Maneja la confirmación de recepción."""
        if ack_id in self.pending_acks:
            data = self.pending_acks.pop(ack_id)
            # Persistir mensaje solo cuando sabemos que llegó
            asyncio.create_task(
                self.storage.save_chat_message(
                    user_id=data['user_id'],
                    direction="out",
                    text=data['text'],
                    timestamp=data['timestamp']
                )
            )
            
            if self.current_chat_addr == addr:
                try:
                    css_id = f"#msg-{ack_id}"
                    widget = self.query_one(css_id, MessageWidget)
                    widget.set_delivered()
                except: pass

    def receive_message(self, addr, msg):
        self._receive_message_safe(addr, msg)

    def _receive_message_safe(self, addr, msg):
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
        
        if not known and msg.get('disconnect'): return
        if not known: 
            self._add_peer_safe(f"Peer_{ip}", ip, port, {})
            if lst.children: target_child = lst.children[-1]

        # Manejo de desconexión UDP
        if msg.get('disconnect') is True:
            if target_child:
                was_online = target_child.online
                self.peer_last_seen[target_child.user_id] = 0
                target_child.set_online_status(False)
                
                if was_online and self.current_chat_addr == (ip, port):
                    chat_box = self.query_one("#chat_box", VerticalScroll)
                    msg_widget = Static(Align(Panel(Text(f"{peer_name} se ha desconectado."), style="dim white"), align="left"))
                    chat_box.mount(msg_widget)
            return
        
        if target_child:
            self.peer_last_seen[target_child.user_id] = time.time()
            target_child.set_online_status(True)
            if self.current_chat_addr == (ip, port):
                self.peer_last_read[target_child.user_id] = time.time()
        
        text = msg.get('text', '')
        if not text: return 

        integrity = msg.get('integrity', None)
        if integrity is False:
             text = f"[bold red blink]⚠️ MENSAJE CORRUPTO (HASH MISMATCH):[/]\n{text}"

        ts = msg.get('timestamp')
        
        if target_child:
            asyncio.create_task(
                self.storage.save_chat_message(
                    user_id=target_child.user_id,
                    direction="in",
                    text=text,
                    timestamp=ts
                )
            )

        # Si el chat está abierto, mostrar mensaje, si no, notificar log
        curr_ip = self.current_chat_addr[0] if self.current_chat_addr else None
        
        if curr_ip == ip: 
            chat_box = self.query_one("#chat_box", VerticalScroll)
            is_at_bottom = chat_box.scroll_y >= (chat_box.max_scroll_y - 2)
            
            new_widget = MessageWidget(text, peer_name, is_me=False, timestamp=ts, delivered=True)
            chat_box.mount(new_widget)
            
            if is_at_bottom:
                chat_box.scroll_end(animate=True)
            else:
                self.add_log(f"⬇️ Nuevo mensaje de {peer_name} (Recibido abajo)")
        else: 
            self.add_log(f"📨 Nuevo mensaje de {peer_name}")

class DNIeLoginApp(App):
    """
    Aplicación independiente para el Login.
    Se ejecuta ANTES de MessengerTUI.
    Maneja la lectura del DNIe, PIN y firmas iniciales.
    """
    CSS = """
    Screen { align: center middle; background: $surface; }
    .login-box { 
        width: 60; 
        height: auto; 
        border: thick $primary; 
        background: $surface-lighten-1;
        padding: 2;
    }
    #title { text-align: center; color: $accent; text-style: bold; margin-bottom: 2; }
    #status { text-align: center; color: $text-muted; margin-bottom: 1; }
    #card-status { text-align: center; margin-bottom: 2; text-style: bold; }
    .card-missing { color: $error; }
    .card-present { color: $success; }
    #error-msg { text-align: center; color: $error; margin-top: 1; text-style: bold; display: none; }
    Input { margin-bottom: 2; }
    Button { width: 100%; }
    LoadingIndicator { height: 1; margin: 1 0; display: none; }
    """

    DOMAIN_SEPARATOR = "DNIe-Secure-Storage-Domain-Separator-v1"

    def __init__(self, key_to_sign_bytes):
        super().__init__()
        self.key_to_sign_bytes = key_to_sign_bytes
        self.return_data = None 
        self.is_logging_in = False 

    def compose(self) -> ComposeResult:
        with Container(classes="login-box"):
            yield Label("🔐 INICIO DE SESIÓN CON DNIe", id="title")
            yield Label("Buscando lector...", id="card-status", classes="card-missing")
            yield Label("Introduzca su PIN:", id="status")
            yield LoadingIndicator(id="loading")
            yield Input(placeholder="PIN del DNIe", password=True, id="pin", disabled=True)
            yield Button("Acceder", variant="primary", id="btn_login", disabled=True)
            yield Label("", id="error-msg")

    def on_mount(self):
        # Polling para detectar inserción de tarjeta
        self.set_interval(1.5, self.check_card_presence)
        self.check_card_presence()

    @work(thread=True)
    def check_card_presence(self):
        """Verifica en hilo secundario si hay tarjeta en el lector."""
        if self.is_logging_in: return
        is_present = False
        try:
            card = DNIeCard()
            if card.connect():
                is_present = True
                card.disconnect()
        except:
            is_present = False
        self.call_from_thread(self.update_card_ui, is_present)

    def update_card_ui(self, is_present: bool):
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
                if inp.value == "": inp.focus() 
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
        """Inicia el proceso de autenticación."""
        pin = self.query_one("#pin", Input).value
        if not pin:
            self.show_error("⚠️ El PIN no puede estar vacío.")
            return
        
        self.is_logging_in = True 
        self.query_one("#btn_login", Button).disabled = True
        self.query_one("#pin", Input).disabled = True
        self.query_one("#loading", LoadingIndicator).display = True
        self.query_one("#status", Label).update("Conectando con tarjeta inteligente...")
        self.query_one("#error-msg").display = False
        
        self.run_dnie_operation(pin)

    @work(exclusive=True, thread=True)
    def run_dnie_operation(self, pin):
        """
        Operación bloqueante con el hardware del DNIe.
        Se ejecuta en un Worker Thread para no congelar la UI.
        
        Pasos:
        1. Conectar y autenticar PIN.
        2. Obtener certificado y firmar la clave de red efímera.
        3. Obtener número de serie, hashearlo y firmarlo para la clave de storage.
        """
        try:
            card = DNIeCard()
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Autenticando PIN..."))
            card.connect()
            card.authenticate(pin)
            
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Firmando identidad de red..."))
            cert_der = card.get_certificate()
            # Firma A: Autoriza a esta clave efímera a actuar en nombre del DNIe en la red
            network_signature = card.sign_data(self.key_to_sign_bytes)
            user_id = card.get_serial_hash()[:8]
            proofs = {'cert': cert_der.hex(), 'sig': network_signature.hex()}

            self.call_from_thread(lambda: self.query_one("#status", Label).update("Generando clave de cifrado..."))
            
            # Firma B: Genera la clave de cifrado para la base de datos local
            serial_raw = card.get_serial()
            serial_bytes = serial_raw.encode('utf-8') if isinstance(serial_raw, str) else serial_raw
            separator_bytes = self.DOMAIN_SEPARATOR.encode('utf-8')
            
            data_to_hash_for_key = serial_bytes + separator_bytes
            digest = hashlib.sha256(data_to_hash_for_key).digest()
            
            storage_signature = card.sign_data(digest)

            self.return_data = (user_id, proofs, storage_signature)
            self.call_from_thread(self.exit_success)
            
        except Exception as e:
            self.call_from_thread(lambda: self.show_error(f"❌ Error: {str(e)}"))
        finally:
            try: card.disconnect()
            except: pass

    def exit_success(self):
        self.exit(result=self.return_data)

    def show_error(self, msg):
        """Resetea la UI en caso de error para permitir reintento."""
        self.is_logging_in = False
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