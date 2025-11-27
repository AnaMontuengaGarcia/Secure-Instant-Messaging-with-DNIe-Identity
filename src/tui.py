from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center, Middle
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
    """
    Pantalla modal de confirmación para salir de la aplicación.
    """
    CSS = """
    QuitScreen { align: center middle; }
    #dialog { grid-size: 2; grid-gutter: 1 2; grid-rows: 1fr 3; padding: 0 1; width: 60; height: 11; border: thick $background 80%; background: $surface; }
    #question { column-span: 2; height: 1fr; width: 1fr; content-align: center middle; }
    Button { width: 100%; }
    """
    
    def compose(self) -> ComposeResult:
        """
        Construye la interfaz de usuario de la pantalla de salida.
        
        Cómo lo hace:
        Crea un contenedor con una etiqueta de pregunta y dos botones ('Salir' y 'Cancelar').
        """
        yield Container(
            Label("Are you sure you want to quit?", id="question"),
            Button("Quit", variant="error", id="quit"),
            Button("Cancel", variant="primary", id="cancel"),
            id="dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Maneja los eventos de pulsación de botones en el diálogo.
        
        Cómo lo hace:
        Verifica el ID del botón presionado. Si es 'quit', cierra la aplicación completamente.
        Si es 'cancel', cierra solo esta pantalla modal volviendo al chat.
        """
        if event.button.id == "quit": self.app.exit()
        else: self.app.pop_screen()

# --- WIDGETS CHAT ---

class ChatItem(ListItem):
    """
    Elemento de lista personalizado que representa a un contacto en la barra lateral.
    """
    def __init__(self, user_id, real_name, ip, port, verified=False, online=False):
        """
        Inicializa un nuevo ítem de contacto.
        
        Cómo lo hace:
        Almacena los datos de identidad (ID, nombre real), conexión (IP, puerto) y estado (verificado, online).
        Llama inmediatamente a update_label() para renderizar el texto inicial.
        """
        super().__init__()
        self.user_id = user_id
        self.real_name = real_name
        self.contact_ip = ip
        self.contact_port = port
        self.verified = verified
        self.online = online  
        self.update_label()

    def set_online_status(self, is_online):
        """
        Actualiza el estado de conexión del contacto.
        
        Cómo lo hace:
        Cambia el flag interno 'online' y fuerza una actualización visual de la etiqueta
        solo si el estado ha cambiado para evitar repintados innecesarios.
        """
        if self.online != is_online:
            self.online = is_online
            self.update_label()

    def update_address(self, new_ip, new_port):
        """
        Actualiza la dirección de red del contacto (Roaming).
        
        Cómo lo hace:
        Sobrescribe la IP y puerto almacenados y refresca la etiqueta visual para reflejar
        la nueva ubicación del par.
        """
        self.contact_ip = new_ip
        self.contact_port = new_port
        self.update_label()

    def update_label(self):
        """
        Regenera el texto y estilo visual del contacto en la lista.
        
        Cómo lo hace:
        1. Determina el icono de estado (punto verde para online, gris para offline).
        2. Formatea el nombre a mostrar: usa el nombre real si está verificado, o el ID si no.
        3. Construye una cadena con formato Rich (colores y estilos) incluyendo la IP.
        4. Actualiza el widget Label interno.
        """
        if self.online:
            status_icon = "[green]●[/]" 
            status_text = "Online"
        else:
            status_icon = "[grey50]●[/]" 
            status_text = "Offline"

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
        """
        Marca al contacto como verificado tras comprobar su firma digital.
        
        Cómo lo hace:
        Asigna el nombre real extraído del certificado DNIe, establece el flag 'verified' a True
        y actualiza la visualización.
        """
        self.real_name = new_real_name
        self.verified = True
        self.update_label()

    def compose(self) -> ComposeResult:
        """
        Renderiza la estructura interna del ítem de la lista.
        
        Cómo lo hace:
        Devuelve un único widget Label que contendrá el texto formateado.
        """
        yield Label(self.display_label)

class ChatInput(TextArea):
    """
    Widget de entrada de texto para redactar mensajes.
    Soporta atajos de teclado para enviar y saltos de línea.
    """
    BINDINGS = [
        Binding("enter", "submit_message", "Send Message", show=True, priority=True),
        Binding("ctrl+n", "insert_newline", "Line Break (Ctrl+N)", show=True, priority=True),
        Binding("alt+enter", "insert_newline", "Line Break", show=False, priority=True),
        Binding("ctrl+enter", "insert_newline", "Line Break", show=False, priority=True),
    ]

    async def action_submit_message(self):
        """
        Acción disparada al presionar Enter.
        
        Cómo lo hace:
        Delega la acción al método 'submit_message' de la aplicación principal (MessengerTUI).
        """
        await self.app.submit_message()

    def action_insert_newline(self):
        """
        Inserta un salto de línea manual en el editor.
        
        Cómo lo hace:
        Utiliza el método insert del widget padre para añadir un caracter '\n'.
        """
        self.insert("\n")

# --- APP PRINCIPAL DE CHAT ---

class MessengerTUI(App):
    """
    Clase principal de la interfaz de usuario basada en Textual.
    Coordina la lógica de red, almacenamiento y presentación.
    """
    CSS = """
    Screen { layout: grid; grid-size: 2; grid-columns: 30% 70%; }
    .sidebar { background: $surface; border-right: solid $primary; }
    .chat-area { layout: vertical; }
    /* MODIFICADO: Aumentado height de .logs al 20% */
    .logs { height: 20%; border-top: solid $secondary; background: $surface-darken-1; }
    .messages { height: 1fr; padding: 1; }
    .input-container { dock: bottom; height: 6; layout: horizontal; padding: 0 1 1 1; }
    ChatInput { width: 1fr; height: 100%; border: solid $accent; } 
    #btn_send { height: 100%; width: 12; margin-left: 1; background: $primary; color: $text; }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "request_quit", "Quit"),
        Binding("l", "copy_logs", "Copy Logs"),
        Binding("r", "refresh_peers", "Refresh Network"),
    ]

    def __init__(self, udp_protocol, discovery, storage, user_id, bind_ip=None):
        """
        Constructor de la aplicación TUI.
        
        Cómo lo hace:
        Inicializa las referencias a los subsistemas (red, descubrimiento, almacenamiento).
        Prepara las estructuras de datos en memoria para logs, nombres conocidos, estado de peers,
        ACKS pendientes y control de lectura de mensajes.
        """
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
        self.recently_disconnected = {}
        
        self.pending_acks = {}
        # Diccionario para controlar la última vez que leímos el chat de un usuario
        # Clave: user_id, Valor: timestamp
        self.peer_last_read = {}

    def compose(self) -> ComposeResult:
        """
        Define la estructura visual principal de la aplicación.
        
        Cómo lo hace:
        Crea un layout de rejilla con:
        1. Cabecera.
        2. Barra lateral izquierda para la lista de contactos.
        3. Área principal derecha dividida en historial de chat, logs del sistema y área de entrada.
        4. Pie de página.
        """
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
        """
        Evento ejecutado cuando la aplicación se ha montado y está lista.
        
        Cómo lo hace:
        1. Carga contactos guardados desde el almacenamiento cifrado.
        2. Configura los callbacks (hooks) del protocolo UDP para conectar eventos de red con la UI.
        3. Configura los callbacks del servicio de descubrimiento mDNS.
        4. Inicia el servicio de descubrimiento de red.
        5. Establece un intervalo periódico para verificar el estado de los peers.
        """
        self.title = "DNIe Secure Messenger"
        
        # Carga inicial desde memoria (que ya fue descifrada en storage.init())
        await self.load_saved_contacts()
        
        self.proto.on_log = self.add_log
        self.proto.on_message = self.receive_message
        self.proto.on_handshake_success = self.on_new_peer_handshake
        self.proto.on_ack_received = self.on_ack_received
        
        # Callbacks para resolver IP y user_id desde la lista de contactos (Integración Network <-> UI)
        self.proto.get_peer_addr_callback = self._get_peer_addr_from_list
        self.proto.get_user_id_callback = self._get_user_id_for_addr
        
        self.discovery.on_found = self.add_peer
        self.discovery.on_log = self.add_log 
        
        self.query_one("#chat_box", RichLog).write("Selecciona un contacto para chatear.")
        self.add_log(f"System initializing for {self.user_id}...")
        
        username = f"User-{self.user_id}"
        await self.discovery.start(username, bind_ip=self.bind_ip)
        
        self.set_interval(5.0, self.check_peer_status)

    async def load_saved_contacts(self):
        """
        Carga los contactos persistentes en la lista visual al inicio.
        
        Cómo lo hace:
        Recupera la lista desde 'storage', itera sobre ellos y crea widgets ChatItem si no existen ya.
        Inicializa el estado de lectura (last_read) para gestionar notificaciones de no leídos.
        """
        contacts = await self.storage.get_all_contacts()
        lst = self.query_one("#contact_list", ListView)
        
        loaded_count = 0
        now = time.time()
        for c in contacts:
            uid = c.get('userID')
            name = c.get('real_name')
            ip = c.get('ip')
            port = c.get('port')
            
            if uid and name:
                self.known_names[uid] = name
                # Asumimos que el historial antiguo ya está leído al iniciar la app
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
        
        self.add_log(f"📚 {loaded_count} Contactos cargados (Base de Datos Cifrada).")

    def check_peer_status(self):
        """
        Tarea periódica para verificar si los contactos siguen online.
        
        Cómo lo hace:
        Compara la última vez que se vio un peer (peer_last_seen) con el tiempo actual.
        Si la diferencia supera 20 segundos, marca al contacto como offline visualmente.
        """
        now = time.time()
        lst = self.query_one("#contact_list", ListView)
        
        for child in lst.children:
            if isinstance(child, ChatItem):
                last_seen = self.peer_last_seen.get(child.user_id, 0)
                is_online = (now - last_seen) < 20.0
                child.set_online_status(is_online)

    def _get_peer_addr_from_list(self, user_id):
        """
        Callback auxiliar para el protocolo de red.
        Busca la dirección IP actual de un usuario dado su ID.
        
        Cómo lo hace:
        Recorre la lista visual de contactos (que actúa como fuente de verdad del estado actual)
        y devuelve la tupla (ip, puerto) si el usuario existe y está online.
        """
        try:
            lst = self.query_one("#contact_list", ListView)
            for child in lst.children:
                if isinstance(child, ChatItem) and child.user_id == user_id:
                    if child.online:
                        return (child.contact_ip, child.contact_port)
                    else:
                        return None  # Peer existe pero está offline
        except:
            pass
        return None

    def _get_user_id_for_addr(self, addr):
        """
        Callback auxiliar para el protocolo de red.
        Busca el ID de usuario correspondiente a una dirección IP.
        
        Cómo lo hace:
        Recorre la lista visual buscando una coincidencia de IP y Puerto, devolviendo el ID asociado.
        """
        try:
            lst = self.query_one("#contact_list", ListView)
            for child in lst.children:
                if isinstance(child, ChatItem):
                    if child.contact_ip == addr[0] and child.contact_port == addr[1]:
                        return child.user_id
        except:
            pass
        return None

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Maneja pulsaciones de botones generales en la App.
        
        Cómo lo hace:
        Si el botón es 'btn_send', invoca la lógica de envío de mensajes.
        """
        if event.button.id == "btn_send":
            await self.submit_message()

    def action_request_quit(self):
        """
        Acción para solicitar salir de la aplicación.
        
        Cómo lo hace:
        Muestra la pantalla modal 'QuitScreen'.
        """
        self.push_screen(QuitScreen())

    def action_refresh_peers(self):
        """
        Acción manual para refrescar el descubrimiento de red.
        
        Cómo lo hace:
        Fuerza al servicio de descubrimiento a enviar queries mDNS.
        """
        self.add_log("🔄 Manual refresh...")
        self.discovery.refresh()

    def action_copy_logs(self):
        """
        Copia el contenido de los logs al portapapeles del sistema.
        
        Cómo lo hace:
        Une el buffer de logs en una sola cadena y usa pyperclip para copiarlo.
        """
        if self.log_buffer:
            try: pyperclip.copy("\n".join(self.log_buffer))
            except: pass

    # --- MÉTODOS DE LÓGICA DE UI Y RED ---

    def add_log(self, text):
        """
        Añade un mensaje al panel de logs del sistema.
        
        Cómo lo hace:
        Añade el texto al buffer circular (máx 1000 líneas) y escribe en el widget RichLog.
        """
        self.log_buffer.append(text)
        if len(self.log_buffer) > 1000: self.log_buffer.pop(0)
        try: self.query_one("#log_box", RichLog).write(text)
        except: pass

    def add_peer(self, user_id, ip, port, props):
        """
        Callback principal del descubrimiento mDNS. Gestiona la detección de pares.
        
        Cómo lo hace:
        1. Ignora la propia IP local.
        2. Filtra detecciones duplicadas muy recientes (debounce).
        3. Actualiza el timestamp de 'última vez visto'.
        4. Delega la lógica de actualización visual a '_add_peer_safe'.
        """
        if ip == "127.0.0.1": return
        stable_id = user_id.strip()
        if stable_id in self.recently_disconnected:
            if time.time() - self.recently_disconnected[stable_id] < 5.0: return
            else: del self.recently_disconnected[stable_id]
        self.peer_last_seen[stable_id] = time.time()
        self._add_peer_safe(stable_id, ip, port, props)

    def _add_peer_safe(self, user_id, ip, port, props):
        """
        Lógica detallada para añadir o actualizar un peer en la lista visual.
        
        Cómo lo hace:
        1. Maneja la señal 'stat=exit' para marcar desconexiones voluntarias.
        2. Si hay clave pública en 'props', registra el contacto en almacenamiento.
        3. Busca si el contacto ya existe en la lista:
           - Si existe: Actualiza su IP/Puerto (Roaming) y lo marca online.
           - Si no existe: Crea un nuevo ChatItem y lo añade a la lista.
        4. Muestra logs de los eventos relevantes (descubrimiento, roaming, desconexión).
        """
        try:
            lst = self.query_one("#contact_list", ListView)
            
            # Nuevos pares descubiertos en caliente (no en DB): Marcamos last_read en 0
            # para que cualquier mensaje entrante se marque como Nuevo
            if user_id not in self.peer_last_read:
                self.peer_last_read[user_id] = 0

            if props.get('stat') == 'exit':
                self.add_log(f"💤 Recibida señal de salida de {user_id} (Multicast)")
                target_child = None
                for child in lst.children:
                    if isinstance(child, ChatItem) and child.user_id == user_id:
                        target_child = child
                        break
                
                if target_child:
                    self.recently_disconnected[user_id] = time.time()
                    self.peer_last_seen[user_id] = 0 
                    target_child.set_online_status(False)
                    disconnect_panel = Align(Panel(Text(f"{target_child.real_name or user_id} se ha desconectado (Global)."), style="dim white"), align="left")
                    if self.current_chat_addr == (ip, port):
                        self.query_one("#chat_box", RichLog).write(disconnect_panel)
                return

            pub_hex = props.get('pub', '')
            if pub_hex:
                try:
                    pub_bytes = bytes.fromhex(pub_hex)
                    pub_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
                    asyncio.create_task(self.storage.register_contact(ip, port, pub_key, user_id=user_id, real_name=None))
                except Exception: pass

            found_item = None
            for child in lst.children:
                if isinstance(child, ChatItem) and child.user_id == user_id:
                    found_item = child
                    break
            
            if found_item:
                was_offline = not found_item.online
                if found_item.contact_ip != ip or found_item.contact_port != port:
                    old_addr = f"{found_item.contact_ip}:{found_item.contact_port}"
                    found_item.update_address(ip, port)
                    if self.current_chat_addr and (self.current_chat_addr[0] == old_addr.split(':')[0]):
                        self.current_chat_addr = (ip, port)
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
                if display_name: log_msg += f" (Known as: {display_name})"
                log_msg += f" @ {ip}"
                self.add_log(log_msg)
        except Exception as e: 
            self.add_log(f"Error updating UI peer: {e}")

    def on_new_peer_handshake(self, addr, pub_key, real_name=None):
        """
        Callback ejecutado cuando se completa un handshake criptográfico exitoso.
        
        Cómo lo hace:
        Delega a '_update_peer_identity_safe' para actualizar la UI con la identidad verificada.
        """
        self._update_peer_identity_safe(addr, real_name)

    def _update_peer_identity_safe(self, addr, real_name):
        """
        Actualiza la identidad visual de un par tras verificar su certificado DNIe.
        
        Cómo lo hace:
        Busca el ítem de la lista por dirección IP/Puerto.
        Si lo encuentra, llama a 'set_verified_identity' para mostrar el nombre real y el check de verificado.
        Si es el chat actual, recarga el historial para refrescar el nombre en la cabecera.
        """
        if not real_name: return
        lst = self.query_one("#contact_list", ListView)
        found = False
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == addr[0] and child.contact_port == addr[1]:
                child.set_verified_identity(real_name)
                self.known_names[child.user_id] = real_name
                found = True
                if self.current_chat_addr == (child.contact_ip, child.contact_port):
                    self.call_later(self._load_and_refresh_chat_history, child)
                break
        if not found:
            self._add_peer_safe(f"Unknown_{addr[0]}", addr[0], addr[1], {})
            self._update_peer_identity_safe(addr, real_name)

    async def on_list_view_selected(self, event: ListView.Selected):
        """
        Maneja la selección de un contacto en la lista lateral.
        
        Cómo lo hace:
        Actualiza la dirección del chat activo y carga el historial de mensajes correspondiente.
        """
        item = event.item
        if not isinstance(item, ChatItem): return
        self.current_chat_addr = (item.contact_ip, item.contact_port)
        await self._load_and_refresh_chat_history(item)

    async def _load_and_refresh_chat_history(self, item: ChatItem):
        """
        Carga, formatea y muestra el historial de chat en el panel central.
        
        Cómo lo hace:
        1. Limpia el panel de chat.
        2. Muestra cabecera con estado e identidad del contacto.
        3. Recupera historial persistente (mensajes confirmados) desde 'storage'.
        4. Itera mensajes:
           - Dibuja separadores de fecha cuando cambia el día.
           - Dibuja línea roja de "Nuevos Mensajes" basada en 'peer_last_read'.
           - Crea burbujas de mensaje (verdes/naranjas).
        5. Añade mensajes pendientes de envío (memoria, color gris) al final.
        6. Actualiza el timestamp de última lectura.
        """
        chat_box = self.query_one("#chat_box", RichLog)
        chat_box.clear()
        target_name = item.real_name if item.real_name else item.user_id
        status = "(Verified)" if item.verified else "(Unverified)"
        conn_status = "[green]ONLINE[/]" if item.online else "[grey]OFFLINE[/]"
        chat_box.write(f"Chatting with {target_name} {status} - {conn_status}\n")
        chat_box.write(f"[dim]History from {item.user_id}[/]\n")
        
        # 1. Recuperamos umbral de lectura
        last_read_ts = self.peer_last_read.get(item.user_id, 0)
        rule_drawn = False
        current_day = None  # Para trackear el día actual y mostrar separadores

        # 2. Cargar e imprimir Historial (desde memoria descifrada)
        # NOTA: Los mensajes guardados en storage ya están confirmados (ACK recibido)
        history = await self.storage.get_chat_history(item.user_id)
        
        for msg in history:
            ts = msg.get('timestamp', 0)
            
            # Verificar si cambió el día para mostrar separador
            msg_date = datetime.fromtimestamp(ts).date() if ts else None
            if msg_date and msg_date != current_day:
                current_day = msg_date
                chat_box.write(self._create_date_separator(ts))
            
            # Si el mensaje es más nuevo que lo último que leímos, pintamos la raya
            # y solo una vez.
            if not rule_drawn and ts > last_read_ts:
                chat_box.write(Rule(style="red", title="Nuevos Mensajes"))
                rule_drawn = True

            text = msg.get('content')
            direction = msg.get('direction')
            is_me = (direction == "out")
            sender_name = "You" if is_me else target_name
            # Si está en el historial guardado, asumimos que está entregado (delivered=True)
            panel = self._create_message_panel(text, sender_name, is_me, timestamp=ts, delivered=True)
            chat_box.write(panel)

        # Si no se pintó raya de nuevos (todos leídos), pintamos raya final gris
        if not rule_drawn:
            chat_box.write(Rule(style="dim"))
            
        # 3. Imprimir Mensajes Pendientes (Memoria temporal, no confirmados)
        pending_list = [v for k, v in self.pending_acks.items() if v['user_id'] == item.user_id]
        pending_list.sort(key=lambda x: x['timestamp'])

        for p_data in pending_list:
            ts = p_data['timestamp']
            
            # Verificar si cambió el día para mostrar separador
            msg_date = datetime.fromtimestamp(ts).date() if ts else None
            if msg_date and msg_date != current_day:
                current_day = msg_date
                chat_box.write(self._create_date_separator(ts))
            
            # Mensajes pendientes -> delivered=False (Hora Gris)
            panel = self._create_message_panel(
                p_data['text'], 
                "You", 
                is_me=True, 
                timestamp=ts,
                delivered=False 
            )
            chat_box.write(panel)
        
        chat_box.write("\n")
        
        # 4. Actualizamos lectura AHORA (después de mostrar)
        self.peer_last_read[item.user_id] = time.time()

    async def submit_message(self):
        """
        Procesa el envío de un mensaje desde la caja de texto.
        
        Cómo lo hace:
        1. Valida que haya texto y un chat seleccionado.
        2. Verifica que el contacto esté online.
        3. Muestra inmediatamente el mensaje en local con estilo "Pendiente" (Gris).
        4. Envía el mensaje cifrado a través del protocolo UDP.
        5. Registra el mensaje en 'pending_acks' esperando confirmación de recepción.
        """
        ta = self.query_one("#msg_input", ChatInput)
        text = ta.text.strip()
        if not text: return
        if not self.current_chat_addr:
            self.add_log("⚠️ Select a contact first!")
            return
            
        target_item = None
        lst = self.query_one("#contact_list", ListView)
        for child in lst.children:
            if isinstance(child, ChatItem) and child.contact_ip == self.current_chat_addr[0] and child.contact_port == self.current_chat_addr[1]:
                target_item = child
                break
        
        if target_item:
            if not target_item.online:
                self.add_log(f"⛔ Cannot send message: {target_item.real_name or target_item.user_id} is OFFLINE.")
                return
            # Si enviamos mensaje, consideramos el chat leído
            self.peer_last_read[target_item.user_id] = time.time()
        else:
             self.add_log("❌ Error: Contact not found in list context.")
             return

        ta.text = "" 
        now_ts = time.time()
        
        # Mostrar mensaje inmediatamente (Pendiente -> Gris)
        msg_panel = self._create_message_panel(text, "You", is_me=True, timestamp=now_ts, delivered=False)
        self.query_one("#chat_box", RichLog).write(msg_panel)
        
        # Enviar (puede que encole si hay handshake, pero ahora devuelve ID siempre)
        msg_id = await self.proto.send_message(self.current_chat_addr, text, user_id=target_item.user_id)
        
        if msg_id:
            # Rastrear para ACK (tanto si se envió ya como si está en cola de handshake)
            self.pending_acks[msg_id] = {
                'text': text,
                'timestamp': now_ts,
                'user_id': target_item.user_id
            }
        else:
            self.add_log("❌ Error fatal al enviar el paquete.")

    def on_ack_received(self, addr, ack_id):
        """
        Callback ejecutado cuando el protocolo recibe un ACK de mensaje.
        
        Cómo lo hace:
        Delega a '_handle_ack_safe' para procesarlo en el hilo principal.
        """
        self._handle_ack_safe(addr, ack_id)

    def _handle_ack_safe(self, addr, ack_id):
        """
        Procesa la confirmación de recepción de un mensaje.
        
        Cómo lo hace:
        1. Busca el ID en la lista de pendientes.
        2. Si existe, mueve el mensaje de 'pendientes' a almacenamiento persistente.
        3. Si el chat está activo, refresca la vista para cambiar el color del mensaje a verde (Entregado).
        """
        if ack_id in self.pending_acks:
            data = self.pending_acks.pop(ack_id)
            asyncio.create_task(
                self.storage.save_chat_message(
                    user_id=data['user_id'],
                    direction="out",
                    text=data['text'],
                    timestamp=data['timestamp']
                )
            )
            # Si estamos en el chat correcto, REFRESCAMOS para cambiar el color a verde
            if self.current_chat_addr == addr:
                lst = self.query_one("#contact_list", ListView)
                target_child = None
                for child in lst.children:
                    if isinstance(child, ChatItem) and child.contact_ip == addr[0] and child.contact_port == addr[1]:
                        target_child = child
                        break
                
                if target_child:
                    # Esto repintará el historial, y como el mensaje ya está guardado (delivered), saldrá verde
                    self.call_later(self._load_and_refresh_chat_history, target_child)

    def receive_message(self, addr, msg):
        """
        Callback ejecutado al recibir un mensaje UDP descifrado.
        
        Cómo lo hace:
        Delega a '_receive_message_safe' para procesarlo de forma segura en la UI.
        """
        self._receive_message_safe(addr, msg)

    def _receive_message_safe(self, addr, msg):
        """
        Lógica completa de recepción y visualización de mensajes entrantes.
        
        Cómo lo hace:
        1. Identifica al remitente en la lista de contactos. Si es desconocido, lo crea.
        2. Maneja mensajes de control 'disconnect' para marcar peers como offline.
        3. Valida la integridad del hash del mensaje. Si falla, muestra alerta de corrupción.
        4. Guarda el mensaje en almacenamiento persistente.
        5. Si el chat con ese usuario está abierto, muestra el mensaje inmediatamente.
        6. Si el chat no está abierto, registra un log de notificación.
        """
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

        if msg.get('disconnect') is True:
            if target_child:
                self.peer_last_seen[target_child.user_id] = 0
                self.recently_disconnected[target_child.user_id] = time.time()
                target_child.set_online_status(False)
                self.add_log(f"💤 {peer_name} has disconnected (Graceful exit).")
                disconnect_panel = Align(Panel(Text(f"{peer_name} se ha desconectado."), style="dim white"), align="left")
                if self.current_chat_addr == (ip, port):
                    self.query_one("#chat_box", RichLog).write(disconnect_panel)
            return
        
        if target_child:
            self.peer_last_seen[target_child.user_id] = time.time()
            target_child.set_online_status(True)
            
            # Actualizamos lectura SI estamos en ese chat
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

        # Los mensajes recibidos siempre se muestran como "Entregados" (son verdes o por defecto)
        msg_panel = self._create_message_panel(text, peer_name, is_me=False, timestamp=ts, delivered=True)
        curr_ip = self.current_chat_addr[0] if self.current_chat_addr else None
        
        if curr_ip == ip: 
            self.query_one("#chat_box", RichLog).write(msg_panel)
        else: 
            self.add_log(f"📨 New message from {peer_name}")

    def _create_message_panel(self, text, title, is_me, timestamp=None, delivered=True):
        """
        Helper gráfico para crear burbujas de mensaje estilizadas.
        
        Cómo lo hace:
        Genera un panel Rich con colores diferenciados:
        - Mensajes propios: Verde (si entregado) o Gris (si pendiente).
        - Mensajes ajenos: Naranja.
        Incluye la hora formateada en el título del panel.
        """
        color = "green" if is_me else "orange1"
        if timestamp:
            ts_str = datetime.fromtimestamp(timestamp).strftime("%H:%M")
            if is_me:
                # Si soy yo: Verde si entregado, Gris oscuro si pendiente de ACK
                time_color = "green" if delivered else "grey37"
                title = f"{title} [{time_color}]\\[{ts_str}][/]"
            else:
                # Si es el otro: Naranja igual que el nombre
                title = f"{title} [orange1]\\[{ts_str}][/]"
                
        return Align(Panel(Text(text), title=title, title_align="left", border_style=color, box=box.ROUNDED, padding=(0, 1), expand=False), align="left")
    
    def _create_date_separator(self, timestamp):
        """
        Helper gráfico para crear una línea separadora con la fecha.
        
        Cómo lo hace:
        Utiliza el widget Rule de Rich para dibujar una línea horizontal con la fecha formateada en el centro.
        """
        date_str = datetime.fromtimestamp(timestamp).strftime("%d / %m / %Y")
        return Rule(title=f"📅 {date_str}", style="cyan")

# --- NUEVA APP DE LOGIN DNIe ---

class DNIeLoginApp(App):
    """
    Aplicación independiente que gestiona la pantalla de Login con DNIe.
    Se ejecuta antes que la aplicación principal de mensajería.
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
    #title { text-align: center; color: $secondary; text-style: bold; margin-bottom: 2; }
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
        """
        Inicializa la App de Login.
        
        Cómo lo hace:
        Recibe la clave pública efímera generada al inicio para firmarla con el DNIe
        y probar la identidad de red.
        """
        super().__init__()
        self.key_to_sign_bytes = key_to_sign_bytes
        self.return_data = None 
        self.is_logging_in = False 

    def compose(self) -> ComposeResult:
        """
        Construye la interfaz de Login.
        
        Cómo lo hace:
        Crea una caja centrada con: estado de tarjeta, input de PIN (oculto) y botón de acceso.
        """
        with Container(classes="login-box"):
            yield Label("🔐 DNIe Identity Access", id="title")
            yield Label("Buscando lector...", id="card-status", classes="card-missing")
            yield Label("Introduzca su PIN:", id="status")
            yield LoadingIndicator(id="loading")
            yield Input(placeholder="PIN del DNIe", password=True, id="pin", disabled=True)
            yield Button("Acceder", variant="primary", id="btn_login", disabled=True)
            yield Label("", id="error-msg")

    def on_mount(self):
        """
        Evento de inicio de la UI de Login.
        
        Cómo lo hace:
        Inicia un temporizador para chequear periódicamente la presencia del lector/tarjeta.
        """
        self.set_interval(1.5, self.check_card_presence)
        self.check_card_presence()

    @work(thread=True)
    def check_card_presence(self):
        """
        Hilo de fondo (worker) que verifica si hay una tarjeta insertada.
        
        Cómo lo hace:
        Intenta conectar con la librería PKCS#11. Si tiene éxito, considera la tarjeta presente.
        Llama a 'update_card_ui' en el hilo principal para actualizar la interfaz.
        """
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
        """
        Actualiza el estado visual del lector de tarjetas.
        
        Cómo lo hace:
        Habilita o deshabilita el input de PIN y el botón de acceso según 'is_present'.
        Cambia las etiquetas de estado a verde (detectada) o rojo (ausente).
        """
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
        """
        Maneja el evento 'Enter' en el campo de PIN.
        """
        if not self.query_one("#btn_login", Button).disabled:
            self.action_login()

    def on_button_pressed(self, event: Button.Pressed):
        """
        Maneja el clic en el botón de acceso.
        """
        if event.button.id == "btn_login":
            self.action_login()
    
    def action_login(self):
        """
        Inicia el proceso de login.
        
        Cómo lo hace:
        1. Valida que el PIN no esté vacío.
        2. Bloquea la UI para evitar doble envío.
        3. Muestra indicador de carga.
        4. Lanza 'run_dnie_operation' en un hilo exclusivo para no congelar la UI.
        """
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
        Ejecuta las operaciones criptográficas críticas con el DNIe.
        
        Cómo lo hace:
        1. Conecta con la SmartCard y valida el PIN.
        2. Obtiene el certificado de autenticación y firma la clave de red (para identidad pública).
        3. Deriva una clave determinista para el almacenamiento local cifrado:
           - Calcula un hash del número de serie + separador de dominio.
           - Firma ese hash con la clave privada del DNIe.
           - Esta firma será la semilla para la clave AES del disco.
        4. Si todo es exitoso, llama a 'exit_success' con los resultados.
        5. Si falla, llama a 'show_error'.
        """
        try:
            card = DNIeCard()
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Autenticando PIN..."))
            card.connect()
            card.authenticate(pin)
            
            # 1. Obtener certificado y firmar identidad de red (Proceso original)
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Firmando identidad de red..."))
            cert_der = card.get_certificate()
            network_signature = card.sign_data(self.key_to_sign_bytes)
            user_id = card.get_serial_hash()[:8]
            proofs = {'cert': cert_der.hex(), 'sig': network_signature.hex()}

            # 2. NUEVO: Derivación de clave de cifrado para almacenamiento
            # Calculamos Hash(Serial_DNI + DomainSeparator)
            self.call_from_thread(lambda: self.query_one("#status", Label).update("Generando clave de cifrado..."))
            
            serial_raw = card.get_serial()
            # Aseguramos bytes
            serial_bytes = serial_raw.encode('utf-8') if isinstance(serial_raw, str) else serial_raw
            separator_bytes = self.DOMAIN_SEPARATOR.encode('utf-8')
            
            data_to_hash_for_key = serial_bytes + separator_bytes
            digest = hashlib.sha256(data_to_hash_for_key).digest()
            
            # Firmamos ese hash con la clave privada del DNIe
            storage_signature = card.sign_data(digest)

            # Retornamos todo
            self.return_data = (user_id, proofs, storage_signature)
            self.call_from_thread(self.exit_success)
            
        except Exception as e:
            self.call_from_thread(lambda: self.show_error(f"❌ Error: {str(e)}"))
        finally:
            try: card.disconnect()
            except: pass

    def exit_success(self):
        """
        Cierra la aplicación de Login devolviendo los datos criptográficos.
        """
        self.exit(result=self.return_data)

    def show_error(self, msg):
        """
        Muestra un error en la interfaz y resetea el formulario para reintentar.
        
        Cómo lo hace:
        Desbloquea los inputs, oculta el indicador de carga y muestra el mensaje de error en rojo.
        """
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