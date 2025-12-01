import socket
import sys
import threading
import time
import select
import subprocess # Utilizado para criar processos filhos (simular o cliente Curl)
from datetime import datetime
from urllib.parse import urlparse
from cryptography.fernet import Fernet

# --- Bibliotecas de Interface Gráfica (PySide6/Qt) ---
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLineEdit,
    QHeaderView, QLabel, QMessageBox, QTextEdit, QFrame
)
from PySide6.QtCore import QTimer, Qt, Signal, QObject

# =============================================================================
# == SISTEMA DE LOGS E SINAIS (Comunicação Thread-Safe)
# =============================================================================

class LogBridge(QObject):
    """
    Classe utilitária que herda de QObject para permitir o uso de Signals.
    Isso é necessário porque threads de background (o servidor) não podem
    escrever diretamente na GUI. Elas emitem um 'sinal' que a GUI captura.
    """
    new_log = Signal(str)

log_bridge = LogBridge()

def log(message):
    """
    Função centralizada de log.
    Envia a mensagem tanto para o terminal (stdout) quanto para a Interface Gráfica.
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    print(formatted_msg)
    log_bridge.new_log.emit(formatted_msg) # Dispara o sinal para a GUI

# =============================================================================
# == CONFIGURAÇÕES E VARIÁVEIS GLOBAIS
# =============================================================================

HOST = '::1' # Endereço IPv6 Localhost
PORT = 8080
BUFFER_SIZE = 4096

# Chave simétrica para criptografia do Cache (Fernet)
ENCRYPTION_KEY = b'jjHaGM9MQ4EFGP_TiVf4B977sTpwQQRgegJEfC89fV0='
fernet_cipher = Fernet(ENCRYPTION_KEY)

# Configurações de expiração e armazenamento
CACHE_EXPIRATION_SECONDS = 300 # 5 minutos
proxy_cache = {} # O "Banco de Dados" em memória

# Mecanismo de Sincronização:
# Este Lock é fundamental para evitar "Race Conditions" quando o servidor (escrita)
# e a interface gráfica (leitura) tentam acessar o 'proxy_cache' simultaneamente.
cache_lock = threading.Lock() 

# =============================================================================
# == NÚCLEO DE REDE (BACKEND)
# =============================================================================

def parse_request(request_data):
    """
    Responsável pelo 'parsing' da requisição bruta (bytes).
    Identifica o método (GET vs CONNECT) e extrai o destino (Host/Porta).
    É aqui que o roteamento lógico do proxy começa.
    """
    thread_id = threading.current_thread().ident
    try:
        request_str = request_data.decode('utf-8', errors='ignore')
        first_line = request_str.split('\n')[0]
        method, url, http_version = first_line.split(' ')
        log(f"[Thread: {thread_id}] > [CLIENTE -> PROXY] Método: {method}, URL: {url}")

        # Tratamento especial para HTTPS (Método CONNECT)
        if method == 'CONNECT':
            try:
                host, port_str = url.split(':')
                port = int(port_str)
                return host, port, request_data, method, url
            except ValueError as e:
                log(f"[Thread: {thread_id}] > Erro ao analisar CONNECT: {e}")
                return None, None, None, None, None
            
        # Tratamento para HTTP Padrão (GET, POST, etc.)
        parsed_url = urlparse(url)
        if parsed_url.netloc:
            host = parsed_url.hostname
            port = parsed_url.port or 80
        else: 
            # Busca o host nos headers se a URL for relativa
            for line in request_str.split('\n'):
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    port = 80 
                    break
            else:
                log(f"[Thread: {thread_id}] > Erro: Host não encontrado.")
                return None, None, None, None, None
        
        log(f"[Thread: {thread_id}] > Destino identificado: {host}:{port}")
        return host, port, request_data, method, url

    except Exception as e:
        log(f"[Thread: {thread_id}] > Erro ao analisar requisição: {e}")
        return None, None, None, None, None

def get_compatible_address(host, port):
    """
    Implementa a lógica de resolução de nomes (DNS).
    Prioriza IPv6 conforme requisito do projeto, mas mantém fallback
    para IPv4 para garantir compatibilidade com a internet atual.
    """
    thread_id = threading.current_thread().ident
    
    # 1. Tentativa Primária: Resolver para IPv6 (AF_INET6)
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
        log(f"[Thread: {thread_id}] > [DNS] IPv6 encontrado: {addr_info[0][4][0]}")
        return socket.AF_INET6, addr_info[0][4]
    except socket.gaierror:
        log(f"[Thread: {thread_id}] > [DNS] IPv6 falhou. Iniciando fallback para IPv4...")
    
    # 2. Fallback: Resolver para IPv4 (AF_INET)
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        log(f"[Thread: {thread_id}] > [DNS] IPv4 encontrado: {addr_info[0][4][0]} (Fallback)")
        return socket.AF_INET, addr_info[0][4]
    except socket.gaierror:
        log(f"[Thread: {thread_id}] > [DNS] Erro Fatal: DNS falhou para ambos os protocolos.")
        return None, None

def handle_client_connection(client_socket, client_addr):
    """
    Função 'Worker'. Executada em uma thread dedicada para cada cliente.
    Gerencia todo o ciclo de vida da requisição HTTP:
    1. Verifica Cache (HIT).
    2. Busca na Rede se necessário (MISS).
    3. Criptografa e armazena novas respostas.
    """
    thread_id = threading.current_thread().ident
    log(f"\n[Thread: {thread_id}] --- NOVA CONEXÃO DE: {client_addr} ---")
    try:
        request_data = client_socket.recv(BUFFER_SIZE)
        if not request_data:
            client_socket.close()
            return
        
        dest_host, dest_port, parsed_request, method, url = parse_request(request_data)
        if not dest_host:
            client_socket.close()
            return
        
        # --- ROTEAMENTO DE PROTOCOLO ---
        
        if method == 'CONNECT':
            log(f"[Thread: {thread_id}] Modo HTTPS (Túnel) ativado para {dest_host}")
            handle_https_tunnel(client_socket, dest_host, dest_port, thread_id)

        elif method == 'GET':
            # --- LÓGICA DE CACHE HTTP ---
            cache_hit = False
            
            # Bloqueio de leitura para thread-safety
            with cache_lock: 
                if url in proxy_cache:
                    cached_item = proxy_cache[url]
                    cache_time = cached_item['timestamp']
                    
                    # Verifica validade temporal do cache
                    if (time.time() - cache_time) < CACHE_EXPIRATION_SECONDS:
                        cache_hit = True
                        log(f"[Thread: {thread_id}] [CACHE] *** HIT *** URL válida encontrada.")
                        try:
                            # Descriptografia "on-the-fly" antes de enviar ao cliente
                            encrypted_response = cached_item['response']
                            response_from_cache = fernet_cipher.decrypt(encrypted_response)
                            log(f"[Thread: {thread_id}] [CACHE] Dados descriptografados com sucesso.")
                        except Exception as e:
                            log(f"[Thread: {thread_id}] Erro descriptografia: {e}. Tratando como MISS.")
                            cache_hit = False
                            del proxy_cache[url]
                    else:
                        log(f"[Thread: {thread_id}] [CACHE] Item expirado. Removendo do dicionário.")
                        del proxy_cache[url]
            
            if cache_hit:
                log(f"[Thread: {thread_id}] [PROXY -> CLIENTE] Enviando dados do cache...")
                client_socket.sendall(response_from_cache)
                return # Fim da execução (economia de rede)
            
            log(f"[Thread: {thread_id}] [CACHE] *** MISS *** Buscando na internet...")
            
        else:
            log(f"[Thread: {thread_id}] Método {method} não cacheável. Passando direto.")
        
        # --- LÓGICA DE REDE (CACHE MISS) ---
        
        dest_family, dest_address = get_compatible_address(dest_host, dest_port)
        if not dest_family:
            client_socket.close()
            return
        
        try:
            dest_socket = socket.socket(dest_family, socket.SOCK_STREAM)
            dest_socket.connect(dest_address)
            log(f"[Thread: {thread_id}] [PROXY -> SERVIDOR] Conectado ao servidor final.")
        except Exception as e:
            log(f"[Thread: {thread_id}] Erro conexão destino: {e}")
            client_socket.close()
            return
        
        try:
            dest_socket.sendall(parsed_request)
            log(f"[Thread: {thread_id}] [PROXY -> SERVIDOR] Requisição encaminhada.")
        except socket.error:
            dest_socket.close()
            client_socket.close()
            return
        
        dest_socket.settimeout(2.0)
        log(f"[Thread: {thread_id}] [SERVIDOR -> PROXY] Aguardando resposta...")
        full_response_bytes = b""
        
        # Loop de recebimento da resposta
        while True:
            try:
                response_data = dest_socket.recv(BUFFER_SIZE)
                if len(response_data) > 0:
                    full_response_bytes += response_data
                    client_socket.sendall(response_data) # Repasse imediato ao cliente
                else:
                    log(f"[Thread: {thread_id}] [SERVIDOR -> PROXY] Resposta completa (fim de stream).")
                    break
            except socket.timeout:
                log(f"[Thread: {thread_id}] [SERVIDOR -> PROXY] Resposta completa (timeout).")
                break
            except socket.error:
                break

        # --- ARMAZENAMENTO SEGURO ---
        if method == 'GET' and len(full_response_bytes) > 0:
            log(f"[Thread: {thread_id}] [CACHE] Iniciando criptografia e salvamento...")
            try:
                # Criptografia antes de salvar na memória (Requisito de Segurança)
                encrypted_response_bytes = fernet_cipher.encrypt(full_response_bytes)
                
                with cache_lock: # Bloqueio de escrita
                    proxy_cache[url] = {
                        'response': encrypted_response_bytes,
                        'timestamp': time.time()
                    }
                log(f"[Thread: {thread_id}] [CACHE] Objeto salvo com segurança.")
            except Exception as e:
                log(f"[Thread: {thread_id}] Erro no armazenamento do cache: {e}")

    except ConnectionAbortedError:
        log(f"[Thread: {thread_id}] Túnel HTTPS finalizado normalmente.")
    except Exception as e:
        log(f"[Thread: {thread_id}] Erro inesperado na thread: {e}")
    finally:
        if 'dest_socket' in locals():
            dest_socket.close()
        client_socket.close()
        log(f"[Thread: {thread_id}] Conexões fechadas.")

def handle_https_tunnel(client_socket, dest_host, dest_port, thread_id):
    """
    Estabelece um Túnel TCP cego para tráfego HTTPS.
    Como o tráfego é criptografado (TLS), o proxy não pode ler nem cachear.
    Utiliza 'select' para multiplexação de I/O eficiente.
    """
    dest_family, dest_address = get_compatible_address(dest_host, dest_port)
    if not dest_family: return
    try:
        dest_socket = socket.socket(dest_family, socket.SOCK_STREAM)
        dest_socket.connect(dest_address)
        log(f"[Thread: {thread_id}] [HTTPS] Conectado ao destino {dest_host}.")
    except Exception as e:
        log(f"[Thread: {thread_id}] [HTTPS] Erro conexão: {e}")
        return
    try:
        # Handshake inicial: Avisa o cliente que o túnel está aberto
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except socket.error:
        dest_socket.close()
        return
    
    # Configuração Não-Bloqueante para uso com Select
    client_socket.setblocking(0)
    dest_socket.setblocking(0)
    sockets = [client_socket, dest_socket]
    log(f"[Thread: {thread_id}] [HTTPS] Túnel estabelecido. Repassando dados criptografados...")

    connection_open = True
    try:
        while connection_open:
            # Monitora ambos os sockets por atividade de leitura
            readable_sockets, _, exceptional_sockets = select.select(sockets, [], sockets, 2.0)
            
            if exceptional_sockets: break 
            if not readable_sockets: continue # Timeout do select, continua loop
                
            for sock in readable_sockets:
                try:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        connection_open = False 
                        break 
                    
                    # Repasse simples
                    if sock is client_socket:
                        dest_socket.sendall(data)
                    elif sock is dest_socket:
                        client_socket.sendall(data)
                except (BlockingIOError, InterruptedError): continue 
                except socket.error:
                    connection_open = False
                    break
    except socket.error: pass
    finally:
        dest_socket.close()
        # Levanta exceção controlada para finalizar a thread pai
        raise ConnectionAbortedError("Túnel HTTPS fechado.")

# =============================================================================
# == INTERFACE GRÁFICA (FRONTEND - PySide6)
# =============================================================================

class CacheManagerWindow(QMainWindow):
    """
    Janela principal de monitoramento.
    Roda na Thread Principal e se comunica com o Backend via Sinais e Lock.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitor do Servidor Proxy IPv6")
        self.setGeometry(100, 100, 900, 700) 

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- PAINEL DE SIMULAÇÃO DE CLIENTE ---
        simulation_frame = QFrame()
        simulation_frame.setFrameShape(QFrame.StyledPanel)
        sim_layout = QVBoxLayout(simulation_frame)
        
        sim_layout.addWidget(QLabel("<b>Simulador de Cliente (Curl) - Processo Independente</b>"))
        
        input_layout = QHBoxLayout()
        self.url_input = QLineEdit("http://example.com")
        self.url_input.setPlaceholderText("Digite a URL alvo...")
        self.sim_button = QPushButton("Disparar Requisição")
        self.sim_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.sim_button.clicked.connect(self.run_simulation)
        
        input_layout.addWidget(QLabel("URL:"))
        input_layout.addWidget(self.url_input)
        input_layout.addWidget(self.sim_button)
        
        sim_layout.addLayout(input_layout)
        sim_layout.addWidget(QLabel("<i>Cria um sub-processo do sistema operacional executando 'curl' via proxy.</i>"))
        
        main_layout.addWidget(simulation_frame)
        main_layout.addSpacing(10)

        # --- TABELA DE VISUALIZAÇÃO DO CACHE ---
        main_layout.addWidget(QLabel("<b>Banco de Dados do Cache (Memória Protegida)</b>"))
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["URL", "Timestamp", "Expira em (s)", "Tamanho (bytes)"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch) 
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 100)
        self.table.setMinimumHeight(150)
        main_layout.addWidget(self.table)

        self.clear_button = QPushButton("Esvaziar Cache")
        self.clear_button.clicked.connect(self.clear_cache)
        main_layout.addWidget(self.clear_button)

        main_layout.addSpacing(10)

        # --- CONSOLE DE LOGS EM TEMPO REAL ---
        main_layout.addWidget(QLabel("<b>Console de Eventos (Backend -> Frontend)</b>"))
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        main_layout.addWidget(self.log_display)

        # --- Configuração de Timers e Eventos ---
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.populate_cache_table)
        self.timer.start(3000) # Polling a cada 3 segundos
        
        # Conecta o sinal do backend ao slot da GUI
        log_bridge.new_log.connect(self.append_log)

        self.populate_cache_table()
        log("Sistema Iniciado. Interface Gráfica pronta.")

    def run_simulation(self):
        """
        Cria um processo filho (subprocess) para executar o curl.exe.
        Isso demonstra a independência entre Cliente e Servidor.
        """
        target_url = self.url_input.text().strip()
        if not target_url: return

        proxy_url = "http://[::1]:8080"
        command = ["curl.exe", "-x", proxy_url, target_url]
        
        if target_url.lower().startswith("https"):
            command.append("-k") # Ignora SSL self-signed para testes
            log(f"[SIMULADOR] Iniciando processo: curl -x {proxy_url} -k {target_url}")
        else:
            log(f"[SIMULADOR] Iniciando processo: curl -x {proxy_url} {target_url}")

        try:
            # Inicia o processo de forma assíncrona (não bloqueia a GUI)
            subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        except FileNotFoundError:
            log("[ERRO] curl.exe não encontrado no PATH do sistema.")
        except Exception as e:
            log(f"[ERRO] Falha ao iniciar subprocesso: {e}")

    def append_log(self, message):
        """Recebe o texto do backend via sinal e atualiza a UI."""
        self.log_display.append(message)
        self.log_display.verticalScrollBar().setValue(self.log_display.verticalScrollBar().maximum())

    def clear_cache(self):
        log("[GUI] Usuário solicitou limpeza. Aguardando Lock...")
        try:
            with cache_lock: # Adquire exclusividade sobre o dicionário
                proxy_cache.clear()
            log("[GUI] Cache esvaziado com sucesso.")
            self.populate_cache_table()
            QMessageBox.information(self, "Sucesso", "Cache limpo.")
        except Exception as e:
            log(f"[GUI] Erro ao limpar: {e}")

    def populate_cache_table(self):
        """
        Lê o estado atual do cache e atualiza a tabela visual.
        Realiza descriptografia temporária para exibir metadados (tamanho).
        """
        items_to_display = []
        current_time = time.time()
        try:
            with cache_lock: # Leitura segura
                for url, data in proxy_cache.items():
                    try:
                        decrypted_data = fernet_cipher.decrypt(data['response'])
                        size = len(decrypted_data)
                    except Exception: size = "Erro Cripto"
                    cache_time = data['timestamp']
                    expires_in = (cache_time + CACHE_EXPIRATION_SECONDS) - current_time
                    items_to_display.append({
                        'url': url,
                        'time_str': datetime.fromtimestamp(cache_time).strftime('%H:%M:%S'),
                        'expires_str': f"{expires_in:.0f}s" if expires_in > 0 else "Expira",
                        'size_str': str(size)
                    })
        except Exception: return 

        self.table.setSortingEnabled(False) 
        self.table.setRowCount(0) 
        self.table.setRowCount(len(items_to_display))
        for i, item in enumerate(items_to_display):
            self.table.setItem(i, 0, QTableWidgetItem(item['url']))
            self.table.setItem(i, 1, QTableWidgetItem(item['time_str']))
            self.table.setItem(i, 2, QTableWidgetItem(item['expires_str']))
            self.table.setItem(i, 3, QTableWidgetItem(item['size_str']))
        self.table.setSortingEnabled(True)

# =============================================================================
# == INICIALIZAÇÃO E GERENCIAMENTO DE THREADS
# =============================================================================

def start_server_thread():
    """
    Ponto de entrada da Thread do Servidor.
    Inicializa o socket e entra no loop de aceitação de conexões.
    """
    try:
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) 
        log(f"[SERVIDOR] Socket inicializado. Ouvindo na porta {PORT} (IPv6)")
    except Exception as e:
        log(f"[SERVIDOR] Erro fatal na inicialização do socket: {e}")
        sys.exit(1)
    try:
        while True:
            # accept() é bloqueante, por isso roda em thread separada da GUI
            client_socket, client_addr = server_socket.accept()
            # Dispara thread worker para não bloquear novas conexões
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_addr))
            client_thread.daemon = True 
            client_thread.start()
    except Exception as e:
        log(f"[SERVIDOR] Erro no loop principal: {e}")
    finally:
        server_socket.close()

def main():
    """
    Função Main. Responsável por orquestrar o início dos subsistemas.
    """
    # 1. Inicia o subsistema de rede (Backend) em background
    server_thread = threading.Thread(target=start_server_thread)
    server_thread.daemon = True # Thread morre se a GUI fechar
    server_thread.start()

    # 2. Inicia o subsistema de interface (Frontend) na thread principal
    # (Interfaces gráficas exigem rodar na Main Thread do processo)
    app = QApplication(sys.argv)
    window = CacheManagerWindow()
    window.show()
    
    # 3. Entra no loop de eventos da GUI
    sys.exit(app.exec())

if __name__ == "__main__":
    main()