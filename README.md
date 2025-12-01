# 🌐 Servidor Proxy HTTP/HTTPS com Suporte a IPv6 e Cache Criptografado

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![IPv6](https://img.shields.io/badge/Network-IPv6%20Ready-green?style=for-the-badge)
![GUI](https://img.shields.io/badge/Interface-PySide6-orange?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Fernet%20Encryption-red?style=for-the-badge)

Este projeto consiste na implementação completa de um **Servidor Proxy Concorrente**, desenvolvido em Python. O sistema atua como intermediário entre clientes e a web, oferecendo otimização de tráfego via **cache em memória**, segurança via **criptografia** e suporte nativo a redes modernas com **IPv6**.

O diferencial deste projeto é a integração de um Backend robusto com uma **Interface Gráfica (GUI)** para monitoramento em tempo real, auditoria de logs e simulação de clientes.

---

## 🚀 Funcionalidades Principais

### 1. Núcleo de Rede & Conectividade (Dual-Stack)
* **IPv6 First:** O servidor escuta nativamente em endereços IPv6 (`[::1]`).
* **Resolução Inteligente:** O sistema prioriza a resolução de DNS para IPv6. Caso a rede ou o site de destino não suportem, ele realiza um *fallback* automático e transparente para IPv4.

### 2. Arquitetura Concorrente
* **Multithreading:** Utiliza a biblioteca `threading` para gerenciar múltiplas conexões simultâneas sem bloqueios.
* **Separação de Processos:** A GUI roda na Thread Principal (Main), enquanto o Servidor roda em Threads de Background (Daemon), garantindo fluidez na interface.

### 3. Cache HTTP Seguro (Data-at-Rest)
* **Interceptação GET:** Requisições HTTP são analisadas e, se elegíveis, armazenadas em memória.
* **Criptografia Fernet:** Todo o conteúdo salvo no cache é criptografado com chave simétrica antes de ser armazenado, garantindo a confidencialidade dos dados em memória.
* **TTL (Time-to-Live):** Sistema automático de expiração de cache (padrão: 5 minutos).

### 4. Suporte a HTTPS (Tunelamento)
* **Método CONNECT:** Implementação de tunelamento TCP para tráfego seguro.
* **Blind Relay:** Cria um canal direto entre cliente e servidor utilizando `select` para multiplexação de I/O, preservando a criptografia ponta-a-ponta (TLS) sem violar a privacidade do usuário.

### 5. Ferramentas de Monitoramento (GUI)
* **Console de Logs:** Visualização passo a passo do fluxo da requisição (`Cliente -> Proxy -> Servidor -> Cache`).
* **Simulador Integrado:** Dispara subprocessos do sistema (`curl`) diretamente da interface para provar a comunicação entre processos distintos.

---

## 🛠️ Tecnologias Utilizadas

* **Linguagem:** Python 3.10+
* **Interface Gráfica:** PySide6 (Qt for Python)
* **Rede:** Biblioteca `socket` (Low-level networking)
* **Criptografia:** Biblioteca `cryptography` (Fernet)
* **Concorrência:** `threading`, `select`
* **Processos:** `subprocess`

---

## ⚙️ Instalação e Execução

### Pré-requisitos
* Python instalado.
* Git instalado.

### Passo a Passo

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/StefanyZaia/ProxyCache.git](https://github.com/StefanyZaia/ProxyCache.git)
    cd ProxyCache
    ```

2.  **Crie e ative um ambiente virtual (Recomendado):**
    ```bash
    # Windows
    python -m venv .venv
    .\.venv\Scripts\Activate

    # Linux/Mac
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Instale as dependências:**
    ```bash
    pip install pyside6 cryptography
    ```

4.  **Execute a aplicação:**
    ```bash
    python proxy_cache.py
    ```

---

## 🧪 Como Testar

Com a interface aberta, você pode testar de duas formas:

### Opção 1: Simulador Integrado (Fácil)
1.  Na parte superior da janela, digite a URL (ex: `http://example.com` ou `https://google.com`).
2.  Clique em **"Disparar Requisição"**.
3.  Acompanhe o fluxo no console de logs preto na parte inferior.

### Opção 2: Via Terminal (Curl)
Abra um terminal externo e execute:

```bash
# Teste HTTP (Gera Cache)
curl -x "[http://[::1]:8080](http://[::1]:8080)" [http://example.com](http://example.com)

# Teste HTTPS (Gera Túnel)
curl -x "[http://[::1]:8080](http://[::1]:8080)" -k [https://google.com](https://google.com)
