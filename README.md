# SecureLink

<p align="center">
  Laboratório de comunicação segura com <strong>Python</strong>,
  <strong>OpenVPN</strong>, <strong>X25519</strong>,
  <strong>HKDF-SHA256</strong> e <strong>ChaCha20-Poly1305</strong>.
</p>

<p align="center">
  <a href="https://github.com/DaniloArantesVieira/Comunicacao-Criptografada/actions/workflows/ci.yml">
    <img src="https://github.com/DaniloArantesVieira/Comunicacao-Criptografada/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/DaniloArantesVieira/Comunicacao-Criptografada/releases">
    <img src="https://img.shields.io/github/v/release/DaniloArantesVieira/Comunicacao-Criptografada" alt="Release">
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
  </a>
</p>

---

## Sobre o projeto

O **SecureLink** é um projeto educacional e laboratorial voltado ao estudo de
**comunicação segura entre aplicações**, combinando criptografia aplicada,
certificados digitais, VPN e isolamento de serviços com Docker.

O ambiente implementa comunicação entre duas aplicações Python através de um
túnel OpenVPN. Além da proteção fornecida pela VPN, a própria aplicação utiliza
um protocolo criptográfico baseado em:

- **X25519** para acordo de chaves;
- **HKDF-SHA256** para derivação de chave;
- **ChaCha20-Poly1305** para criptografia autenticada;
- **AAD (Additional Authenticated Data)** para autenticação de metadados;
- nonces aleatórios de **12 bytes**.

O projeto também possui validações de protocolo, limites de tamanho, timeout de
sockets, testes automatizados e pipeline de integração contínua.

> **Aviso:** este repositório possui finalidade educacional e laboratorial e não
> deve ser considerado, sem revisão adicional, uma implementação pronta para
> ambientes de produção.

---

## Arquitetura

```text
                         SecureLink
┌──────────────────────────────────────────────────────────────┐
│                         Docker Compose                       │
│                                                              │
│  ┌─────────────────┐                      ┌─────────────────┐ │
│  │   app_client    │                      │   app_server    │ │
│  │     Python      │                      │     Python      │ │
│  └────────┬────────┘                      └────────▲────────┘ │
│           │ network_mode                           │          │
│           ▼                                        │          │
│  ┌─────────────────┐                      ┌─────────────────┐ │
│  │  client_norte   │                      │   client_sul    │ │
│  │    OpenVPN      │                      │    OpenVPN      │ │
│  │   10.8.0.2      │                      │   10.8.0.3      │ │
│  └────────┬────────┘                      └────────▲────────┘ │
│           │                                        │          │
│           └──────────────┐        ┌────────────────┘          │
│                          ▼        │                           │
│                     ┌─────────────────┐                       │
│                     │ OpenVPN Server  │                       │
│                     │    10.8.0.1     │                       │
│                     └─────────────────┘                       │
│                                                              │
│                     ┌─────────────────┐                       │
│                     │       CA        │                       │
│                     │ certificados   │                       │
│                     └─────────────────┘                       │
└──────────────────────────────────────────────────────────────┘
```

A aplicação cliente compartilha o namespace de rede do `client_norte`, enquanto
a aplicação servidora compartilha o namespace do `client_sul`.

Com isso, a comunicação da aplicação ocorre através da VPN:

```text
10.8.0.2 → tun0 → OpenVPN → tun0 → 10.8.0.3
```

---

## Camadas de segurança

O SecureLink combina duas camadas principais de proteção.

### OpenVPN

A camada de transporte utiliza:

- TLS 1.3 como versão mínima;
- certificados emitidos pela CA do laboratório;
- validação do certificado do servidor pelo cliente;
- validação de certificados de cliente pelo servidor;
- grupos TLS `X25519` e `secp256r1`;
- `ChaCha20-Poly1305` como cifra do canal de dados;
- endereçamento VPN determinístico via CCD.

Endereços utilizados:

| Componente | Endereço VPN |
|---|---|
| OpenVPN Server | `10.8.0.1` |
| Cliente Norte | `10.8.0.2` |
| Cliente Sul | `10.8.0.3` |

### Criptografia da aplicação

Mesmo dentro do túnel VPN, a mensagem possui proteção criptográfica própria.

```text
X25519
   │
   ▼
Shared Secret
   │
   ▼
HKDF-SHA256
   │
   ▼
Chave de 256 bits
   │
   ▼
ChaCha20-Poly1305
   │
   ├── Plaintext
   ├── Nonce de 12 bytes
   └── AAD
```

A chave compartilhada não é transmitida pela rede.

---

## Protocolo da aplicação

Cliente e servidor iniciam gerando pares de chaves X25519.

As chaves públicas são trocadas e cada lado calcula localmente o segredo
compartilhado.

A estrutura transmitida pela aplicação utiliza:

```text
┌────────────────────────┐
│ Public Key - 32 bytes  │
├────────────────────────┤
│ AAD Length - 2 bytes   │
├────────────────────────┤
│ AAD                    │
├────────────────────────┤
│ Nonce - 12 bytes       │
├────────────────────────┤
│ Ciphertext Length      │
│       4 bytes          │
├────────────────────────┤
│ Ciphertext + Tag       │
└────────────────────────┘
```

### Limites de segurança

O protocolo aplica os seguintes limites:

| Parâmetro | Limite |
|---|---:|
| Timeout do socket | 10 segundos |
| AAD máximo | 4 KiB |
| Ciphertext mínimo | 16 bytes |
| Ciphertext máximo | 1 MiB |

Os comprimentos são validados **antes da leitura dos respectivos payloads**,
reduzindo o risco de bloqueios ou consumo excessivo de memória causado por
frames inválidos.

Leituras de socket também utilizam `recv_exact()`, garantindo que mensagens
parciais sejam tratadas corretamente.

---

## Estrutura do repositório

```text
securelink/
├── .github/
│   └── workflows/
│       └── ci.yml
├── app/
│   ├── crypto/
│   │   ├── chacha20.py
│   │   ├── ecdh.py
│   │   └── kdf.py
│   ├── Dockerfile
│   ├── message_client.py
│   ├── message_server.py
│   ├── protocol.py
│   └── requirements.txt
├── ca/
│   ├── scripts/
│   │   ├── init_ca.sh
│   │   └── issue_cert.sh
│   ├── Dockerfile
│   └── openssl.cnf
├── client/
│   ├── scripts/
│   │   └── entrypoint.sh
│   ├── Dockerfile
│   └── client.conf
├── server/
│   ├── ccd/
│   │   ├── cliente_norte
│   │   └── cliente_sul
│   ├── scripts/
│   │   └── entrypoint.sh
│   ├── Dockerfile
│   └── server.conf
├── tests/
│   ├── test_crypto.py
│   └── test_runtime.py
├── .gitattributes
├── .gitignore
├── docker-compose.yml
├── LICENSE
├── pyproject.toml
├── requirements-dev.txt
├── SECURITY.md
└── README.md
```

---

## Principais componentes

### `app/`

Implementa a comunicação entre as aplicações.

- `message_client.py` — cliente da aplicação;
- `message_server.py` — servidor da aplicação;
- `protocol.py` — framing, limites e leitura segura do protocolo;
- `crypto/ecdh.py` — acordo de chaves X25519;
- `crypto/kdf.py` — derivação com HKDF-SHA256;
- `crypto/chacha20.py` — criptografia autenticada ChaCha20-Poly1305.

### `ca/`

Implementa a autoridade certificadora utilizada pelo laboratório.

A CA é responsável pela geração e assinatura dos certificados usados pelos
componentes OpenVPN.

### `client/`

Imagem e configuração dos clientes OpenVPN.

O mesmo componente é utilizado para criar:

```text
cliente_norte → 10.8.0.2
cliente_sul   → 10.8.0.3
```

### `server/`

Servidor OpenVPN do ambiente.

Utiliza CCD (`client-config-dir`) para atribuir endereços VPN previsíveis aos
clientes.

### `tests/`

Contém os testes da camada criptográfica e das proteções implementadas em
runtime e no protocolo.

---

## Requisitos

Para executar o ambiente completo:

- Docker;
- Docker Compose;
- suporte a `/dev/net/tun`.

Para desenvolvimento e execução dos testes localmente:

- Python 3.11 ou superior;
- dependências de `requirements-dev.txt`.

---

## Executando o laboratório

Clone o repositório:

```bash
git clone https://github.com/DaniloArantesVieira/Comunicacao-Criptografada.git
cd Comunicacao-Criptografada
```

Suba o ambiente:

```bash
docker compose up --build
```

Ou em segundo plano:

```bash
docker compose up --build -d
```

Verifique os serviços:

```bash
docker compose ps -a
```

Os componentes OpenVPN devem ficar saudáveis e as aplicações encerram com
código `0` após completar a comunicação.

Para visualizar a troca de mensagens:

```bash
docker compose logs app_client
docker compose logs app_server
```

Para confirmar que o tráfego utiliza o túnel:

```bash
docker exec client_norte ip route get 10.8.0.3
```

Resultado esperado:

```text
10.8.0.3 dev tun0 src 10.8.0.2
```

Para encerrar o ambiente:

```bash
docker compose down
```

---

## Desenvolvimento

Crie um ambiente virtual:

```bash
python -m venv .venv
```

Ative-o e instale as dependências:

```bash
python -m pip install -r requirements-dev.txt
```

Execute os testes:

```bash
python -m pytest -q
```

Execute a análise estática:

```bash
ruff check .
```

Valide a configuração do Compose:

```bash
docker compose config
```

---

## Testes e qualidade

A versão `v1.0.0` foi validada com:

```text
20 testes automatizados aprovados
Ruff aprovado
Docker Compose validado
OpenVPN Server healthy
Cliente Norte healthy
Cliente Sul healthy
Comunicação através de tun0 confirmada
```

O pipeline de CI executa automaticamente em pushes e pull requests destinados
à branch `main`.

Os quality gates incluem:

```text
Ruff
pytest
docker compose config
```

---

## Segurança

O projeto possui uma política de segurança em [`SECURITY.md`](./SECURITY.md).

Não devem ser versionados:

- chaves privadas;
- certificados gerados contendo material sensível;
- credenciais;
- arquivos `.env`;
- outros segredos.

Caso algum material criptográfico sensível seja exposto, ele deve ser
considerado comprometido e substituído.

---

## Release

A primeira versão estável está disponível como:

**[SecureLink v1.0.0](https://github.com/DaniloArantesVieira/Comunicacao-Criptografada/releases/tag/v1.0.0)**

Ela consolida a fundação do repositório, validação criptográfica, quality gates,
hardening de runtime, integração da aplicação à VPN, autenticação OpenVPN e
hardening do protocolo.

---

## Tecnologias

- Python
- `cryptography`
- X25519
- HKDF-SHA256
- ChaCha20-Poly1305
- OpenVPN
- OpenSSL
- Docker
- Docker Compose
- pytest
- Ruff
- GitHub Actions

---

## Licença

Distribuído sob a licença **MIT**.

Consulte [`LICENSE`](./LICENSE) para mais informações.

---

## Autor

**Danilo Arantes Vieira**

GitHub: [@DaniloArantesVieira](https://github.com/DaniloArantesVieira)