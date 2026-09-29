import os
import socket
import time

from crypto.chacha20 import encrypt_message
from crypto.ecdh import (
    compute_shared_secret,
    generate_key_pair,
    load_public_key,
    serialize_public_key,
)
from crypto.kdf import derive_key
from protocol import (
    MAX_AAD_SIZE,
    MAX_CIPHERTEXT_SIZE,
    MIN_CIPHERTEXT_SIZE,
    SOCKET_TIMEOUT_SECONDS,
    recv_exact,
    validate_frame_size,
)

HOST = os.getenv("APP_SERVER_HOST", "app_server")
PORT = 5000

MAX_CONNECTION_ATTEMPTS = 10
RETRY_DELAY_SECONDS = 1


def connect_with_retry() -> socket.socket:
    for attempt in range(1, MAX_CONNECTION_ATTEMPTS + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)

        try:
            sock.connect((HOST, PORT))
            return sock

        except OSError as exc:
            sock.close()

            if attempt == MAX_CONNECTION_ATTEMPTS:
                raise ConnectionError(
                    f"Não foi possível conectar a {HOST}:{PORT} "
                    f"após {MAX_CONNECTION_ATTEMPTS} tentativas"
                ) from exc

            print(
                "[APP CLIENT] Servidor indisponível "
                f"(tentativa {attempt}/{MAX_CONNECTION_ATTEMPTS})."
            )

            time.sleep(RETRY_DELAY_SECONDS)

    raise RuntimeError("Estado de conexão inesperado")


def main():
    print("[APP CLIENT] Iniciando transmissor...")

    client_private, client_public = generate_key_pair()
    client_public_bytes = serialize_public_key(client_public)

    with connect_with_retry() as sock:
        sock.sendall(client_public_bytes)
        print(f"[APP CLIENT] Chave pública enviada: {client_public_bytes.hex()}")

        peer_pub = recv_exact(sock, 32)
        print(f"[APP CLIENT] Chave pública recebida: {peer_pub.hex()}")

        peer_public_key = load_public_key(peer_pub)
        shared_secret = compute_shared_secret(client_private, peer_public_key)

        key = derive_key(
            shared_secret,
            salt=b"securelink-salt",
            info=b"msg-channel",
        )

        aad = (
            b"remetente=filial_norte;"
            b"destinatario=filial_sul;"
            b"timestamp=2026-03-31T20:00:00Z"
        )

        validate_frame_size(
            "AAD",
            len(aad),
            maximum=MAX_AAD_SIZE,
        )

        plaintext = b"Transferencia aprovada no valor de R$ 18.500,00"

        nonce, ciphertext = encrypt_message(plaintext, key, aad)

        validate_frame_size(
            "ciphertext",
            len(ciphertext),
            minimum=MIN_CIPHERTEXT_SIZE,
            maximum=MAX_CIPHERTEXT_SIZE,
        )

        print(f"[APP CLIENT] AAD: {aad.decode()}")
        print(f"[APP CLIENT] Nonce: {nonce.hex()}")
        print(f"[APP CLIENT] Ciphertext+Tag: {ciphertext.hex()}")
        print(f"[APP CLIENT] Tag Poly1305: {ciphertext[-16:].hex()}")

        sock.sendall(len(aad).to_bytes(2, "big"))
        sock.sendall(aad)
        sock.sendall(nonce)
        sock.sendall(len(ciphertext).to_bytes(4, "big"))
        sock.sendall(ciphertext)

        print("[APP CLIENT] Mensagem enviada com sucesso.")
        time.sleep(2)


if __name__ == "__main__":
    main()