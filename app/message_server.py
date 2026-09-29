import socket
import time

from crypto.chacha20 import decrypt_message
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
    recv_frame_length,
)

HOST = "0.0.0.0"
PORT = 5000


def main():
    print("[APP SERVER] Iniciando receptor...")

    server_private, server_public = generate_key_pair()
    server_public_bytes = serialize_public_key(server_public)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)

        print(f"[APP SERVER] Escutando em {HOST}:{PORT}...")

        conn, addr = sock.accept()

        with conn:
            conn.settimeout(SOCKET_TIMEOUT_SECONDS)

            print(f"[APP SERVER] Conexão recebida de {addr}")

            peer_pub = recv_exact(conn, 32)
            print(f"[APP SERVER] Chave pública recebida: {peer_pub.hex()}")

            conn.sendall(server_public_bytes)
            print(f"[APP SERVER] Chave pública enviada: {server_public_bytes.hex()}")

            peer_public_key = load_public_key(peer_pub)
            shared_secret = compute_shared_secret(
                server_private,
                peer_public_key,
            )

            key = derive_key(
                shared_secret,
                salt=b"securelink-salt",
                info=b"msg-channel",
            )

            aad_len = recv_frame_length(
                conn,
                2,
                name="AAD",
                maximum=MAX_AAD_SIZE,
            )
            aad = recv_exact(conn, aad_len)

            nonce = recv_exact(conn, 12)

            ct_len = recv_frame_length(
                conn,
                4,
                name="ciphertext",
                minimum=MIN_CIPHERTEXT_SIZE,
                maximum=MAX_CIPHERTEXT_SIZE,
            )
            ciphertext = recv_exact(conn, ct_len)

            print(f"[APP SERVER] AAD: {aad.decode(errors='ignore')}")
            print(f"[APP SERVER] Nonce: {nonce.hex()}")
            print(f"[APP SERVER] Ciphertext+Tag: {ciphertext.hex()}")
            print(f"[APP SERVER] Tag Poly1305: {ciphertext[-16:].hex()}")

            plaintext = decrypt_message(
                nonce,
                ciphertext,
                key,
                aad,
            )

            if plaintext is None:
                print("[APP SERVER] Falha de autenticação: InvalidTag")
            else:
                print(
                    f"[APP SERVER] Mensagem decifrada: "
                    f"{plaintext.decode()}"
                )

            time.sleep(2)


if __name__ == "__main__":
    main()