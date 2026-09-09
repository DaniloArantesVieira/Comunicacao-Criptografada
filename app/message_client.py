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

HOST = "app_server"
PORT = 5000


def main():
    time.sleep(3)
    print("[APP CLIENT] Iniciando transmissor...")

    client_private, client_public = generate_key_pair()
    client_public_bytes = serialize_public_key(client_public)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        sock.sendall(client_public_bytes)
        print(f"[APP CLIENT] Chave pública enviada: {client_public_bytes.hex()}")

        peer_pub = sock.recv(32)
        print(f"[APP CLIENT] Chave pública recebida: {peer_pub.hex()}")

        peer_public_key = load_public_key(peer_pub)
        shared_secret = compute_shared_secret(client_private, peer_public_key)
        print(f"[APP CLIENT] Segredo compartilhado: {shared_secret.hex()}")

        key = derive_key(shared_secret, salt=b"securelink-salt", info=b"msg-channel")
        print(f"[APP CLIENT] Chave derivada HKDF: {key.hex()}")

        aad = b"remetente=filial_norte;destinatario=filial_sul;timestamp=2026-03-31T20:00:00Z"
        plaintext = b"Transferencia aprovada no valor de R$ 18.500,00"

        nonce, ciphertext = encrypt_message(plaintext, key, aad)

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
