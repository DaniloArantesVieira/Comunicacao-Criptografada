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

HOST = "0.0.0.0"
PORT = 5000


def recv_exact(conn, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Conexão encerrada antes de receber todos os bytes")
        data += chunk
    return data


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
            print(f"[APP SERVER] Conexão recebida de {addr}")

            peer_pub = recv_exact(conn, 32)
            print(f"[APP SERVER] Chave pública recebida: {peer_pub.hex()}")

            conn.sendall(server_public_bytes)
            print(f"[APP SERVER] Chave pública enviada: {server_public_bytes.hex()}")

            peer_public_key = load_public_key(peer_pub)
            shared_secret = compute_shared_secret(server_private, peer_public_key)
            print(f"[APP SERVER] Segredo compartilhado: {shared_secret.hex()}")

            key = derive_key(shared_secret, salt=b"securelink-salt", info=b"msg-channel")
            print(f"[APP SERVER] Chave derivada HKDF: {key.hex()}")

            aad_len = int.from_bytes(recv_exact(conn, 2), "big")
            aad = recv_exact(conn, aad_len)
            nonce = recv_exact(conn, 12)
            ct_len = int.from_bytes(recv_exact(conn, 4), "big")
            ciphertext = recv_exact(conn, ct_len)

            print(f"[APP SERVER] AAD: {aad.decode(errors='ignore')}")
            print(f"[APP SERVER] Nonce: {nonce.hex()}")
            print(f"[APP SERVER] Ciphertext+Tag: {ciphertext.hex()}")
            print(f"[APP SERVER] Tag Poly1305: {ciphertext[-16:].hex()}")

            plaintext = decrypt_message(nonce, ciphertext, key, aad)
            if plaintext is None:
                print("[APP SERVER] Falha de autenticação: InvalidTag")
            else:
                print(f"[APP SERVER] Mensagem decifrada: {plaintext.decode()}")

            time.sleep(2)


if __name__ == "__main__":
    main()
