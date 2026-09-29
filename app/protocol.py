import socket

SOCKET_TIMEOUT_SECONDS = 10

MAX_AAD_SIZE = 4 * 1024
MAX_CIPHERTEXT_SIZE = 1024 * 1024
MIN_CIPHERTEXT_SIZE = 16


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""

    while len(data) < n:
        chunk = sock.recv(n - len(data))

        if not chunk:
            raise ConnectionError(
                "Conexão encerrada antes de receber todos os bytes"
            )

        data += chunk

    return data


def validate_frame_size(
    name: str,
    size: int,
    *,
    maximum: int,
    minimum: int = 0,
) -> None:
    if size < minimum or size > maximum:
        raise ValueError(
            f"{name} fora dos limites permitidos: {size} bytes "
            f"(mínimo={minimum}, máximo={maximum})"
        )


def recv_frame_length(
    sock: socket.socket,
    length_size: int,
    *,
    name: str,
    maximum: int,
    minimum: int = 0,
) -> int:
    size = int.from_bytes(
        recv_exact(sock, length_size),
        "big",
    )

    validate_frame_size(
        name,
        size,
        minimum=minimum,
        maximum=maximum,
    )

    return size