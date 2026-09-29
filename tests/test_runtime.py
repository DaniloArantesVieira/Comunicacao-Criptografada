import importlib
import inspect
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

APP_DIR = Path(__file__).resolve().parents[1] / "app"

if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

message_client = importlib.import_module("message_client")
message_server = importlib.import_module("message_server")
protocol = importlib.import_module("protocol")


def test_client_recv_exact_handles_partial_reads():
    sock = MagicMock()
    sock.recv.side_effect = [
        b"ab",
        b"cd",
        b"ef",
    ]

    result = message_client.recv_exact(sock, 6)

    assert result == b"abcdef"


def test_client_recv_exact_rejects_early_connection_close():
    sock = MagicMock()
    sock.recv.side_effect = [
        b"ab",
        b"",
    ]

    with pytest.raises(
        ConnectionError,
        match="Conexão encerrada antes de receber todos os bytes",
    ):
        message_client.recv_exact(sock, 4)


def test_server_recv_exact_handles_partial_reads():
    conn = MagicMock()
    conn.recv.side_effect = [
        b"12",
        b"34",
        b"56",
    ]

    result = message_server.recv_exact(conn, 6)

    assert result == b"123456"


def test_connect_with_retry_succeeds_after_temporary_failures(monkeypatch):
    first_socket = MagicMock()
    second_socket = MagicMock()
    third_socket = MagicMock()

    first_socket.connect.side_effect = OSError("indisponível")
    second_socket.connect.side_effect = OSError("indisponível")

    socket_factory = MagicMock(
        side_effect=[
            first_socket,
            second_socket,
            third_socket,
        ]
    )

    sleep_mock = MagicMock()

    monkeypatch.setattr(message_client.socket, "socket", socket_factory)
    monkeypatch.setattr(message_client.time, "sleep", sleep_mock)
    monkeypatch.setattr(message_client, "MAX_CONNECTION_ATTEMPTS", 3)
    monkeypatch.setattr(message_client, "RETRY_DELAY_SECONDS", 1)

    result = message_client.connect_with_retry()

    assert result is third_socket

    for sock in (
        first_socket,
        second_socket,
        third_socket,
    ):
        sock.settimeout.assert_called_once_with(
            message_client.SOCKET_TIMEOUT_SECONDS
        )

    first_socket.close.assert_called_once()
    second_socket.close.assert_called_once()
    third_socket.close.assert_not_called()

    assert sleep_mock.call_count == 2


def test_connect_with_retry_fails_after_maximum_attempts(monkeypatch):
    sockets = [
        MagicMock(),
        MagicMock(),
        MagicMock(),
    ]

    for sock in sockets:
        sock.connect.side_effect = OSError("indisponível")

    socket_factory = MagicMock(side_effect=sockets)
    sleep_mock = MagicMock()

    monkeypatch.setattr(message_client.socket, "socket", socket_factory)
    monkeypatch.setattr(message_client.time, "sleep", sleep_mock)
    monkeypatch.setattr(message_client, "MAX_CONNECTION_ATTEMPTS", 3)
    monkeypatch.setattr(message_client, "RETRY_DELAY_SECONDS", 1)

    with pytest.raises(
        ConnectionError,
        match="após 3 tentativas",
    ):
        message_client.connect_with_retry()

    for sock in sockets:
        sock.close.assert_called_once()

    assert sleep_mock.call_count == 2


@pytest.mark.parametrize(
    "module",
    [
        message_client,
        message_server,
    ],
)
def test_runtime_does_not_log_sensitive_key_material(module):
    source = inspect.getsource(module)

    assert "Segredo compartilhado" not in source
    assert "Chave derivada HKDF" not in source
    assert "shared_secret.hex()" not in source
    assert "key.hex()" not in source


def test_protocol_rejects_oversized_aad():
    with pytest.raises(
        ValueError,
        match="AAD fora dos limites permitidos",
    ):
        protocol.validate_frame_size(
            "AAD",
            protocol.MAX_AAD_SIZE + 1,
            maximum=protocol.MAX_AAD_SIZE,
        )


def test_protocol_rejects_oversized_ciphertext():
    with pytest.raises(
        ValueError,
        match="ciphertext fora dos limites permitidos",
    ):
        protocol.validate_frame_size(
            "ciphertext",
            protocol.MAX_CIPHERTEXT_SIZE + 1,
            minimum=protocol.MIN_CIPHERTEXT_SIZE,
            maximum=protocol.MAX_CIPHERTEXT_SIZE,
        )


def test_protocol_rejects_ciphertext_shorter_than_tag():
    with pytest.raises(
        ValueError,
        match="ciphertext fora dos limites permitidos",
    ):
        protocol.validate_frame_size(
            "ciphertext",
            protocol.MIN_CIPHERTEXT_SIZE - 1,
            minimum=protocol.MIN_CIPHERTEXT_SIZE,
            maximum=protocol.MAX_CIPHERTEXT_SIZE,
        )


def test_recv_frame_length_rejects_oversized_frame_before_payload():
    sock = MagicMock()
    oversized = protocol.MAX_CIPHERTEXT_SIZE + 1
    sock.recv.return_value = oversized.to_bytes(4, "big")

    with pytest.raises(
        ValueError,
        match="ciphertext fora dos limites permitidos",
    ):
        protocol.recv_frame_length(
            sock,
            4,
            name="ciphertext",
            minimum=protocol.MIN_CIPHERTEXT_SIZE,
            maximum=protocol.MAX_CIPHERTEXT_SIZE,
        )

    sock.recv.assert_called_once_with(4)