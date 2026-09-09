from app.crypto.chacha20 import decrypt_message, encrypt_message
from app.crypto.ecdh import (
    compute_shared_secret,
    generate_key_pair,
    load_public_key,
    serialize_public_key,
)
from app.crypto.kdf import derive_key


def test_x25519_shared_secret_matches_between_peers():
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    alice_secret = compute_shared_secret(alice_private, bob_public)
    bob_secret = compute_shared_secret(bob_private, alice_public)

    assert alice_secret == bob_secret
    assert len(alice_secret) == 32


def test_x25519_public_key_serialization_round_trip():
    _, public_key = generate_key_pair()

    serialized = serialize_public_key(public_key)
    restored = load_public_key(serialized)

    assert len(serialized) == 32
    assert serialize_public_key(restored) == serialized


def test_hkdf_derives_32_byte_key_deterministically():
    shared_secret = b"a" * 32

    key_a = derive_key(
        shared_secret,
        salt=b"securelink-salt",
        info=b"msg-channel",
    )
    key_b = derive_key(
        shared_secret,
        salt=b"securelink-salt",
        info=b"msg-channel",
    )

    assert key_a == key_b
    assert len(key_a) == 32


def test_hkdf_context_changes_derived_key():
    shared_secret = b"a" * 32

    key_a = derive_key(
        shared_secret,
        salt=b"securelink-salt",
        info=b"channel-a",
    )
    key_b = derive_key(
        shared_secret,
        salt=b"securelink-salt",
        info=b"channel-b",
    )

    assert key_a != key_b


def test_chacha20_poly1305_encrypts_and_decrypts_message():
    key = b"k" * 32
    plaintext = b"mensagem confidencial"
    aad = b"origem=norte;destino=sul"

    nonce, ciphertext = encrypt_message(plaintext, key, aad)
    decrypted = decrypt_message(nonce, ciphertext, key, aad)

    assert len(nonce) == 12
    assert decrypted == plaintext
    assert ciphertext != plaintext


def test_chacha20_poly1305_rejects_modified_ciphertext():
    key = b"k" * 32
    plaintext = b"mensagem confidencial"
    aad = b"origem=norte;destino=sul"

    nonce, ciphertext = encrypt_message(plaintext, key, aad)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    decrypted = decrypt_message(
        nonce,
        bytes(tampered),
        key,
        aad,
    )

    assert decrypted is None


def test_chacha20_poly1305_rejects_modified_aad():
    key = b"k" * 32
    plaintext = b"mensagem confidencial"
    aad = b"origem=norte;destino=sul"

    nonce, ciphertext = encrypt_message(plaintext, key, aad)

    decrypted = decrypt_message(
        nonce,
        ciphertext,
        key,
        b"origem=sul;destino=norte",
    )

    assert decrypted is None


def test_chacha20_poly1305_uses_unique_nonces():
    key = b"k" * 32
    plaintext = b"mesma mensagem"
    aad = b"contexto"

    nonce_a, ciphertext_a = encrypt_message(plaintext, key, aad)
    nonce_b, ciphertext_b = encrypt_message(plaintext, key, aad)

    assert nonce_a != nonce_b
    assert ciphertext_a != ciphertext_b


def test_x25519_independent_sessions_produce_different_secrets():
    alice_private_a, _ = generate_key_pair()
    _, bob_public_a = generate_key_pair()

    alice_private_b, _ = generate_key_pair()
    _, bob_public_b = generate_key_pair()

    secret_a = compute_shared_secret(alice_private_a, bob_public_a)
    secret_b = compute_shared_secret(alice_private_b, bob_public_b)

    assert secret_a != secret_b
