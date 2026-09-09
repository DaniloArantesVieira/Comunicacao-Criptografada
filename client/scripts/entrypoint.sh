#!/bin/bash
set -e

if [ -z "$CLIENT_NAME" ]; then
  echo "[CLIENT] Variável CLIENT_NAME não definida."
  exit 1
fi

CERT_DIR="/certs/${CLIENT_NAME}"

echo "[CLIENT ${CLIENT_NAME}] Iniciando..."
ls -R "${CERT_DIR}" || true

cat > /tmp/client-runtime.conf <<EOF
client
dev tun
proto udp
remote server 1194

nobind
persist-key
persist-tun

ca ${CERT_DIR}/ca.cert.pem
cert ${CERT_DIR}/${CLIENT_NAME}.cert.pem
key ${CERT_DIR}/${CLIENT_NAME}.key.pem

tls-client
tls-version-min 1.3
tls-groups X25519:secp256r1

remote-cert-tls server
verify-x509-name server name

data-ciphers CHACHA20-POLY1305
data-ciphers-fallback CHACHA20-POLY1305
cipher CHACHA20-POLY1305

verb 4
auth-nocache
EOF

openvpn --config /tmp/client-runtime.conf
