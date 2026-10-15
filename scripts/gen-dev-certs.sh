#!/usr/bin/env sh
# Owner: M10. Generates a self-signed certificate for https://localhost (development only).
# Output goes to infra/nginx/certs/, which is git-ignored. Never commit the private key.
set -eu

CERT_DIR="$(dirname "$0")/../infra/nginx/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
  -keyout "$CERT_DIR/dev.key" \
  -out "$CERT_DIR/dev.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/dev.key"
echo "Wrote $CERT_DIR/dev.crt and dev.key (self-signed, development only)."
