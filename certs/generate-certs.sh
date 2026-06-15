#!/bin/bash

# mTLS 用の証明書生成スクリプト
# このスクリプトは、nl_bridge (クライアント) と kernel-bridge (サーバー) 間の
# 相互 TLS 認証用の証明書を生成します。

set -e

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_KEY="$CERT_DIR/ca-key.pem"
CA_CERT="$CERT_DIR/ca-cert.pem"
SERVER_KEY="$CERT_DIR/server-key.pem"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CERT="$CERT_DIR/server-cert.pem"
CLIENT_KEY="$CERT_DIR/client-key.pem"
CLIENT_CSR="$CERT_DIR/client.csr"
CLIENT_CERT="$CERT_DIR/client-cert.pem"

echo "[*] Generating mTLS certificates..."

# 1. CA (認証局) の秘密鍵を生成
echo "[*] Generating CA private key..."
openssl genrsa -out "$CA_KEY" 2048

# 2. CA の証明書を生成
echo "[*] Generating CA certificate..."
openssl req -new -x509 -days 3650 -key "$CA_KEY" -out "$CA_CERT" \
  -subj "/C=JP/ST=Tokyo/L=Tokyo/O=NullSphere/CN=NullSphere-CA"

# 3. サーバー (kernel-bridge) の秘密鍵を生成
echo "[*] Generating server private key..."
openssl genrsa -out "$SERVER_KEY" 2048

# 4. サーバーの証明書署名要求 (CSR) を生成
echo "[*] Generating server CSR..."
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "/C=JP/ST=Tokyo/L=Tokyo/O=NullSphere/CN=kernel-bridge"

# 5. CA でサーバー証明書に署名
echo "[*] Signing server certificate..."
openssl x509 -req -days 365 -in "$SERVER_CSR" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -sha256

# 6. クライアント (nl_bridge) の秘密鍵を生成
echo "[*] Generating client private key..."
openssl genrsa -out "$CLIENT_KEY" 2048

# 7. クライアントの CSR を生成
echo "[*] Generating client CSR..."
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" \
  -subj "/C=JP/ST=Tokyo/L=Tokyo/O=NullSphere/CN=nl-bridge"

# 8. CA でクライアント証明書に署名
echo "[*] Signing client certificate..."
openssl x509 -req -days 365 -in "$CLIENT_CSR" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CERT" -sha256

# 9. 一時ファイルをクリーンアップ
rm -f "$SERVER_CSR" "$CLIENT_CSR" "$CERT_DIR/ca-cert.srl"

echo "[✓] Certificate generation completed!"
echo ""
echo "Generated certificates:"
echo "  CA Certificate:     $CA_CERT"
echo "  CA Private Key:     $CA_KEY"
echo "  Server Certificate: $SERVER_CERT"
echo "  Server Private Key: $SERVER_KEY"
echo "  Client Certificate: $CLIENT_CERT"
echo "  Client Private Key: $CLIENT_KEY"
echo ""
echo "[!] Keep these certificates secure and do not commit them to version control."
