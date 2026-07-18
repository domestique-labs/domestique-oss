#!/bin/bash
# Generate a self-signed CA certificate for TLS interception.
# In production, use your PKI (Active Directory Certificate Services, etc.)

set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_KEY="${CERT_DIR}/ca.key"
CA_CERT="${CERT_DIR}/ca.crt"
CA_SUBJECT="/C=US/ST=CA/O=LLM Firewall/CN=LLM Firewall Root CA"
VALIDITY_DAYS=3650  # 10 years for root CA

echo "=== Generating LLM Firewall Root CA ==="

# Generate CA private key
openssl genrsa -out "${CA_KEY}" 4096
echo "✓ Generated CA private key: ${CA_KEY}"

# Generate CA certificate
openssl req -x509 -new -nodes \
    -key "${CA_KEY}" \
    -sha256 \
    -days ${VALIDITY_DAYS} \
    -out "${CA_CERT}" \
    -subj "${CA_SUBJECT}"
echo "✓ Generated CA certificate: ${CA_CERT}"

# Generate a server certificate for the proxy (signed by our CA)
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CERT="${CERT_DIR}/server.crt"

# Domains to intercept - the proxy will present these certs
DOMAINS="api.openai.com,api.anthropic.com,generativelanguage.googleapis.com,api.cohere.ai,api.mistral.ai,api.together.xyz"

# Create SAN config
SAN_CONF="${CERT_DIR}/san.cnf"
cat > "${SAN_CONF}" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = CA
O = LLM Firewall
CN = LLM Firewall Proxy

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
EOF

# Add all intercepted domains to SAN
IFS=',' read -ra DOMAIN_ARRAY <<< "${DOMAINS}"
idx=1
for domain in "${DOMAIN_ARRAY[@]}"; do
    echo "DNS.${idx} = ${domain}" >> "${SAN_CONF}"
    echo "DNS.$((idx+1)) = *.${domain}" >> "${SAN_CONF}"
    idx=$((idx+2))
done

# Generate server key and CSR
openssl genrsa -out "${SERVER_KEY}" 2048
openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -config "${SAN_CONF}"

# Sign with CA
openssl x509 -req \
    -in "${SERVER_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${SERVER_CERT}" \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile "${SAN_CONF}"

echo "✓ Generated server certificate: ${SERVER_CERT}"
echo ""
echo "=== Next Steps ==="
echo "1. Deploy ${CA_CERT} to all devices:"
echo "   - Windows: GPO → Computer Config → Policies → Windows Settings → Security → Public Key → Trusted Root CAs"
echo "   - macOS: MDM profile or: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${CA_CERT}"
echo "   - Linux: cp ${CA_CERT} /usr/local/share/ca-certificates/ && update-ca-certificates"
echo ""
echo "2. Configure DNS to point LLM domains to the firewall proxy IP"
echo "3. Place ${SERVER_KEY} and ${SERVER_CERT} in the proxy's TLS config"
