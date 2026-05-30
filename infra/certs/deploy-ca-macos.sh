#!/bin/bash
# Deploy LLM Firewall CA certificate to macOS via MDM or locally.

set -euo pipefail

CERT_PATH="${1:-$(dirname "$0")/ca.crt}"

if [ ! -f "${CERT_PATH}" ]; then
    echo "ERROR: Certificate not found: ${CERT_PATH}"
    echo "Usage: $0 [path-to-ca.crt]"
    exit 1
fi

echo "=== Deploying LLM Firewall CA Certificate (macOS) ==="
echo "Certificate: ${CERT_PATH}"

# Verify cert
openssl x509 -in "${CERT_PATH}" -text -noout | grep -E "Subject:|Not After"

echo ""
echo "Installing to System Keychain (requires sudo)..."
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "${CERT_PATH}"

echo "✓ Certificate installed and trusted"
echo ""
echo "=== For MDM Deployment (Jamf, Intune, Kandji, etc.) ==="
echo "1. Upload ${CERT_PATH} as a Certificate payload"
echo "2. Set trust: 'Always Trust' for SSL"
echo "3. Scope to all managed devices"
echo ""
echo "=== Verify ==="
echo "Run: security find-certificate -c 'LLM Firewall' /Library/Keychains/System.keychain"
