# Domestique — Deployment Guide

## Overview

This guide covers deploying the Domestique in a multi-machine environment so that **all LLM API traffic is transparently intercepted** without requiring per-application configuration changes.

## Architecture Summary

```
[Users] → [DNS Override] → [TLS Termination (nginx)] → [Firewall Proxy] → [External LLMs]
```

The system works by:
1. Internal DNS resolves LLM provider domains to the firewall proxy IP
2. CA certificate enables TLS interception without errors
3. Firewall inspects, filters, and forwards (or blocks) requests
4. Users and applications require zero configuration changes

---

## Prerequisites

- Internal DNS control (Active Directory DNS, CoreDNS, or similar)
- Your PKI or ability to deploy a custom CA certificate
- Container runtime (Docker/Kubernetes) for the proxy
- Network access: proxy must reach external LLM APIs on port 443
- MDM solution (Intune, Jamf, SCCM) for certificate deployment

---

## Step 1: Generate Certificates

```bash
cd infra/certs
chmod +x generate-ca.sh
./generate-ca.sh
```

This creates:
- `ca.key` / `ca.crt` — Root CA (deploy to all clients)
- `server.key` / `server.crt` — Server cert with SANs for all intercepted domains

**For production**: Use your PKI to issue the server certificate instead.

---

## Step 2: Deploy CA Certificate to Clients

### Windows (via GPO)
```powershell
.\infra\certs\deploy-ca-windows.ps1 -CertificatePath .\infra\certs\ca.crt
```
Or manually: GPO → Computer Config → Policies → Windows Settings → Security → Public Key → Trusted Root CAs

### macOS (via MDM)
```bash
./infra/certs/deploy-ca-macos.sh ./infra/certs/ca.crt
```
Or via Jamf/Intune: Upload ca.crt as a Certificate profile, set to Always Trust for SSL.

### Linux
```bash
sudo cp infra/certs/ca.crt /usr/local/share/ca-certificates/domestique-ca.crt
sudo update-ca-certificates
```

---

## Step 3: Configure DNS

### Option A: Active Directory DNS
Add Host (A) records overriding LLM domains:
```
api.openai.com            → 10.0.1.100  (firewall proxy IP)
api.anthropic.com         → 10.0.1.100
generativelanguage.googleapis.com → 10.0.1.100
api.cohere.ai             → 10.0.1.100
api.mistral.ai            → 10.0.1.100
api.together.xyz          → 10.0.1.100
```

### Option B: CoreDNS
Deploy the provided CoreDNS config:
```bash
# Edit infra/dns/llm-hosts with your firewall proxy IP
# Deploy CoreDNS with the config
kubectl apply -f infra/dns/coredns-config.yaml
```

### Option C: PAC File (supplementary)
Deploy `infra/pac/proxy.pac` via:
- GPO: User Config → Windows Settings → Internet Explorer Maintenance → Connection → Automatic Configuration
- MDM: Set system proxy auto-config URL to `http://pac-server.internal/proxy.pac`

---

## Step 4: Deploy the Firewall Proxy

### Docker Compose (small deployments)
```bash
cp .env.example .env
# Edit .env with your LLM provider API keys

docker compose up -d
```

### Kubernetes (production)
```bash
# Using Helm
helm install domestique ./infra/kubernetes/helm-chart \
    --set proxy.replicas=3 \
    --set openaiApiKey=$OPENAI_API_KEY \
    --set anthropicApiKey=$ANTHROPIC_API_KEY

# Or using Kustomize
kubectl apply -k infra/kubernetes/kustomize/
```

---

## Step 5: Block Direct Access

**Critical**: Block direct access to LLM provider IPs at the network firewall. Otherwise users could bypass the proxy by hardcoding IPs or using DoH.

Firewall rules (outbound):
```
DENY  tcp/443  →  api.openai.com (resolved IPs)
DENY  tcp/443  →  api.anthropic.com (resolved IPs)
# ... etc.
ALLOW tcp/443  FROM firewall-proxy-ip → ANY  (proxy can reach upstream)
```

Also consider:
- Block DNS-over-HTTPS (DoH) providers
- Disable DoH in browsers via GPO/MDM

---

## Step 6: Configure Policies

Edit `proxy/policy/default_policy.yaml`:

```yaml
rules:
  - name: block-secrets
    detector: secret_scanner
    types: [aws_access_key, private_key, connection_string]
    action: block

  - name: redact-pii
    detector: pii_detector
    types: [us_ssn, credit_card, email_address]
    action: redact

  - name: block-internal-code
    detector: code_classifier
    action: block
    severity_min: 0.9
```

---

## Step 7: Verify

### Test from a client machine:
```bash
# Should resolve to your firewall proxy IP
nslookup api.openai.com

# Should succeed (proxied through firewall)
curl https://api.openai.com/v1/models -H "Authorization: Bearer test"

# Should be blocked (contains a secret)
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"My key is AKIAIOSFODNN7EXAMPLE"}]}'
```

### Check audit logs:
```bash
tail -f logs/audit.jsonl | jq .
```

---

## Monitoring

- **Health**: `GET http://firewall-proxy:8000/health`
- **Metrics**: Prometheus endpoint at `:9090/metrics`
- **Audit logs**: JSONL format in `logs/audit.jsonl`, forward to SIEM
- **Dashboard**: Grafana dashboards for request volume, block rate, latency

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Certificate errors in apps | Verify CA is in trusted root store; check app doesn't use cert pinning |
| DNS not resolving to proxy | Verify DNS records; check client isn't using DoH |
| High latency | Scale proxy replicas; check network path; review detection pipeline |
| False positives | Adjust `severity_min` thresholds; add allowlist patterns |
| App bypasses proxy | Implement network firewall rules (Step 5); deploy local agent |

---

## Security Hardening Checklist

- [ ] CA certificate deployed to all devices
- [ ] Direct LLM API access blocked at network firewall
- [ ] DNS-over-HTTPS disabled on managed devices
- [ ] Proxy API keys stored in secrets manager (Vault, etc.)
- [ ] Audit logs forwarded to SIEM
- [ ] Fail-closed mode enabled (`DOMESTIQUE_FAIL_MODE=closed`)
- [ ] Regular policy reviews scheduled
- [ ] Proxy containers scanned for vulnerabilities
- [ ] Access to proxy admin API restricted to security team
