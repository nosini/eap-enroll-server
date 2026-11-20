#!/bin/bash
# Throwaway OpenBao dev server with a PKI like production's, for testing
# eap-enroll. See README.md.
set -euo pipefail
D=$PWD
DOCS=${DOCS:-$D/docs-openbao.md}
export PATH=$D/bin:$PATH
export BAO_ADDR=https://127.0.0.1:8200 BAO_CACERT=$D/baotls/vault-ca.pem BAO_TOKEN=root

pkill -f "[b]ao server -dev" || true
while pgrep -f "[b]ao server -dev" >/dev/null; do sleep 0.5; done
rm -rf baotls pki state && mkdir -p baotls pki state
setsid nohup bao server -dev -dev-tls -dev-tls-cert-dir="$D/baotls" -dev-root-token-id=root \
  -dev-listen-address=127.0.0.1:8200 >state/bao.log 2>&1 &
for _ in $(seq 60); do bao status >/dev/null 2>&1 && break; sleep 0.5; done
bao status >/dev/null

# Root, like the production root CA.
bao secrets enable -path=pki -max-lease-ttl=87600h pki >/dev/null
bao write -field=certificate pki/root/generate/internal common_name="Test Root" \
  key_type=ec key_bits=384 ttl=87600h >pki/root.pem
echo >>pki/root.pem

intermediate() { # mount name issuer_name
  bao secrets enable -path="$1" -max-lease-ttl=43800h pki >/dev/null
  bao write -field=csr "$1/intermediate/generate/internal" common_name="$2" key_type=ec key_bits=384 >"pki/$1.csr"
  bao write -field=certificate pki/root/sign-intermediate csr=@"pki/$1.csr" format=pem ttl=43800h \
    use_csr_values=false common_name="$2" >"pki/$1.pem"
  echo >>"pki/$1.pem"
  bao write "$1/intermediate/set-signed" certificate=@"pki/$1.pem" >/dev/null
  bao patch "$1/issuer/default" issuer_name="$3" >/dev/null
  bao write "$1/config/crl" auto_rebuild=true expiry=72h >/dev/null
}
intermediate pki-radius "Test EAP CA" eap
intermediate pki-enroll "Test Enrollment CA" enroll

# eap-client exactly as issue-eap-client-cert writes it.
bao write pki-radius/roles/eap-client - <<'EOF' >/dev/null
{"issuer_ref": "eap", "key_type": "ec", "key_bits": 384, "ttl": "17520h", "max_ttl": "17520h",
 "allowed_domains": ["alice", "carol"], "allow_bare_domains": true, "allow_subdomains": false,
 "allow_glob_domains": false, "allow_any_name": false, "enforce_hostnames": false,
 "allow_localhost": false, "allow_wildcard_certificates": false, "allow_ip_sans": false,
 "use_csr_common_name": false, "use_csr_sans": false, "require_cn": true,
 "server_flag": false, "client_flag": true, "code_signing_flag": false,
 "email_protection_flag": false, "no_store": false}
EOF

# device role as in docs/openbao.md.
python3 - "$DOCS" <<'EOF' >pki/device-role.json
import re, sys
text = open(sys.argv[1]).read()
print(re.search(r"roles/device - <<'EOF'\n(.*?)\nEOF", text, re.S).group(1))
EOF
bao write pki-enroll/roles/device - <pki/device-role.json >/dev/null

# Server TLS certificate for the service, from the same root.
bao write pki/roles/tls allowed_domains=enroll.test allow_bare_domains=true \
  allow_ip_sans=true key_type=ec key_bits=256 ttl=720h server_flag=true client_flag=false >/dev/null
bao write -format=json pki/issue/tls common_name=enroll.test ip_sans=127.0.0.1 >pki/tls.json
python3 - <<'EOF'
import json
d = json.load(open('pki/tls.json'))['data']
open('pki/tls-key.pem', 'w').write(d['private_key'].strip() + '\n')
open('pki/tls-chain.pem', 'w').write(d['certificate'].strip() + '\n' + open('pki/root.pem').read())
EOF
cat pki/pki-radius.pem pki/root.pem >pki/wifi-cacerts.pem
cat pki/pki-enroll.pem pki/root.pem >pki/device-cacerts.pem

# Users.
bao secrets enable -path=kv kv-v2 >/dev/null
bao kv put kv/apps/freeradius/user-groups alice=staff carol=guests Bob=disabled >/dev/null

# AppRole with the policy from docs/openbao.md.
bao auth enable approle >/dev/null
python3 - "$DOCS" <<'EOF' >pki/policy.hcl
import re, sys
text = open(sys.argv[1]).read()
print(re.search(r"```hcl\n(.*?)```", text, re.S).group(1))
EOF
bao policy write eap-enroll pki/policy.hcl >/dev/null
bao write auth/approle/role/eap-enroll token_policies=eap-enroll token_ttl=20m token_max_ttl=1h \
  secret_id_bound_cidrs=127.0.0.1/32 token_bound_cidrs=127.0.0.1/32 >/dev/null
bao read -field=role_id auth/approle/role/eap-enroll/role-id >state/role-id
bao write -f -field=secret_id auth/approle/role/eap-enroll/secret-id >state/secret-id
# A second role bound elsewhere, to check that the CIDR binding works.
bao write auth/approle/role/elsewhere token_policies=eap-enroll secret_id_bound_cidrs=192.0.2.1/32 >/dev/null
bao read -field=role_id auth/approle/role/elsewhere/role-id >state/elsewhere-role-id
bao write -f -field=secret_id auth/approle/role/elsewhere/secret-id >state/elsewhere-secret-id

cat >state/config.json <<EOF
{
  "listen": "127.0.0.1:8443",
  "public_url": "https://enroll.test:8443",
  "tls_cert_file": "$D/pki/tls-chain.pem",
  "tls_key_file": "$D/pki/tls-key.pem",
  "setup_ca_file": "$D/pki/root.pem",
  "device_ca_file": "$D/pki/pki-enroll.pem",
  "wifi_cacerts_file": "$D/pki/wifi-cacerts.pem",
  "device_cacerts_file": "$D/pki/device-cacerts.pem",
  "database": "$D/state/enroll.db",
  "wifi_ttl": "2160h",
  "device_ttl": "8760h",
  "openbao": {
    "address": "https://127.0.0.1:8200",
    "ca_file": "$D/baotls/vault-ca.pem",
    "role_id_file": "$D/state/role-id",
    "secret_id_file": "$D/state/secret-id"
  }
}
EOF
echo "setup done"
