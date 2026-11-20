#!/bin/bash
# End-to-end test of eap-enroll against the dev OpenBao from setup.sh.
set -uo pipefail
D=$PWD
export PATH=$D/bin:$PATH
export BAO_ADDR=https://127.0.0.1:8200 BAO_CACERT=$D/baotls/vault-ca.pem
CFG=$D/state/config.json
W=$D/work
rm -rf "$W" && mkdir -p "$W"
rm -f state/enroll.db*
fails=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
check() { # description expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected $2, got $3"; fi
}

pkill -f "[e]ap-enroll serve" || true
sleep 0.5
setsid nohup bin/eap-enroll serve -config "$CFG" >state/serve.log 2>&1 &
for _ in $(seq 40); do curl -s --cacert pki/root.pem --resolve enroll.test:8443:127.0.0.1 \
  -o /dev/null https://enroll.test:8443/.well-known/est/wifi/cacerts && break; sleep 0.25; done

URL=https://enroll.test:8443/.well-known/est
est() { # name path [curl args...]; writes $W/name.out (body) and prints status
  local name=$1 path=$2; shift 2
  # A random loopback source address per request, so the per-IP rate
  # limit doesn't interfere (it has its own check below).
  curl -s --interface "127.0.$((RANDOM % 250 + 1)).$((RANDOM % 250 + 1))" \
    --cacert pki/root.pem --resolve enroll.test:8443:127.0.0.1 -o "$W/$name.out" \
    -w '%{http_code}' -H 'Content-Type: application/pkcs10' "$@" "$URL/$path"
}
csr() { # name curve
  openssl ecparam -name "$2" -genkey -noout -out "$W/$1.key" 2>/dev/null
  openssl req -new -key "$W/$1.key" -subj "/CN=mallory/O=Evil" -addext "subjectAltName=DNS:evil.example" \
    -outform DER 2>/dev/null | base64 -w 64 >"$W/$1.csr"
}
certs() { # name -> $W/name.pem (all certificates) and $W/name.leaf.pem
  base64 -d "$W/$1.out" | openssl pkcs7 -inform DER -print_certs 2>/dev/null | sed '/^subject=/d;/^issuer=/d;/^$/d' >"$W/$1.pem"
  openssl x509 -in "$W/$1.pem" -out "$W/$1.leaf.pem"
}
field() { openssl x509 -in "$W/$1.leaf.pem" -noout "${@:2}" 2>/dev/null; }

# cacerts
check "wifi/cacerts" 200 "$(est cacerts wifi/cacerts -X GET)"
base64 -d "$W/cacerts.out" | openssl pkcs7 -inform DER -print_certs -noout | grep -q "Test EAP CA" \
  && ok "wifi/cacerts holds the EAP CA" || bad "wifi/cacerts content"

# Code and setup URI.
URI=$(bin/eap-enroll code -config "$CFG" -user ALICE -label "Pixel test" 2>>state/admin.log)
CODE=$(python3 -c 'import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query)["code"][0])' "$URI")
FP=$(openssl x509 -in pki/root.pem -outform DER | sha256sum | cut -c1-64)
case "$URI" in *"ca=$FP"*) ok "setup URI has the root fingerprint";; *) bad "setup URI $URI";; esac

# Device credential on P-256.
csr dev prime256v1
check "device/simpleenroll" 200 "$(est dev device/simpleenroll -H "Authorization: Bearer $CODE" --data-binary @"$W/dev.csr")"
certs dev
check "device cert CN" "subject=CN=alice" "$(field dev -subject -nameopt RFC2253)"
DEVID=$(field dev -ext subjectAltName | grep -o 'urn:uuid:[0-9a-f-]*' | cut -d: -f3)
[ -n "$DEVID" ] && ok "device URI SAN $DEVID" || bad "no device URI SAN"
field dev -ext extendedKeyUsage | grep -q 'TLS Web Client Authentication' && ! field dev -ext extendedKeyUsage | grep -q Server \
  && ok "device cert client auth only" || bad "device cert EKU"
check "code reuse" 401 "$(est reuse device/simpleenroll -H "Authorization: Bearer $CODE" --data-binary @"$W/dev.csr")"

# Wi-Fi certificate.
csr wifi secp384r1
check "wifi/simpleenroll" 200 "$(est wifi wifi/simpleenroll --cert "$W/dev.pem" --key "$W/dev.key" --data-binary @"$W/wifi.csr")"
certs wifi
check "wifi cert CN" "subject=CN=alice" "$(field wifi -subject -nameopt RFC2253)"
field wifi -ext subjectAltName | grep -q . && bad "wifi cert has SANs: $(field wifi -ext subjectAltName)" || ok "wifi cert has no SANs"
openssl verify -CAfile pki/root.pem -untrusted pki/pki-radius.pem "$W/wifi.leaf.pem" >/dev/null && ok "wifi cert chains to the EAP CA" || bad "wifi chain"
DAYS=$(( ($(date -d "$(field wifi -enddate | cut -d= -f2)" +%s) - $(date +%s)) / 86400 ))
case $DAYS in 59|60) ok "wifi lifetime $DAYS days";; *) bad "wifi lifetime $DAYS days";; esac
check "wifi needs a client cert" 401 "$(est nocert wifi/simpleenroll --data-binary @"$W/wifi.csr")"
csr wifi256 prime256v1
check "wifi P-256 refused" 400 "$(est wifi256 wifi/simpleenroll --cert "$W/dev.pem" --key "$W/dev.key" --data-binary @"$W/wifi256.csr")"
# A Wi-Fi certificate isn't a device credential (same root, other intermediate).
check "wifi cert as client cert" 000 "$(est wificlient wifi/simpleenroll --cert "$W/wifi.pem" --key "$W/wifi.key" --data-binary @"$W/wifi.csr")"

# Device renewal with a P-384 key (role key_bits 0).
csr dev2 secp384r1
check "device/simplereenroll P-384" 200 "$(est dev2 device/simplereenroll --cert "$W/dev.pem" --key "$W/dev.key" --data-binary @"$W/dev2.csr")"
certs dev2
field dev2 -ext subjectAltName | grep -q "urn:uuid:$DEVID" && ok "renewed credential keeps the device ID" || bad "renewed URI"

# Profile, with the new credential; that retires the old one.
check "wifi/profile" 200 "$(est profile wifi/profile -X GET --cert "$W/dev2.pem" --key "$W/dev2.key")"
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); sys.exit(p["ssid"] != "Test Net" or p["server_domain"] != "radius.example.org")' "$W/profile.out" \
  && ok "profile content" || bad "profile $(cat "$W/profile.out")"

# A second Wi-Fi certificate; confirming it revokes the first.
check "second wifi/simpleenroll" 200 "$(est wifi2 wifi/simpleenroll --cert "$W/dev2.pem" --key "$W/dev2.key" --data-binary @"$W/wifi.csr")"
certs wifi2
check "wifi/confirm" 204 "$(est confirm wifi/confirm --cert "$W/dev2.pem" --key "$W/dev2.key" -H 'Content-Type: text/plain' --data-binary "$(field wifi2 -serial | cut -d= -f2)")"
curl -s --cacert baotls/vault-ca.pem https://127.0.0.1:8200/v1/pki-radius/crl/pem >"$W/radius1.crl"
openssl crl -in "$W/radius1.crl" -noout -text | tr -d ' :' | grep -qi "SerialNumber$(field wifi -serial | cut -d= -f2)" \
  && ok "confirmed: first wifi cert on the CRL" || bad "first wifi cert not on CRL after confirm"
openssl crl -in "$W/radius1.crl" -noout -text | tr -d ' :' | grep -qi "SerialNumber$(field wifi2 -serial | cut -d= -f2)" \
  && bad "confirmed cert itself revoked" || ok "confirmed cert not revoked"

# Policy: what the AppRole may and may not do, with its own token.
TOKEN=$(bao write -field=token auth/approle/login role_id=@state/role-id secret_id=@state/secret-id)
openssl req -new -key "$W/wifi.key" -subj /CN=x -out "$W/p.csr" 2>/dev/null
pol() { # path key=value...; true/false become JSON booleans, @file reads a file
  local path=$1; shift
  local body
  body=$(python3 -c '
import json, sys
d = {}
for a in sys.argv[1:]:
    k, v = a.split("=", 1)
    d[k] = open(v[1:]).read() if v.startswith("@") else v[4:] if v.startswith("str:") else json.loads(v[5:]) if v.startswith("json:") else {"true": True, "false": False}.get(v, v)
print(json.dumps(d))' "$@")
  local code
  code=$(curl -s -o "$W/pol.out" -w "%{http_code}" --cacert "$BAO_CACERT" -H "X-Vault-Token: $TOKEN" \
    -X POST --data "$body" "$BAO_ADDR/v1/$path")
  case $code in 2*) echo allowed;; 403) echo denied;; *) echo "http-$code";; esac
}
check "policy: allowed sign" allowed "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=alice exclude_cn_from_sans=true ttl=1440h)"
check "policy: other ttl" denied "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=alice exclude_cn_from_sans=true ttl=17520h)"
check "policy: no ttl" denied "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=alice exclude_cn_from_sans=true)"
check "policy: exclude_cn_from_sans=false" denied "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=alice exclude_cn_from_sans=false ttl=1440h)"
check "policy: alt_names" denied "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=alice alt_names=x ttl=1440h exclude_cn_from_sans=true)"
check "policy: no common_name" denied "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" ttl=1440h exclude_cn_from_sans=true)"
check "policy: issue (server keygen)" denied "$(pol pki-radius/issue/eap-client common_name=alice)"
check "policy: sign-verbatim" denied "$(pol pki-radius/sign-verbatim csr=@"$W/p.csr")"
check "policy: other role" denied "$(pol pki/sign/tls csr=@"$W/p.csr" common_name=enroll.test)"
check "policy: kv write" denied "$(pol kv/data/apps/freeradius/user-groups 'data=json:{"mallory":"staff"}')"
check "policy: string \"true\"" denied "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=alice exclude_cn_from_sans=str:true ttl=1440h)"
check "policy: device sign" allowed "$(pol pki-enroll/sign/device csr=@"$W/p.csr" common_name=alice uri_sans=urn:uuid:00000000-0000-4000-8000-000000000000 exclude_cn_from_sans=true ttl=8760h)"
check "policy: device without uri_sans" denied "$(pol pki-enroll/sign/device csr=@"$W/p.csr" common_name=alice exclude_cn_from_sans=true ttl=8760h)"
check "role: device URI outside urn:uuid" http-400 "$(pol pki-enroll/sign/device csr=@"$W/p.csr" common_name=alice uri_sans=https://evil.example exclude_cn_from_sans=true ttl=8760h)"
check "role: CN outside allowed_domains" http-400 "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=mallory exclude_cn_from_sans=true ttl=1440h)"
check "policy: no default policy (cubbyhole)" denied "$(pol cubbyhole/test a=b)"
check "policy: revoke-self" allowed "$(pol auth/token/revoke-self)"
check "policy: revoked token" denied "$(pol pki-radius/sign/eap-client csr=@"$W/p.csr" common_name=alice exclude_cn_from_sans=true ttl=1440h)"
check "approle: CIDR binding" denied "$(bao write -field=token auth/approle/login role_id=@state/elsewhere-role-id secret_id=@state/elsewhere-secret-id >/dev/null 2>&1 && echo allowed || echo denied)"

# Rate limit: burst of 5 from one address.
codes=""
for _ in 1 2 3 4 5 6; do
  codes="$codes $(curl -s --interface 127.0.9.9 --cacert pki/root.pem --resolve enroll.test:8443:127.0.0.1 \
    -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer WRONG' --data-binary @"$W/dev.csr" \
    "$URL/device/simpleenroll")"
done
check "rate limit from one address" " 401 401 401 401 401 429" "$codes"

# Disabled user.
BAO_TOKEN=root bao kv put kv/apps/freeradius/user-groups alice=disabled carol=guests Bob=disabled >/dev/null
check "wifi for disabled user" 403 "$(est dis wifi/simpleenroll --cert "$W/dev2.pem" --key "$W/dev2.key" --data-binary @"$W/wifi.csr")"
BAO_TOKEN=root bao kv put kv/apps/freeradius/user-groups alice=staff carol=guests Bob=disabled >/dev/null
check "code for disabled user" 1 "$(bin/eap-enroll code -config "$CFG" -user bob -label x >/dev/null 2>>state/admin.log; echo $?)"

# Disable the device.
bin/eap-enroll devices -config "$CFG" 2>>state/admin.log
bin/eap-enroll disable -config "$CFG" "$DEVID" 2>>state/admin.log
check "disable exit" 0 $?
check "wifi after disable" 403 "$(est after wifi/simpleenroll --cert "$W/dev2.pem" --key "$W/dev2.key" --data-binary @"$W/wifi.csr")"
curl -s --cacert baotls/vault-ca.pem https://127.0.0.1:8200/v1/pki-radius/crl/pem >"$W/radius.crl"
SERIAL=$(field wifi2 -serial | cut -d= -f2)
openssl crl -in "$W/radius.crl" -noout -text | tr -d ' :' | grep -qi "SerialNumber$SERIAL" \
  && ok "wifi cert on the pki-radius CRL" || bad "wifi serial $SERIAL not on CRL"
curl -s --cacert baotls/vault-ca.pem https://127.0.0.1:8200/v1/pki-enroll/crl/pem >"$W/enroll.crl"
check "device CRL entries" 2 "$(openssl crl -in "$W/enroll.crl" -noout -text | grep -c 'Serial Number')"
bin/eap-enroll devices -config "$CFG" 2>>state/admin.log

# Reusing a superseded device credential disables the device.
URI2=$(bin/eap-enroll code -config "$CFG" -user carol -label "Reuse test" 2>>state/admin.log)
CODE2=$(python3 -c 'import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query)["code"][0])' "$URI2")
csr r1 prime256v1
check "reuse: enroll" 200 "$(est r1 device/simpleenroll -H "Authorization: Bearer $CODE2" --data-binary @"$W/r1.csr")"
certs r1
csr r2 prime256v1
check "reuse: renew" 200 "$(est r2 device/simplereenroll --cert "$W/r1.pem" --key "$W/r1.key" --data-binary @"$W/r2.csr")"
certs r2
check "reuse: new credential" 200 "$(est r2p wifi/profile -X GET --cert "$W/r2.pem" --key "$W/r2.key")"
check "reuse: old credential" 403 "$(est r1old wifi/profile -X GET --cert "$W/r1.pem" --key "$W/r1.key")"
check "reuse: new credential after reuse" 403 "$(est r2late wifi/profile -X GET --cert "$W/r2.pem" --key "$W/r2.key")"
curl -s --cacert baotls/vault-ca.pem https://127.0.0.1:8200/v1/pki-enroll/crl/pem >"$W/enroll2.crl"
openssl crl -in "$W/enroll2.crl" -noout -text | tr -d ' :' | grep -qi "SerialNumber$(field r2 -serial | cut -d= -f2)" \
  && ok "reuse: new credential on the CRL" || bad "reuse: new credential not on the CRL"
grep -q '"msg":"credential_reuse"' state/serve.log && ok "reuse: logged" || bad "reuse: not logged"

# Logs must not contain the code or the secret ID.
grep -qe "$CODE" -e "$CODE2" state/serve.log state/admin.log && bad "code in logs" || ok "code not in logs"
grep -qf state/secret-id state/serve.log state/admin.log && bad "secret ID in logs" || ok "secret ID not in logs"

# The service and the admin commands revoke their tokens when they exit.
pkill -f "[e]ap-enroll serve"
for _ in $(seq 40); do pgrep -f "[e]ap-enroll serve" >/dev/null || break; sleep 0.25; done
left=$(BAO_TOKEN=root python3 - <<'EOF'
import json, subprocess
run = lambda *a: subprocess.run(["bao", *a], capture_output=True, text=True)
n = 0
for a in json.loads(run("list", "-format=json", "auth/token/accessors").stdout):
    r = run("write", "-format=json", "auth/token/lookup-accessor", "accessor=" + a)
    if r.returncode == 0 and json.loads(r.stdout)["data"].get("path", "").startswith("auth/approle/"):
        n += 1
print(n)
EOF
)
check "no AppRole tokens left" 0 "$left"
echo "failures: $fails"
