# OpenBao setup

What the service expects in OpenBao. Names are the configuration
defaults. The roles and the policy below were tested against an OpenBao
2.7.3 dev server with [test/openbao](../test/openbao) (2026-11-20).

`allowed_parameters` compares values with their JSON type: the service
sends `exclude_cn_from_sans` as the boolean `true`, which matches
`[true]`; the `bao` CLI sends `exclude_cn_from_sans=true` as a string,
which the policy refuses. `allowed_parameters` only limits parameters
that are present, so the ones that must always be sent are listed in
`required_parameters` too.

## Wi-Fi certificates: existing `pki-radius` mount

The service uses an existing role, `eap-client`, which FreeRADIUS's CA
issues from. The role must:

- take the CN from the request, not the CSR (`use_csr_common_name=false`,
  `use_csr_sans=false`, `require_cn=true`);
- allow only enabled usernames as CN (`allowed_domains` = the usernames,
  `allow_bare_domains=true`, `allow_subdomains=false`,
  `allow_glob_domains=false`, `allow_any_name=false`,
  `enforce_hostnames=false`);
- be client-only (`client_flag=true`, `server_flag=false`);
- use `key_type=ec`, `key_bits=384`;
- store certificates (`no_store=false`), otherwise revoking by serial
  fails;
- have a `max_ttl` at least as long as the service's `wifi_ttl`.

## Device credentials: new `pki-enroll` mount

A separate intermediate CA, signed by the same root or another one. RADIUS
must not trust it.

```sh
bao secrets enable -path=pki-enroll -max-lease-ttl=26280h pki
# generate a CSR, sign it with the root, set-signed, name the issuer ...
bao write pki-enroll/config/crl auto_rebuild=true expiry=72h
```

Role `device` (a write replaces the whole role, so always write all
fields):

```sh
bao write pki-enroll/roles/device - <<'EOF'
{
  "issuer_ref": "default",
  "key_type": "ec",
  "key_bits": 0,
  "ttl": "8760h",
  "max_ttl": "8760h",
  "allow_any_name": true,
  "enforce_hostnames": false,
  "allow_ip_sans": false,
  "allowed_uri_sans": ["urn:uuid:*"],
  "allowed_other_sans": [],
  "use_csr_common_name": false,
  "use_csr_sans": false,
  "require_cn": true,
  "server_flag": false,
  "client_flag": true,
  "code_signing_flag": false,
  "email_protection_flag": false,
  "key_usage": ["DigitalSignature"],
  "ext_key_usage": [],
  "no_store": false
}
EOF
```

With `key_bits: 0` the role signs both P-256 and P-384 keys (tested).

## AppRole and policy

Replace the TTL values with the service's `wifi_ttl` and `device_ttl`,
spelled exactly as in its configuration: the service sends them
verbatim.

```hcl
path "pki-radius/sign/eap-client" {
  capabilities        = ["update"]
  required_parameters = ["csr", "common_name", "exclude_cn_from_sans", "ttl"]
  allowed_parameters = {
    "csr"                  = []
    "common_name"          = []
    "exclude_cn_from_sans" = [true]
    "ttl"                  = ["2160h"]
  }
}

path "pki-enroll/sign/device" {
  capabilities        = ["update"]
  required_parameters = ["csr", "common_name", "uri_sans", "exclude_cn_from_sans", "ttl"]
  allowed_parameters = {
    "csr"                  = []
    "common_name"          = []
    "uri_sans"             = []
    "exclude_cn_from_sans" = [true]
    "ttl"                  = ["8760h"]
  }
}

path "pki-radius/revoke" { capabilities = ["update"] }
path "pki-enroll/revoke" { capabilities = ["update"] }
path "pki-radius/crl/rotate" { capabilities = ["read"] }
path "pki-enroll/crl/rotate" { capabilities = ["read"] }

path "kv/data/apps/freeradius/user-groups" { capabilities = ["read"] }
```

Limits of this policy: the service can revoke any certificate in both
mounts, not just those it issued, and the `eap-client` role decides which
usernames are valid at all; the service's own user check comes on top.

The AppRole: short token TTL, secret ID bound to the service host's
address.

```sh
bao write auth/approle/role/eap-enroll \
  token_policies=eap-enroll token_ttl=20m token_max_ttl=1h \
  secret_id_bound_cidrs=<service address>/32 token_bound_cidrs=<service address>/32 \
  secret_id_ttl=0 secret_id_num_uses=0
```

The service logs in again whenever its token is about to expire, so the
token needn't be renewable.
