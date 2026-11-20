# eap-enroll-server

An EST ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) enrollment
service that issues EAP-TLS client certificates for Wi-Fi from an
[OpenBao](https://openbao.org) PKI to phones, and lets them renew those
certificates. The phones never hold an OpenBao credential: they enroll
once with a one-time code from a QR code and authenticate renewals with a
device credential whose key stays in their keystore.

- [docs/design.md](docs/design.md): trust model, checks, rate limits,
  logging.
- [docs/protocol.md](docs/protocol.md): the client's side (endpoints,
  encodings, setup URI).
- [docs/openbao.md](docs/openbao.md): mounts, roles and AppRole policy
  the service needs.

## Build

Go 1.27.3 or newer:

```sh
CGO_ENABLED=0 go build -trimpath -o eap-enroll ./cmd/eap-enroll
go test ./...
```

## Configure

Copy [config.example.json](config.example.json) and adjust it. Unknown
fields are errors.

| Field | Meaning |
| --- | --- |
| `listen` | Listen address. The service terminates TLS itself, because it needs the client certificate and the client's address. |
| `public_url` | URL the phones use, `https://host[:port]`. |
| `tls_cert_file`, `tls_key_file` | Server certificate chain and key. The chain must include the `setup_ca_file` certificate. Changed files are picked up within a minute. |
| `setup_ca_file` | One CA certificate from the server's chain; its fingerprint goes into the QR code and the phone pins it. |
| `device_ca_file` | The device credential intermediate (`pki-enroll`) only, never the root it shares with other CAs. Self-signed certificates are refused. |
| `wifi_cacerts_file`, `device_cacerts_file` | PEM bundles served at `wifi/cacerts` and `device/cacerts`. |
| `database` | SQLite file. |
| `code_ttl` | Lifetime of one-time codes (default 15m, at most 24h). |
| `wifi_ttl`, `device_ttl` | Certificate lifetimes, sent to OpenBao verbatim as `ttl`. |
| `wifi_profile` | Optional: `ssid` (exact, spaces kept), `server_domain` (RADIUS server certificate name) and `server_ca_file` (CA of the RADIUS server certificate), served at `wifi/profile`. |
| `openbao.*` | Address, optional CA file and TLS server name, AppRole role ID and secret ID files, and the mounts, roles and KV path (defaults as in the example). |

[deploy/eap-enroll.service](deploy/eap-enroll.service) is an example
systemd unit.

## Admin commands

All take `-config FILE` and write their audit events to standard error.

```sh
# One-time code for an enabled user, shown as a QR code:
eap-enroll code -config FILE -user alice -label "Pixel" | qrencode -t ansiutf8

# Devices with status and certificate expiry:
eap-enroll devices -config FILE

# Block a device now and revoke its certificates (rerun to retry after an
# OpenBao failure):
eap-enroll disable -config FILE DEVICE_ID
```

## Licence

[MPL-2.0](LICENSE).
