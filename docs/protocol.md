# Protocol

The client's reference: how a phone gets its certificates. Everything is
EST ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030), with the
[RFC 8951](https://www.rfc-editor.org/rfc/rfc8951) clarifications) over
HTTPS, with two labels:

- `device`: the device credential, a client certificate for this service
  only. Its key stays in the phone's keystore.
- `wifi`: the EAP-TLS client certificate. Every request uses a new key.

## Setup URI

The administrator runs `eap-enroll code` and shows the result as a QR
code:

```
eapenroll://setup?ca=<fingerprint>&code=<code>&url=<service URL>&v=1
```

Parameters may come in any order and are URL-encoded.

| Parameter | Value |
| --- | --- |
| `v` | `1`. Refuse other versions. |
| `url` | Base URL of the service, `https://host[:port]`, no path. |
| `ca` | Lowercase hex SHA-256 of the DER encoding of a CA certificate in the service's TLS chain (its issuing or root CA). The service always sends that certificate in its chain. The client uses the served certificate with this fingerprint as its only trust anchor for the service and verifies the rest of the chain and the host name against it. |
| `code` | One-time code: 32 characters of RFC 4648 base32 (`A-Z`, `2-7`). Valid for minutes, single use. |

## TLS

TLS 1.3 only. The server asks for a client certificate but doesn't
require one; requests without a valid one fail on the endpoints that
need it (401).

## Endpoints

All paths are under `/.well-known/est/`.

| Request | Authentication | Body | Response |
| --- | --- | --- | --- |
| `GET wifi/cacerts` | none | | CA chain of the Wi-Fi certificates |
| `GET device/cacerts` | none | | CA chain of the device credentials |
| `POST device/simpleenroll` | `Authorization: Bearer <code>` | CSR for the keystore key | device credential + chain |
| `POST wifi/simpleenroll` | TLS client certificate: device credential | CSR for a new key | Wi-Fi certificate + chain |
| `POST device/simplereenroll` | TLS client certificate: device credential | CSR, same or new key | new device credential + chain |
| `POST wifi/confirm` | TLS client certificate: device credential | serial of the working Wi-Fi certificate | `204`, older Wi-Fi certificates revoked |
| `GET wifi/profile` | TLS client certificate: device credential | | Wi-Fi network settings (JSON) |

`wifi/simpleenroll` is used for the first Wi-Fi certificate and for every
renewal. This deviates from EST on purpose: the phone can't use the old
Wi-Fi key once Wi-Fi has it, so it authenticates with the device
credential instead.

### Requests

- `Content-Type: application/pkcs10`; the body is the base64 of the DER
  CSR. Line breaks are allowed; `Content-Transfer-Encoding` is ignored.
  At most 16 KiB.
- The CSR must be signed by its key (proof of possession).
- Keys: EC P-384 for `wifi`; EC P-256 or P-384 for `device` (StrongBox
  usually only has P-256).
- The service ignores the CSR's subject and extensions. It sets the
  subject to `CN=<username>` itself; device credentials also get the URI
  SAN `urn:uuid:<device ID>`.

### Responses

- `200`: `Content-Type: application/pkcs7-mime; smime-type=certs-only`,
  body the base64 (one line, no line breaks or trailing newline) of a
  DER PKCS#7 SignedData with
  no content and no signers. Certificate order: the issued certificate
  first, then its CA chain (issuing CA first). `cacerts` has only the
  chain.
- Errors have a short `text/plain` body meant for logs, not for parsing:

| Status | Meaning | Client action |
| --- | --- | --- |
| 400 | Malformed body, bad CSR or wrong key type | Fix the request; don't retry as is |
| 401 | Missing, wrong, used or expired code; missing, unknown, revoked or expired device credential | Setup needs a new code |
| 403 | Device or user disabled | Stop; tell the user |
| 413 | Body too large | Don't retry |
| 429 | Rate limited; `Retry-After` in seconds | Wait at least that long |
| 502 | The certificate authority failed | Retry later |
| 500 | Other server error | Retry later |

A failed CSR check (400) doesn't use up a one-time code; any other
answer to `device/simpleenroll` does.

### `wifi/confirm`

After the phone has connected to Wi-Fi with a new certificate, it sends
that certificate's serial number: `text/plain`, hex, with or without
colons, any case, at most 256 bytes. The service revokes the device's
Wi-Fi certificates that were issued before that one and answers `204`.
Repeating the request is harmless. `400` means the serial isn't a
current Wi-Fi certificate of this device; `502` means revoking failed
(retry later).

Until the phone confirms, older Wi-Fi certificates stay valid, so a new
certificate that doesn't work never leaves the phone without Wi-Fi.

Reaching the service proves nothing about Wi-Fi (the phone may use
mobile data or a VPN), so the app must not confirm because a request
succeeded. Android tells the app when it connected through the app's own
network suggestion: `WifiManager.ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION`,
sent only for a suggestion built with `setIsAppInteractionRequired(true)`
and only to an app that may read scan results (precise location
permission, location on). Once the suggestion holds only the new
certificate, that broadcast means the new certificate worked; the
confirmation itself may then go over any network. Without the
permission, the app doesn't confirm, and older certificates simply
expire.

### `wifi/profile`

The network the certificates are for, so the app needs no manual
settings. `404` if the service has no profile configured.

```json
{
  "ssid": "Example Net",
  "server_domain": "radius.example.org",
  "server_ca_certificates": ["<base64 DER>"]
}
```

- `ssid`: the network name.
- `server_domain`: the RADIUS server's certificate name, for
  `WifiEnterpriseConfig.setDomainSuffixMatch()`.
- `server_ca_certificates`: the CA certificates that issued the RADIUS
  server's certificate, for `setCaCertificates()`. These aren't the
  `wifi/cacerts` certificates, which issued the client certificates.

## Device credential renewal

The old device credential keeps working after `device/simplereenroll`
until the phone first authenticates with the new one; then the service
revokes the older credentials of that device. So the phone must switch to
the new credential right after renewing and keep the old one until it
has.

## Lifetimes

Set by the service (`wifi_ttl`, `device_ttl`, for example 60 days and
a year); read them from the issued certificates. Renew at about 2/3 of
the lifetime. When a
device credential expires or is revoked, the phone needs a new code.
