# Design

## Purpose

Phones on a WPA3-Enterprise network authenticate with EAP-TLS client
certificates from an OpenBao PKI. This service lets a phone get its first
certificate and renew it without an administrator signing each one, and
without the phone holding any OpenBao credential.

An unmanaged Android phone can generate a key and hand key and
certificate to Wi-Fi, but after that the app can't use the key any more.
So every Wi-Fi certificate has a new key, and renewal authenticates with
a separate **device credential**: a client certificate whose key stays in
the phone's keystore and that only this service trusts.

## Trust model

- The service holds the only OpenBao credential (an AppRole). Its policy
  allows signing with exactly two roles, revoking in those two mounts,
  rotating their CRLs and reading the user-groups map
  ([openbao.md](openbao.md)). A stolen phone or app gives no access to
  OpenBao.
- The device credentials come from their own intermediate. RADIUS never
  trusts it, and the service trusts only that intermediate for client
  certificates, not the shared root, so Wi-Fi certificates or other
  certificates under the same root can't authenticate here.
- TLS verification alone isn't enough: a client certificate is accepted
  only if its serial is recorded in the service's database as a device
  credential of that device, not revoked, and the device is enabled.
  Disabling therefore takes effect immediately, without waiting for a
  CRL.
- The phone learns which CA to trust for the service from the QR code
  (fingerprint), not on first use.
- The username in a certificate always comes from the service's records
  (from the one-time code), never from the CSR. Users must be enabled in
  the FreeRADIUS user-groups map (any group except `disabled`) when the
  code is created and at every enrollment.

## Flow

1. The administrator runs `eap-enroll code -user U -label L`. The service
   checks that U is enabled, stores the SHA-256 of a random 160-bit code
   with U, L and an expiry, and prints the setup URI.
2. The phone sends a CSR for its keystore key to `device/simpleenroll`
   with the code. In one transaction the code is marked used and a device
   (random UUID) is created. Then the user is checked again and the
   device credential is signed. If that fails, the device is removed
   again; the code stays used.
3. With the device credential, the phone gets Wi-Fi certificates
   (`wifi/simpleenroll`) and renews the credential
   (`device/simplereenroll`).
4. `eap-enroll disable ID` marks the device disabled, then revokes its
   unexpired certificates in OpenBao and rotates the CRLs. RADIUS sees
   the revocation after its next CRL fetch.

## Checks

Before anything is signed:

- The CSR parses, its signature verifies with its own key, and the key
  is ECDSA on an allowed curve (Wi-Fi: P-384, as the RADIUS role
  requires; device: P-256 or P-384).
- A CSR is checked before a code is consumed, so a broken client doesn't
  burn codes.

After OpenBao signs, the result is checked before it is recorded or sent:
CN is the username, the public key is the CSR's, it is not a CA, its
extended key usage is client authentication without server
authentication, it has no DNS, e-mail or IP SANs, the URI SANs are
exactly the device URI (device) or none (Wi-Fi), and it is signed by the
first CA of the returned chain. A certificate that fails these checks is
revoked at once.

Races with disabling: a certificate is recorded in a transaction that
fails if the device is disabled. SQLite serialises writers, so either the
record exists before `disable` lists the device's certificates, or the
insert fails and the handler revokes the new certificate.

`disable` marks certificates as revoked only after the CRL rotation
succeeded, so running it again after an OpenBao failure retries both.

## Rate limits

In memory, per client IP address (IPv6 per /64):

- Every POST: token bucket, 10 per minute, burst 5.
- Wrong, used or expired codes: 5 within 15 minutes block the client for
  15 minutes.
- More than 30 wrong codes from all clients within 15 minutes stop code
  enrollment for everyone until the window ends.

Codes have 160 bits of entropy, so the limits protect the service and the
log more than the codes. The service trusts no proxy headers; the client
address is the TCP peer, so it needs its own listener (or TLS passthrough,
which keeps the peer address only with the PROXY protocol, which this
service doesn't support).

## Audit log

JSON lines on standard error (the journal): `code_created`,
`enroll_device`, `enroll_wifi`, `reenroll_device`,
`certificate_issued`, `device_disabled`, `cert_revoked`, and
`<event>_refused` with a `reason` (`bad_code`, `code_used`,
`code_expired`, `no_code`, `user_disabled`, `device_disabled`,
`unknown_cert`, `revoked_cert`, `rate_limited`, `bad_csr`,
`openbao_error`, ...). Fields: remote address, device ID, username,
label, serial, expiry, as far as known.

Never logged: codes or their hashes, CSRs, certificates, tokens, AppRole
IDs, OpenBao response bodies (only status and OpenBao's error strings).

## Storage

SQLite (WAL) with three tables: one-time codes (hash, user, label,
expiry, used), devices (ID, user, label, created, disabled), and issued
certificates (kind, serial, device, expiry, revoked). The server and the
admin commands use the same file. Expired codes are deleted at start and
hourly.

## Dependencies

- Go standard library for HTTP, TLS, X.509, ASN.1 (PKCS#7 is encoded
  directly) and the OpenBao API (a few JSON calls; the official client
  library would add many modules).
- `modernc.org/sqlite`: SQLite without cgo, so the binary stays static.

## Not done yet

- The phone can't yet tell the service which Wi-Fi certificate a new one
  replaced, so old Wi-Fi certificates stay valid until they expire or
  the device is disabled.
- The service doesn't hand out the Wi-Fi profile (SSID, server CA,
  domain).
