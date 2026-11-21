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
  OpenBao. The service revokes every token it replaces and its last one
  when it exits. Whoever can run the admin commands can use the AppRole
  too.
- The device credentials come from their own intermediate. RADIUS never
  trusts it, and the service trusts only that intermediate for client
  certificates, not the shared root, so Wi-Fi certificates or other
  certificates under the same root can't authenticate here.
- TLS verification alone isn't enough: a client certificate is accepted
  only if its serial is recorded in the service's database as a device
  credential of that device, not revoked, and the device is enabled.
  Disabling therefore takes effect immediately, without waiting for a
  CRL.
- A device credential is rotated like a refresh token. When a superseded
  credential is presented while its device is still enabled, the device
  is disabled: only `revokeOlder` revokes a credential of an enabled
  device, so either a copy of the credential exists or the app kept using
  the old one against the protocol. Both can't be told apart, so the
  service assumes a copy. The owner needs a new code, and the copy stops
  working.
- With `key_attestation`, the service proves that every device
  credential key was generated in the Android Keystore's TEE or
  StrongBox of a locked device with verified or self-signed boot, using
  an attestation chain that ends at a pinned root. The key can then not
  be copied out of the secure hardware. Without `key_attestation`, the
  service still can't verify that a device key is non-exportable: a
  copied credential is limited by the reuse detection above, by the
  per-device issuance caps and by `eap-enroll disable`; it is not
  prevented.
- The phone learns which CA to trust for the service from the QR code
  (fingerprint), not on first use.
- The username in a certificate always comes from the service's records
  (from the one-time code), never from the CSR. Users must be enabled in
  the FreeRADIUS user-groups map (any group except `disabled`) when the
  code is created, at every enrollment, and on every authenticated
  request.

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
   (`wifi/simpleenroll`), the Wi-Fi settings (`wifi/profile`), and renews
   the credential (`device/simplereenroll`).
4. Old certificates are revoked once their replacements are known to
   work: older Wi-Fi certificates when the phone confirms that it has
   connected with the new one (`wifi/confirm`); older device credentials
   the first time the phone authenticates with the new one. Until then
   both stay valid, so a failed renewal never locks the phone out. Using a
   superseded device credential after that disables the device (see the
   trust model), so the phone must switch to the renewed credential at
   once and stop using the old one.
5. `eap-enroll disable ID` marks the device disabled, then revokes its
   unexpired certificates in OpenBao and rotates the CRLs. RADIUS sees
   the revocation after its next CRL fetch.
6. `eap-enroll prune` deletes disabled devices and their certificate
   records once every certificate is revoked or expired. A device whose
   revocation hasn't finished is kept, so rerunning `disable` can
   complete it. A deleted device's credentials are unknown afterwards and
   refused with 401 `unknown_cert`, which the app treats like a disabled
   device (it needs a new code). OpenBao's CRLs still list the revoked
   certificates, and the journal keeps the audit events.

## Checks

Before anything is signed:

- The CSR parses, its signature verifies with its own key, and the key
  is ECDSA on an allowed curve (Wi-Fi: P-384, as the RADIUS role
  requires; device: P-256 or P-384).
- A CSR is checked before a code is consumed, so a broken client doesn't
  burn codes.

After OpenBao signs, the result is checked before it is recorded or sent:

- CN is the username and exactly one CN attribute, and the only subject
  attributes are CN, C, L, ST, O and OU.
- The public key is the CSR's and it is not a CA: no CA flag, and its
  key usage doesn't allow signing certificates or CRLs (some verifiers
  treat a certificate with `keyCertSign` and no basic constraints as a
  CA).
- Its extended key usage is exactly client authentication: nothing else,
  not even unknown purposes.
- Its subjectAltName extension is parsed as ASN.1: Wi-Fi certificates have
  no SAN or no names; device credentials have exactly one URI name, the
  device URI. Other name types (otherName/UPN, directory names, registered
  IDs, DNS, e-mail, IP) are refused.
- It has no unhandled critical extensions.
- Its lifetime ends after now and no later than now plus the profile's
  TTL and five minutes.
- It is signed by a CA from the service's own configuration
  (`wifi_cacerts_file` or `device_ca_file`), not only by the first CA of
  the chain OpenBao returned. For a chain that isn't empty, the check
  against its first CA stays too.

A certificate that fails these checks is revoked at once, and so is one
from an answer the service can't use (a CA chain that doesn't parse,
more than one certificate); then the serial comes from the answer's
`serial_number`.

Races with disabling: a certificate is recorded in a transaction that
fails if the device is disabled. SQLite serialises writers, so either the
record exists before `disable` lists the device's certificates, or the
insert fails and the handler revokes the new certificate.

`disable` marks certificates as revoked only after the CRL rotation
succeeded, so running it again after an OpenBao failure retries both.

## Key attestation

`key_attestation` is optional. When it is configured, every
`device/simpleenroll` and `device/simplereenroll` must carry a
`Key-Attestation` header with the Android Keystore attestation chain for
the CSR's key. Wi-Fi certificates are unaffected. The chain is verified
offline (not Play Integrity, no Google API except the optional public
status list):

- The chain has 1 to 10 certificates, leaf first, and each certificate
  is signed by the next. Attestation chains often lack CA flags, so
  basic constraints are not required. The last certificate must be one
  of the pinned roots or be signed by one. The leaf's validity dates are
  ignored because Android's are unreliable; intermediates and roots
  must be valid now.
- If `status_url` is set, no certificate in the chain may have a serial
  listed as `REVOKED` or `SUSPENDED`. The list is fetched over HTTPS
  (30 s timeout, 10 MiB limit) at startup and every six hours, and
  every five minutes after a failed fetch. An empty list counts as a
  failed fetch. With no
  successful fetch, or with the last one more than seven days old,
  attestation fails closed with `502 attestation_status_unavailable`.
- The leaf has the Android key description extension
  (1.3.6.1.4.1.11129.2.1.17) and no other certificate has it. The
  leaf's public key is the CSR's key.
- The key description says both attestation and KeyMint security levels
  are TEE or StrongBox (`require_strongbox` needs both StrongBox), the
  challenge matches, and the hardware-enforced list says origin
  `GENERATED`, purpose includes `SIGN`, and the root of trust says
  `deviceLocked` with `Verified` or `SelfSigned` boot. `SelfSigned` is
  what GrapheneOS and OSes with their own verified-boot key report. If
  `verified_boot_keys` is set, the boot key must be in it. Without it,
  any OS that relocks the bootloader with its own key passes: the key
  still can't leave the secure hardware, but the OS isn't checked. To
  allow only GrapheneOS, pin its published verified-boot key
  fingerprints for your phone models.
- If `app_package` is set, the attestation application ID must name
  that package and contain one of the `app_signing_certs` SHA-256
  digests.

The challenges bind the attestation to the request. `simpleenroll` uses
the SHA-256 of the one-time code as sent; `simplereenroll` uses the
SHA-256 of the DER of the device credential presented in TLS. Android
fixes the challenge when the key is generated, so a renewal with
attestation needs a new key. Refusals are logged with the detailed
error and the audit reasons `bad_attestation` (400, missing or malformed
header), `attestation_refused` (403, any policy failure) and
`attestation_status_unavailable` (502). A refused attestation happens
before the code is used or anything is signed, so the code stays usable
and the old credential stays valid. Successful enrollments log the
security level, verified-boot state, lock state, boot key and
attestation version.

The roots are Google's hardware attestation root certificates. Google
publishes the current ones as a JSON array of PEM strings at
`https://android.googleapis.com/attestation/root` (linked from the key
attestation page on developer.android.com), so `roots_file` is that array
joined into one PEM file. `deploy/attestation-roots.pem` is that file as
of 2026-11-20 (an RSA root valid until 2042 and the EC P-384 "Key
Attestation CA1" valid until 2035); regenerate it with:

```sh
curl -fsS https://android.googleapis.com/attestation/root |
  python3 -c 'import json,sys; print("".join(c.rstrip("\n")+"\n" for c in json.load(sys.stdin)), end="")' \
  > attestation-roots.pem
```

The phone's secure chip chains to them on stock Android and also on
GrapheneOS; pin all current ones. Test chains are generated in the
tests, never copied from a phone or Google.

Google occasionally revokes leaked attestation keys. The optional
`status_url` is Google's public revocation list; the service only uses
it to refuse, and treats it as unavailable rather than valid when it
cannot load a fresh copy.

## Rate limits

In memory, for unauthenticated requests, per client IP address (IPv6 per
/64):

- Every POST without a usable one-time code: token bucket, 10 per minute,
  burst 5.
- Wrong, used or expired codes: 5 within 15 minutes block the client for
  15 minutes.
- 30 or more wrong codes from all clients within 15 minutes log one
  `code_failures_high` warning per window. They never stop enrollment: a
  usable code has 160 bits of entropy and is an unguessable secret, so it
  bypasses the per-IP limits (bucket and block).

Requests with a device credential are limited per device instead, with
the same rate but a burst of 10 (setting up a phone takes several
requests in a row): authentication comes first, and only a failed
authentication is charged to the client address. A phone with a valid
credential is therefore never affected by the address it shares with
other clients, for example behind NAT or CGNAT. An authenticated request
also checks that the device's user is still enabled.

Per device, the service issues at most 5 valid Wi-Fi certificates and 3
valid device credentials, and at most 10 Wi-Fi certificates and 5 device
credentials per 24 hours (revoked ones count). Over a limit the answer is
429 with `Retry-After: 3600`. The valid-count cap is also enforced in the
database transaction, so concurrent requests can't exceed it; a
certificate issued in that race is revoked again.

The limiter map holds at most 65536 client keys. Idle entries are swept
once a minute; when the map is full, one entry is evicted for a new key,
preferring one that isn't blocked. The limiter never refuses a
request because it is full.

The service trusts no proxy headers; the client address is the TCP peer,
so it needs its own listener (or TLS passthrough, which keeps the peer
address only with the PROXY protocol, which this service doesn't
support).

## Audit log

JSON lines on standard error (the journal): `code_created`,
`enroll_device`, `enroll_wifi`, `reenroll_device`, `confirm_wifi`,
`certificate_issued`, `device_disabled`, `cert_revoked`,
`device_deleted`, `credential_reuse`, `code_failures_high`, and `<event>_refused` with a
`reason` (`bad_code`, `code_used`, `code_expired`, `no_code`,
`user_disabled`, `device_disabled`, `credential_reuse`, `unknown_cert`,
`revoked_cert`, `rate_limited`, `too_many_certificates`, `bad_csr`,
`bad_attestation`, `attestation_refused`,
`attestation_status_unavailable`, `openbao_error`, ...). Every refusal
also sends that reason code in an `Enroll-Error` response header, so the
client can tell refusals apart that share a status (a 403 is a disabled
device only for `device_disabled` and `credential_reuse`); the header
carries nothing but the fixed code, and the text body stays for logs.
Fields: remote
address, device ID, username, label, serial, expiry, as far as known.
Successful device enrollments also log the attestation security level,
verified-boot state, device lock state, verified boot key and
attestation version.

Never logged: codes or their hashes, CSRs, certificates, key
attestation chains, tokens, AppRole IDs, OpenBao response bodies (only
status and OpenBao's error strings).

## Storage

SQLite (WAL) with three tables: one-time codes (hash, user, label,
expiry, used), devices (ID, user, label, created, disabled), and issued
certificates (kind, serial, device, expiry, revoked). The server and the
admin commands use the same file. Expired codes are deleted at start and
hourly; disabled devices only by `eap-enroll prune`.

## Dependencies

- Go standard library for HTTP, TLS, X.509, ASN.1 (PKCS#7 is encoded
  directly) and the OpenBao API (a few JSON calls; the official client
  library would add many modules).
- `modernc.org/sqlite`: SQLite without cgo, so the binary stays static.

## Lifetimes

Suggested: Wi-Fi certificates 60 days, device credentials a year. The
phone renews at about 2/3, so renewal runs every ~40 days and problems
show up while the old certificate still works. A lost phone that isn't
disabled keeps Wi-Fi access for at most 60 days.
