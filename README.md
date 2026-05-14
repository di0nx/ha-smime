# S/MIME Notify (`smime_notify`)

Home Assistant Custom Integration (HACS-ready) to send SMTP emails with S/MIME signing and optional encryption.

## Features

- UI setup via Config Flow and Options Flow
- Recommended UI-friendly service: `smime_notify.send`
- SMTP support: `none`, `STARTTLS`, `SSL/TLS`
- Required plaintext body with optional HTML body
- Optional attachments
- Per-message controls for signing, encryption, fallback behavior, and recipient skipping
- Default recipient fallback when recipients are omitted
- Local recipient certificate lookup with configurable file name hash modes
- SMIMEA DNS recipient certificate lookup with DNS TTL-aware caching
- Services:
  - `smime_notify.send`
  - `smime_notify.send_test_email`
  - `smime_notify.test_recipient_certificate`
  - `smime_notify.clear_certificate_cache`
  - `smime_notify.reload_certificates`
  - `smime_notify.validate_config`

## Installation (HACS)

1. In Home Assistant, open **HACS → Integrations → 3 dots → Custom repositories**.
2. Add this repository URL and category **Integration**.
3. Install **S/MIME Notify**.
4. Restart Home Assistant.
5. Go to **Settings → Devices & Services → Add Integration → S/MIME Notify**.

## Manual Installation

Copy `custom_components/smime_notify` into your Home Assistant config folder and restart Home Assistant.

## UI Configuration

Configure at least:

- SMTP host/port/encryption
- SMTP username/password (if needed)
- Sender name/email
- Signing certificate path + private key path
- Local public-key directory and/or SMIMEA source
- File type list for local public keys, for example `pem, crt, cer, der, txt`
- Hash mode for local/remote public-key lookup

Optional:

- default recipient
- sign/encrypt defaults
- fallback behavior for missing recipient certs
- source order (`local,smimea,remote`)

Multiple config entries are supported. If more than one S/MIME Notify instance is loaded, pass `config_entry_id` to `smime_notify.send` so the service knows which SMTP/S/MIME configuration to use.

Sender identities are configured per instance. Use one line per identity in the setup flow: `id|Display Name|sender@example.org`. The first/default identity is used when `sender_identity` is omitted.

## Recommended UI service: `smime_notify.send`

`smime_notify.send` is the preferred Home Assistant action for automations and scripts because `services.yaml` defines user-friendly fields for the UI.

```yaml
action: smime_notify.send
data:
  title: "S/MIME Test"
  message: "Plaintext body"
  html: "<h1>S/MIME Test</h1><p>HTML body</p>"
  target:
    - dion@kitsos.net
  sign: true
  encrypt: true
  sender_identity: default
  # config_entry_id is required if multiple S/MIME Notify instances are loaded
  # config_entry_id: "01J..."
  skip_recipients_without_cert: false
  allow_unencrypted_fallback: false
```

If `target` is omitted, the integration uses the configured default recipient. If both are missing, sending is aborted.

## Classic notify service removed

The previous dynamic `notify.smime_signed` path has been disabled because it was unreliable in Home Assistant. Use `smime_notify.send` instead; it exposes the same S/MIME options with explicit UI fields.

## Sign and encrypt behavior

When both `sign: true` and `encrypt: true` are set, the integration now signs the MIME message first and then encrypts the signed S/MIME MIME part. Recipients should see a decrypted message that still contains the S/MIME signature instead of an encrypted-only message.

## Recipient certificate test

Use this service to verify whether the integration can resolve and validate a recipient certificate before sending encrypted mail:

```yaml
action: smime_notify.test_recipient_certificate
data:
  email: dion@kitsos.net
```

On success, the Home Assistant log includes the source, certificate subject/issuer, validity period, recipient e-mail addresses, DNS TTL, and DNSSEC AD status when SMIMEA is used.

## Local public keys

Example path:

`/ssl/smime/publickeys/person@example.org.pem`

Default extension order:

- `pem`
- `crt`
- `cer`
- `der`
- `txt`

## Local/remote hash mode

The UI hash mode applies only to local file and remote URL lookup. Normalization before hashing:

- trim
- lowercase

Example local/remote full-address hash:

```bash
echo -n "person@example.org" | sha256sum
```

## SMIMEA DNS lookup

SMIMEA uses its own RFC-style owner name and does **not** use the UI hash mode.

For an address such as `dion@kitsos.net`:

1. Split the e-mail address into local-part and domain:
   - local-part: `dion`
   - domain: `kitsos.net`
2. Normalize the local-part:
   - trim
   - lowercase
3. Calculate SHA-256 over the normalized local-part only, not the full e-mail address.
4. Use the first 28 bytes of the hash, represented as the first 56 hexadecimal characters.
5. Build the owner name as:

```text
<first_56_hex_chars_of_sha256_localpart>._smimecert.<domain>
```

For `dion@kitsos.net`, the name is:

```text
d55bcf8025bdb22b72cf95c0306748d814c0effe3859bddc00d2b1aa._smimecert.kitsos.net
```

## Supported SMIMEA record format

The integration supports full DER certificate records of this form:

```text
SMIMEA 3 0 0 <cert_der_hex>
```

Meaning:

- `3` = domain-issued certificate
- `0` = full certificate selector
- `0` = exact full data matching type
- `<cert_der_hex>` = complete DER-encoded X.509 recipient certificate

The DER certificate is parsed as X.509 and validated for expiration, recipient e-mail address, and S/MIME `emailProtection` EKU when the EKU extension is present.

## SMIMEA DNSSEC and cache behavior

When dnspython exposes the DNS response flags, the integration logs whether the resolver returned DNSSEC AD (`true`/`false`). If AD status is not available, lookup does not crash; logs show `unknown`.

SMIMEA cache entries use the DNS record TTL. For example, a `300 IN SMIMEA` record is cached for at most 300 seconds. Use `smime_notify.clear_certificate_cache` to clear the in-memory cache manually.

## S/MIME encryption limitation

The current Python `cryptography` PKCS7 backend supports only RSA recipient certificates for S/MIME encryption. EC/ECDSA certificates may be perfectly valid as S/MIME identity/signing certificates, but they cannot currently be used as recipient encryption certificates by this backend.

If a recipient certificate uses EC, Ed25519, Ed448, DSA, or another non-RSA public key and `encrypt=true`, the integration now fails before calling the PKCS7 backend and reports a clear Home Assistant error instead of crashing with a raw stack trace.

Workarounds:

- Publish/use an RSA S/MIME certificate for recipients that should receive encrypted mail.
- Use `allow_unencrypted_fallback: true` only if sending unencrypted is acceptable for that message. This logs a warning and does not silently downgrade.
- Future improvement: add an optional OpenSSL CLI/CMS backend for broader recipient key support.

## Remote HTTPS public keys

Remote HTTPS settings are present for architecture compatibility, but the remote source is not implemented yet. If enabled, logs show the sanitized configured base URL and explain that the source is not implemented.

## Security notes

- Secrets are not logged.
- Private keys are not exposed in diagnostics.
- With `encrypt=true`, unencrypted sending is blocked unless explicitly allowed.
- Custom headers from notify payloads are validated and protected against header injection.

## Troubleshooting

- Call `smime_notify.validate_config`
- Call `smime_notify.test_recipient_certificate`
- Call `smime_notify.send_test_email`
- Prefer `smime_notify.send` for UI-friendly sending
- Review Home Assistant logs for the detailed source-by-source certificate lookup trace
