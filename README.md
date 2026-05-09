# S/MIME Notify (`smime_notify`)

Home Assistant Custom Integration (HACS-ready) to send SMTP emails with:

- **S/MIME signing** (default on)
- **optional S/MIME encryption**
- `notify.smime_signed` action support
- Configurable local recipient certificate lookup with hash modes

## Features

- UI setup via Config Flow and Options Flow
- SMTP support: `none`, `STARTTLS`, `SSL/TLS`
- Required plaintext + HTML mail body (proper multipart/alternative)
- Optional attachments (`data.attachments`)
- Per-message controls:
  - `data.sign`
  - `data.encrypt`
  - `data.allow_unencrypted_fallback`
  - `data.skip_recipients_without_cert`
- Default recipient fallback when `target` is omitted
- Local recipient cert lookup with configurable extension order
- Hash mode support:
  - `raw_email`
  - `sha256_email_hex`
  - `both_raw_then_hash`
  - `both_hash_then_raw`
- Services:
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
- Local public-key directory
- File type list (for example `pem, crt, cer, der, txt`)
- Hash mode

Optional:

- default recipient
- sign/encrypt defaults
- fallback behavior for missing recipient certs

## Sign-only example

```yaml
action: notify.smime_signed
data:
  title: "Home Assistant Test"
  message: "Diese E-Mail ist S/MIME signiert."
  target:
    - person@example.org
  data:
    html: "<h1>Hallo</h1><p>Diese Mail kommt von Home Assistant.</p>"
    sign: true
    encrypt: false
```

## Sign + Encrypt example

```yaml
action: notify.smime_signed
data:
  title: "Secret Home Assistant Report"
  message: "Fallback Plaintext"
  target:
    - person@example.org
  data:
    html: "<h1>Secret Report</h1>"
    sign: true
    encrypt: true
    allow_unencrypted_fallback: false
    skip_recipients_without_cert: false
```

## Default recipient

If `target` is not set, the integration uses the configured default recipient.
If both are missing, sending is aborted and logged.

## Local public keys

Example path:

`/ssl/smime/publickeys/person@example.org.pem`

Default extension order:

- `pem`
- `crt`
- `cer`
- `der`
- `txt`

## Remote HTTPS public keys

Phase-2 roadmap. Source ordering/settings are already present to keep architecture stable.

## Hash mode

Normalization before hashing:

- trim
- lowercase

Example:

```bash
echo -n "person@example.org" | sha256sum
```

## SMIMEA

Phase-3 roadmap (DNS-based recipient certificate lookup with TTL-aware caching).

## Cache behavior

MVP currently uses in-memory recipient certificate cache (clearable via service).

## Security notes

- Secrets are not logged.
- Private keys are not exposed in diagnostics.
- With `encrypt=true`, unencrypted sending is blocked unless explicitly allowed.
- Custom headers are validated and protected against header injection.

## Troubleshooting

- Call `smime_notify.validate_config`
- Call `smime_notify.test_recipient_certificate`
- Call `smime_notify.send_test_email`
- Review Home Assistant logs for cert and SMTP errors

## Known limitations

- MVP phase implemented first: local source + signing/encryption + notify workflow.
- Remote HTTPS cert source and SMIMEA DNS lookup are not fully implemented yet.
