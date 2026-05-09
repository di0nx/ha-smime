"""Notification handling for S/MIME Notify."""

from __future__ import annotations

import base64
import hashlib
import html as html_lib
import logging
import mimetypes
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
from typing import Any

import aiosmtplib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, pkcs7, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from homeassistant.components.notify import NotifyEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify

from .const import (
    CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
    CONF_CERT_EXPIRY_WARNING_DAYS,
    CONF_DEFAULT_RECIPIENT,
    CONF_ENCRYPT_DEFAULT,
    CONF_FILE_TYPES,
    CONF_FROM_EMAIL,
    CONF_FROM_NAME,
    CONF_HASH_MODE,
    CONF_INCLUDE_CERT_CHAIN,
    CONF_LOCAL_CERT_DIR,
    CONF_NOTIFY_SERVICE_NAME,
    CONF_SIGN_CERT_PATH,
    CONF_SIGN_DEFAULT,
    CONF_SIGN_KEY_PASSWORD,
    CONF_SIGN_KEY_PATH,
    CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
    CONF_SMTP_ENCRYPTION,
    CONF_SMTP_HOST,
    CONF_SMTP_PASSWORD,
    CONF_SMTP_PORT,
    CONF_SMTP_TIMEOUT,
    CONF_SMTP_USERNAME,
    CONF_TLS_VERIFY,
    DATA_MANAGER,
    DEFAULT_ALLOW_UNENCRYPTED_FALLBACK,
    DEFAULT_CERT_EXPIRY_WARNING_DAYS,
    DEFAULT_ENCRYPT_DEFAULT,
    DEFAULT_FROM_NAME,
    DEFAULT_HASH_MODE,
    DEFAULT_INCLUDE_CERT_CHAIN,
    DEFAULT_LOCAL_FILE_TYPES,
    DEFAULT_NOTIFY_SERVICE_NAME,
    DEFAULT_SIGN_DEFAULT,
    DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT,
    DEFAULT_SMTP_PORT,
    DEFAULT_SMTP_TIMEOUT,
    DEFAULT_TLS_VERIFY,
    DOMAIN,
    HASH_MODE_BOTH_HASH_THEN_RAW,
    HASH_MODE_RAW_EMAIL,
    HASH_MODE_SHA256_EMAIL_HEX,
    SMTP_ENCRYPTION_SSL,
    SMTP_ENCRYPTION_STARTTLS,
)

_LOGGER = logging.getLogger(__name__)

DISALLOWED_EXTRA_HEADERS = {
    "to",
    "cc",
    "bcc",
    "from",
    "subject",
    "content-type",
    "content-transfer-encoding",
    "mime-version",
    "reply-to",
}


@dataclass
class RecipientCertResult:
    """Result for recipient cert lookup."""

    email: str
    certificate: x509.Certificate | None
    source: str | None
    location: str | None
    error: str | None = None


@dataclass
class SenderMaterial:
    """Sender certificate/key material."""

    signing_cert: x509.Certificate
    additional_certs: list[x509.Certificate]
    private_key: Any


class SmimeNotifyManager:
    """Manage S/MIME notify sending."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self._sender_material: SenderMaterial | None = None
        self._cert_cache: dict[str, RecipientCertResult] = {}

    @property
    def config(self) -> dict[str, Any]:
        merged = {**self.entry.data, **self.entry.options}
        merged.setdefault(CONF_FILE_TYPES, DEFAULT_LOCAL_FILE_TYPES)
        merged.setdefault(CONF_HASH_MODE, DEFAULT_HASH_MODE)
        merged.setdefault(CONF_SIGN_DEFAULT, DEFAULT_SIGN_DEFAULT)
        merged.setdefault(CONF_ENCRYPT_DEFAULT, DEFAULT_ENCRYPT_DEFAULT)
        merged.setdefault(CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT, DEFAULT_ALLOW_UNENCRYPTED_FALLBACK)
        merged.setdefault(CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT, DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT)
        merged.setdefault(CONF_INCLUDE_CERT_CHAIN, DEFAULT_INCLUDE_CERT_CHAIN)
        merged.setdefault(CONF_TLS_VERIFY, DEFAULT_TLS_VERIFY)
        merged.setdefault(CONF_SMTP_PORT, DEFAULT_SMTP_PORT)
        merged.setdefault(CONF_SMTP_TIMEOUT, DEFAULT_SMTP_TIMEOUT)
        merged.setdefault(CONF_FROM_NAME, DEFAULT_FROM_NAME)
        merged.setdefault(CONF_CERT_EXPIRY_WARNING_DAYS, DEFAULT_CERT_EXPIRY_WARNING_DAYS)
        return merged

    @property
    def notify_service_name(self) -> str:
        name = str(self.config.get(CONF_NOTIFY_SERVICE_NAME, DEFAULT_NOTIFY_SERVICE_NAME)).strip()
        return slugify(name) or DEFAULT_NOTIFY_SERVICE_NAME

    async def async_reload_certificates(self) -> None:
        """Reload sender cert/key from disk."""
        self._sender_material = None
        await self.async_validate_sender_material()
        _LOGGER.info("S/MIME sender certificates reloaded")

    async def async_validate_sender_material(self) -> None:
        """Validate sender cert and key are loadable and matching."""
        cert_path = str(self.config.get(CONF_SIGN_CERT_PATH) or "").strip()
        key_path = str(self.config.get(CONF_SIGN_KEY_PATH) or "").strip()
        if not cert_path or not key_path:
            raise HomeAssistantError(
                "Signing certificate path and private key path must be configured to enable signing"
            )
        material = await self.hass.async_add_executor_job(self._load_sender_material)
        self._sender_material = material

        now = datetime.now(UTC)
        warn_delta = timedelta(days=int(self.config.get(CONF_CERT_EXPIRY_WARNING_DAYS, DEFAULT_CERT_EXPIRY_WARNING_DAYS)))
        if material.signing_cert.not_valid_after_utc <= now:
            raise HomeAssistantError("Sender certificate is expired")
        if material.signing_cert.not_valid_after_utc <= now + warn_delta:
            _LOGGER.warning(
                "Sender certificate will expire soon at %s",
                material.signing_cert.not_valid_after_utc.isoformat(),
            )

    async def async_validate_config_service(self) -> None:
        """Validate critical configuration and log findings."""
        await self.async_validate_sender_material()
        smtp_host = self.config.get(CONF_SMTP_HOST)
        smtp_port = self.config.get(CONF_SMTP_PORT)
        if not smtp_host:
            raise HomeAssistantError("SMTP host is missing")
        if not smtp_port:
            raise HomeAssistantError("SMTP port is missing")

        cert_dir = self.config.get(CONF_LOCAL_CERT_DIR)
        if cert_dir and not Path(cert_dir).exists():
            _LOGGER.warning("Local recipient certificate directory does not exist: %s", cert_dir)

        file_types = self._validated_file_types()
        if not file_types:
            raise HomeAssistantError("No valid file types configured")

        _LOGGER.info("S/MIME config validation succeeded")

    async def async_clear_certificate_cache(self) -> None:
        """Clear in-memory cert cache."""
        self._cert_cache.clear()
        _LOGGER.info("S/MIME recipient certificate cache cleared")

    async def async_send_test_email(self, call: ServiceCall) -> None:
        """Send test email service."""
        recipient = call.data["recipient"]
        subject = call.data.get("subject", "S/MIME Test Email")
        message = call.data.get("message", "S/MIME test message")
        html = call.data.get("html", f"<p>{html_lib.escape(message)}</p>")
        sign = call.data.get("sign")
        encrypt = call.data.get("encrypt")

        _LOGGER.info("Running SMTP/S/MIME test for recipient %s", recipient)
        await self._send_message(
            title=subject,
            plaintext=message,
            html=html,
            to=[recipient],
            cc=[],
            bcc=[],
            reply_to=None,
            attachments=[],
            extra_headers={},
            sign=sign,
            encrypt=encrypt,
            allow_unencrypted_fallback=None,
            skip_recipients_without_cert=None,
            service_context="send_test_email",
        )

    async def async_test_recipient_certificate(self, call: ServiceCall) -> None:
        """Test recipient cert lookup and validation."""
        email = _normalize_email(call.data["email"])
        result = await self._async_resolve_recipient_certificate(email)
        if not result.certificate:
            _LOGGER.error(
                "Recipient certificate not found for %s (source=%s, error=%s)",
                email,
                result.source,
                result.error,
            )
            raise HomeAssistantError(f"No valid recipient certificate found for {email}")

        cert = result.certificate
        _LOGGER.info(
            "Recipient certificate found for %s: source=%s location=%s subject=%s issuer=%s expires=%s emails=%s",
            email,
            result.source,
            result.location,
            cert.subject.rfc4514_string(),
            cert.issuer.rfc4514_string(),
            cert.not_valid_after_utc.isoformat(),
            _certificate_emails(cert),
        )

    async def async_send_notify_service(self, call: ServiceCall) -> None:
        """Handle notify.<service_name> calls."""
        data = call.data
        title = str(data.get("title") or "")
        plaintext = str(data.get("message") or "")
        payload = data.get("data") or {}
        html = payload.get("html")

        if not plaintext:
            raise HomeAssistantError("Plaintext body is required")
        if not html:
            html = f"<p>{html_lib.escape(plaintext)}</p>"

        target = _as_email_list(data.get("target"))
        if not target:
            default_recipient = self.config.get(CONF_DEFAULT_RECIPIENT, "").strip()
            if default_recipient:
                target = [default_recipient]
            else:
                _LOGGER.error(
                    "No target provided and no default recipient configured. Configure default recipient or pass target."
                )
                raise HomeAssistantError("No recipients configured")

        await self._send_message(
            title=title,
            plaintext=plaintext,
            html=str(html),
            to=target,
            cc=_as_email_list(payload.get("cc")),
            bcc=_as_email_list(payload.get("bcc")),
            reply_to=payload.get("reply_to"),
            attachments=_as_string_list(payload.get("attachments")),
            extra_headers=_validate_extra_headers(payload.get("headers") or {}),
            sign=payload.get("sign"),
            encrypt=payload.get("encrypt"),
            allow_unencrypted_fallback=payload.get("allow_unencrypted_fallback"),
            skip_recipients_without_cert=payload.get("skip_recipients_without_cert"),
            service_context="notify",
        )

    async def _send_message(
        self,
        *,
        title: str,
        plaintext: str,
        html: str,
        to: list[str],
        cc: list[str],
        bcc: list[str],
        reply_to: str | None,
        attachments: list[str],
        extra_headers: dict[str, str],
        sign: bool | None,
        encrypt: bool | None,
        allow_unencrypted_fallback: bool | None,
        skip_recipients_without_cert: bool | None,
        service_context: str,
    ) -> None:
        """Build and send an email with S/MIME options."""
        sign_flag = self.config[CONF_SIGN_DEFAULT] if sign is None else bool(sign)
        encrypt_flag = self.config[CONF_ENCRYPT_DEFAULT] if encrypt is None else bool(encrypt)
        allow_fallback = (
            self.config[CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT]
            if allow_unencrypted_fallback is None
            else bool(allow_unencrypted_fallback)
        )
        skip_missing = (
            self.config[CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT]
            if skip_recipients_without_cert is None
            else bool(skip_recipients_without_cert)
        )

        recipient_groups = {
            "to": [_normalize_email(addr) for addr in to],
            "cc": [_normalize_email(addr) for addr in cc],
            "bcc": [_normalize_email(addr) for addr in bcc],
        }
        all_recipients = recipient_groups["to"] + recipient_groups["cc"] + recipient_groups["bcc"]
        if not all_recipients:
            raise HomeAssistantError("No recipients specified")

        recipient_certs: dict[str, x509.Certificate] = {}
        missing_cert_errors: dict[str, str] = {}

        if encrypt_flag:
            for email in all_recipients:
                cert_result = await self._async_resolve_recipient_certificate(email)
                if cert_result.certificate:
                    recipient_certs[email] = cert_result.certificate
                else:
                    missing_cert_errors[email] = cert_result.error or "certificate not found"

            if missing_cert_errors and skip_missing:
                for group_name in ("to", "cc", "bcc"):
                    recipient_groups[group_name] = [
                        email for email in recipient_groups[group_name] if email not in missing_cert_errors
                    ]
                if not any(recipient_groups.values()):
                    raise HomeAssistantError(
                        "Encryption requested but no recipients remain after skipping missing certificates"
                    )
                _LOGGER.warning("Skipping recipients without certificate: %s", sorted(missing_cert_errors))
            elif missing_cert_errors and not allow_fallback:
                missing_text = "; ".join(f"{email}: {error}" for email, error in missing_cert_errors.items())
                raise HomeAssistantError(
                    f"Encryption requested, missing recipient certificates: {missing_text}"
                )
            elif missing_cert_errors and allow_fallback:
                _LOGGER.warning(
                    "Encryption fallback triggered due to missing certificates: %s",
                    ", ".join(sorted(missing_cert_errors)),
                )
                encrypt_flag = False

        base_message = await self.hass.async_add_executor_job(
            self._build_base_email,
            title,
            plaintext,
            html,
            recipient_groups["to"],
            recipient_groups["cc"],
            recipient_groups["bcc"],
            reply_to,
            attachments,
            extra_headers,
        )
        base_bytes = base_message.as_bytes(policy=SMTP)

        if sign_flag and not self._sender_material:
            await self.async_validate_sender_material()

        if sign_flag:
            signed_der = await self.hass.async_add_executor_job(self._sign_data, base_bytes)
            if encrypt_flag:
                ordered_recipients = recipient_groups["to"] + recipient_groups["cc"] + recipient_groups["bcc"]
                encrypted_der = await self.hass.async_add_executor_job(
                    self._encrypt_data,
                    signed_der,
                    [recipient_certs[email] for email in ordered_recipients],
                )
                final_message = self._build_pkcs7_wrapper(base_message, encrypted_der, smime_type="enveloped-data")
            else:
                final_message = self._build_pkcs7_wrapper(base_message, signed_der, smime_type="signed-data")
        elif encrypt_flag:
            ordered_recipients = recipient_groups["to"] + recipient_groups["cc"] + recipient_groups["bcc"]
            encrypted_der = await self.hass.async_add_executor_job(
                self._encrypt_data,
                base_bytes,
                [recipient_certs[email] for email in ordered_recipients],
            )
            final_message = self._build_pkcs7_wrapper(base_message, encrypted_der, smime_type="enveloped-data")
        else:
            _LOGGER.warning("Sending message without signing and encryption (context=%s).", service_context)
            final_message = base_message

        await self._async_send_smtp(
            message=final_message,
            recipients=recipient_groups["to"] + recipient_groups["cc"] + recipient_groups["bcc"],
        )

    async def _async_send_smtp(self, message: EmailMessage, recipients: list[str]) -> None:
        cfg = self.config
        encryption_mode = cfg[CONF_SMTP_ENCRYPTION]
        tls_context = ssl.create_default_context()
        if not cfg.get(CONF_TLS_VERIFY, True):
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE

        smtp = aiosmtplib.SMTP(
            hostname=cfg[CONF_SMTP_HOST],
            port=int(cfg[CONF_SMTP_PORT]),
            timeout=float(cfg[CONF_SMTP_TIMEOUT]),
            use_tls=encryption_mode == SMTP_ENCRYPTION_SSL,
            start_tls=encryption_mode == SMTP_ENCRYPTION_STARTTLS,
            tls_context=tls_context,
        )

        try:
            await smtp.connect()
            username = str(cfg.get(CONF_SMTP_USERNAME) or "").strip()
            if username:
                await smtp.login(username, str(cfg.get(CONF_SMTP_PASSWORD) or ""))
            await smtp.sendmail(str(cfg[CONF_FROM_EMAIL]), recipients, message.as_bytes(policy=SMTP))
        except Exception as err:
            raise HomeAssistantError("SMTP send failed") from err
        finally:
            try:
                await smtp.quit()
            except Exception:
                pass

    def _build_base_email(
        self,
        title: str,
        plaintext: str,
        html: str,
        to: list[str],
        cc: list[str],
        bcc: list[str],
        reply_to: str | None,
        attachments: list[str],
        extra_headers: dict[str, str],
    ) -> EmailMessage:
        cfg = self.config
        message = EmailMessage()
        from_name = str(cfg.get(CONF_FROM_NAME) or "").strip()
        from_email = str(cfg.get(CONF_FROM_EMAIL) or "").strip()

        message["From"] = f"{from_name} <{from_email}>" if from_name else from_email
        message["Subject"] = title
        message["To"] = ", ".join(to)
        if cc:
            message["Cc"] = ", ".join(cc)
        if reply_to:
            message["Reply-To"] = str(reply_to)
        for header, value in extra_headers.items():
            message[header] = value

        message.set_content(plaintext)
        message.add_alternative(html, subtype="html")

        for path_str in attachments:
            file_path = Path(path_str)
            if not file_path.is_file():
                raise HomeAssistantError(f"Attachment not found: {file_path}")
            content_type, _ = mimetypes.guess_type(str(file_path))
            if not content_type:
                content_type = "application/octet-stream"
            maintype, subtype = content_type.split("/", 1)
            message.add_attachment(
                file_path.read_bytes(),
                maintype=maintype,
                subtype=subtype,
                filename=file_path.name,
            )

        return message

    def _build_pkcs7_wrapper(self, base_message: EmailMessage, pkcs7_der: bytes, *, smime_type: str) -> EmailMessage:
        wrapped = EmailMessage()
        for header in ("From", "To", "Cc", "Subject", "Reply-To"):
            if header in base_message:
                wrapped[header] = base_message[header]

        wrapped["MIME-Version"] = "1.0"
        wrapped["Content-Description"] = "S/MIME Cryptographic Message"
        wrapped["Content-Disposition"] = 'attachment; filename="smime.p7m"'
        wrapped["Content-Transfer-Encoding"] = "base64"
        wrapped.set_type("application/pkcs7-mime")
        wrapped.set_param("smime-type", smime_type)
        wrapped.set_param("name", "smime.p7m")
        wrapped.set_payload(base64.encodebytes(pkcs7_der).decode("ascii"))
        return wrapped

    def _load_sender_material(self) -> SenderMaterial:
        cert_path = Path(str(self.config[CONF_SIGN_CERT_PATH]))
        key_path = Path(str(self.config[CONF_SIGN_KEY_PATH]))
        key_password = str(self.config.get(CONF_SIGN_KEY_PASSWORD) or "")

        if not cert_path.is_file():
            raise HomeAssistantError(f"Signing certificate path not found: {cert_path}")
        if not key_path.is_file():
            raise HomeAssistantError(f"Private key path not found: {key_path}")

        certs = _load_certificates_from_bytes(cert_path.read_bytes())
        if not certs:
            raise HomeAssistantError("No certificates found in signing cert file")

        password_bytes = key_password.encode("utf-8") if key_password else None
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=password_bytes)
        signing_cert = certs[0]
        self._assert_private_key_matches_certificate(private_key, signing_cert)

        return SenderMaterial(
            signing_cert=signing_cert,
            additional_certs=certs[1:],
            private_key=private_key,
        )

    def _assert_private_key_matches_certificate(self, private_key: Any, cert: x509.Certificate) -> None:
        cert_public = cert.public_key()
        private_public = private_key.public_key()

        if isinstance(cert_public, rsa.RSAPublicKey) and isinstance(private_public, rsa.RSAPublicKey):
            if cert_public.public_numbers() != private_public.public_numbers():
                raise HomeAssistantError("Private key does not match signing certificate")
            return
        if isinstance(cert_public, ec.EllipticCurvePublicKey) and isinstance(private_public, ec.EllipticCurvePublicKey):
            if cert_public.public_numbers() != private_public.public_numbers():
                raise HomeAssistantError("Private key does not match signing certificate")
            return

        cert_blob = cert_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_blob = private_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_blob != key_blob:
            raise HomeAssistantError("Private key does not match signing certificate")

    def _sign_data(self, data: bytes) -> bytes:
        if not self._sender_material:
            raise HomeAssistantError("Sender material is not loaded")

        material = self._sender_material
        builder = pkcs7.PKCS7SignatureBuilder().set_data(data)
        builder = builder.add_signer(material.signing_cert, material.private_key, hashes.SHA256())
        if self.config.get(CONF_INCLUDE_CERT_CHAIN, True):
            for cert in material.additional_certs:
                builder = builder.add_certificate(cert)

        return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])

    def _encrypt_data(self, data: bytes, recipient_certs: list[x509.Certificate]) -> bytes:
        builder = pkcs7.PKCS7EnvelopeBuilder().set_data(data)
        for cert in recipient_certs:
            builder = builder.add_recipient(cert)
        return builder.encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])

    async def _async_resolve_recipient_certificate(self, email: str) -> RecipientCertResult:
        if email in self._cert_cache:
            return self._cert_cache[email]

        result = await self.hass.async_add_executor_job(self._resolve_recipient_certificate_local, email)
        self._cert_cache[email] = result
        return result

    def _resolve_recipient_certificate_local(self, email: str) -> RecipientCertResult:
        cert_dir = Path(str(self.config.get(CONF_LOCAL_CERT_DIR) or "").strip())
        if not cert_dir.exists() or not cert_dir.is_dir():
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="local",
                location=str(cert_dir),
                error="local cert directory not found",
            )

        file_types = self._validated_file_types()
        if not file_types:
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="local",
                location=str(cert_dir),
                error="no file types configured",
            )

        for name in _candidate_names(email, str(self.config.get(CONF_HASH_MODE, DEFAULT_HASH_MODE))):
            for file_type in file_types:
                candidate = cert_dir / f"{name}.{file_type}"
                if not candidate.is_file():
                    continue
                try:
                    cert = _load_first_certificate(candidate.read_bytes())
                    _validate_recipient_certificate(cert, email)
                except Exception as err:
                    return RecipientCertResult(
                        email=email,
                        certificate=None,
                        source="local",
                        location=str(candidate),
                        error=str(err),
                    )
                return RecipientCertResult(
                    email=email,
                    certificate=cert,
                    source="local",
                    location=str(candidate),
                )

        return RecipientCertResult(
            email=email,
            certificate=None,
            source="local",
            location=str(cert_dir),
            error="certificate not found",
        )

    def _validated_file_types(self) -> list[str]:
        configured = self.config.get(CONF_FILE_TYPES, DEFAULT_LOCAL_FILE_TYPES)
        file_types: list[str] = []
        for entry in configured:
            normalized = str(entry).strip().lower().lstrip(".")
            if normalized and all(ch.isalnum() for ch in normalized):
                file_types.append(normalized)
        return file_types


def _normalize_email(email: str) -> str:
    return str(email).strip().lower()


def _sha256_email(email: str) -> str:
    return hashlib.sha256(email.encode("utf-8")).hexdigest()


def _candidate_names(email: str, hash_mode: str) -> list[str]:
    normalized = _normalize_email(email)
    hashed = _sha256_email(normalized)
    if hash_mode == HASH_MODE_RAW_EMAIL:
        return [normalized]
    if hash_mode == HASH_MODE_SHA256_EMAIL_HEX:
        return [hashed]
    if hash_mode == HASH_MODE_BOTH_HASH_THEN_RAW:
        return [hashed, normalized]
    return [normalized, hashed]


def _as_email_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [_normalize_email(value)]
    if isinstance(value, list):
        return [_normalize_email(item) for item in value if str(item).strip()]
    return []


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _validate_extra_headers(headers: dict[str, Any]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for name, value in headers.items():
        header_name = str(name).strip()
        header_value = str(value).strip()
        if not header_name:
            continue
        if "\n" in header_name or "\r" in header_name or "\n" in header_value or "\r" in header_value:
            raise HomeAssistantError("Invalid newline in custom headers")
        if header_name.lower() in DISALLOWED_EXTRA_HEADERS:
            raise HomeAssistantError(f"Header {header_name} is not allowed")
        sanitized[header_name] = header_value
    return sanitized


def _certificate_emails(cert: x509.Certificate) -> list[str]:
    emails: set[str] = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for addr in san.get_values_for_type(x509.RFC822Name):
            emails.add(_normalize_email(addr))
    except x509.ExtensionNotFound:
        pass

    for attr in cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS):
        emails.add(_normalize_email(attr.value))
    return sorted(emails)


def _validate_recipient_certificate(cert: x509.Certificate, recipient_email: str) -> None:
    now = datetime.now(UTC)
    if cert.not_valid_after_utc <= now:
        raise HomeAssistantError("Recipient certificate is expired")

    emails = _certificate_emails(cert)
    normalized = _normalize_email(recipient_email)
    if normalized not in emails:
        raise HomeAssistantError("Recipient email is not present in certificate")

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.EMAIL_PROTECTION not in eku:
            raise HomeAssistantError("Recipient certificate is not valid for S/MIME email protection")
    except x509.ExtensionNotFound:
        _LOGGER.debug("Recipient certificate has no EKU extension; accepting certificate")


def _load_certificates_from_bytes(raw: bytes) -> list[x509.Certificate]:
    data = raw.strip()
    certs: list[x509.Certificate] = []

    if b"-----BEGIN CERTIFICATE-----" in data:
        start_marker = b"-----BEGIN CERTIFICATE-----"
        end_marker = b"-----END CERTIFICATE-----"
        cursor = 0
        while True:
            begin = data.find(start_marker, cursor)
            if begin < 0:
                break
            end = data.find(end_marker, begin)
            if end < 0:
                break
            end += len(end_marker)
            certs.append(x509.load_pem_x509_certificate(data[begin:end]))
            cursor = end
        return certs

    try:
        certs.append(x509.load_der_x509_certificate(data))
        return certs
    except Exception as err:
        raise HomeAssistantError("Unable to parse certificate data") from err


def _load_first_certificate(raw: bytes) -> x509.Certificate:
    certs = _load_certificates_from_bytes(raw)
    if not certs:
        raise HomeAssistantError("No certificate found")
    return certs[0]


# ---------------------------------------------------------------------------
# Home Assistant notify platform entry point
# ---------------------------------------------------------------------------


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the S/MIME notify entity from a config entry."""
    manager: SmimeNotifyManager = hass.data[DOMAIN][config_entry.entry_id][DATA_MANAGER]
    async_add_entities([SmimeNotifyEntity(manager)])


class SmimeNotifyEntity(NotifyEntity):
    """S/MIME Notify entity that sends signed/encrypted emails via SMTP."""

    _attr_should_poll = False
    _attr_has_entity_name = False

    def __init__(self, manager: SmimeNotifyManager) -> None:
        self._manager = manager
        self._attr_unique_id = f"{manager.entry.entry_id}_notify"
        # Use the configured service name as the entity name so the HA service
        # is reachable as notify.<notify_service_name>.
        self._attr_name = manager.notify_service_name

    async def async_send_message(
        self,
        message: str,
        title: str | None = None,
        target: list[str] | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Send a message via S/MIME-capable SMTP."""
        payload = data or {}
        html = payload.get("html")
        if not html:
            html = f"<p>{html_lib.escape(message)}</p>"

        recipients = list(target or [])
        if not recipients:
            default_recipient = str(self._manager.config.get(CONF_DEFAULT_RECIPIENT) or "").strip()
            if default_recipient:
                recipients = [default_recipient]

        if not recipients:
            raise HomeAssistantError(
                "No target provided and no default_recipient configured"
            )

        await self._manager._send_message(
            title=title or "",
            plaintext=message,
            html=html,
            to=recipients,
            cc=_as_email_list(payload.get("cc")),
            bcc=_as_email_list(payload.get("bcc")),
            reply_to=payload.get("reply_to"),
            attachments=_as_string_list(payload.get("attachments")),
            extra_headers=_validate_extra_headers(payload.get("headers") or {}),
            sign=payload.get("sign"),
            encrypt=payload.get("encrypt"),
            allow_unencrypted_fallback=payload.get("allow_unencrypted_fallback"),
            skip_recipients_without_cert=payload.get("skip_recipients_without_cert"),
            service_context="notify_entity",
        )
