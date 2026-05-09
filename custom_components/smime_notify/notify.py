"""Notification handling for S/MIME Notify."""

from __future__ import annotations

import base64
import hashlib
import html as html_lib
import logging
import mimetypes
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import aiosmtplib
import dns.exception
import dns.flags
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from homeassistant.components.notify import NotifyEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.exceptions import HomeAssistantError
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
    CONF_LOCAL_SOURCE_ENABLED,
    CONF_INCLUDE_CERT_CHAIN,
    CONF_LOCAL_CERT_DIR,
    CONF_NOTIFY_SERVICE_NAME,
    CONF_REMOTE_BASE_URL,
    CONF_REMOTE_SOURCE_ENABLED,
    CONF_REMOTE_TIMEOUT,
    CONF_SMIMEA_SOURCE_ENABLED,
    CONF_SOURCE_ORDER,
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
    DEFAULT_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
    DEFAULT_ENCRYPT_DEFAULT,
    DEFAULT_FROM_NAME,
    DEFAULT_INCLUDE_CERT_CHAIN,
    DEFAULT_LOCAL_CERT_DIR,
    DEFAULT_REMOTE_SOURCE_ENABLED,
    DEFAULT_REMOTE_TIMEOUT,
    DEFAULT_SMIMEA_SOURCE_ENABLED,
    DEFAULT_SOURCE_ORDER,
    DEFAULT_SIGN_DEFAULT,
    DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
    DOMAIN,
    DEFAULT_CERT_EXPIRY_WARNING_DAYS,
    DEFAULT_HASH_MODE,
    DEFAULT_LOCAL_FILE_TYPES,
    DEFAULT_NOTIFY_SERVICE_NAME,
    HASH_MODE_BOTH_HASH_THEN_RAW,
    HASH_MODE_RAW_EMAIL,
    HASH_MODE_SHA256_EMAIL_HEX,
    SMTP_ENCRYPTION_SSL,
    SMTP_ENCRYPTION_SSL_LEGACY,
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
    attempted_locations: list[str] | None = None
    ttl: int | None = None
    dnssec_ad: bool | None = None
    smimea_name: str | None = None
    smimea_usage: int | None = None
    smimea_selector: int | None = None
    smimea_matching_type: int | None = None
    record_count: int | None = None


@dataclass
class CachedRecipientCertResult:
    """Cached recipient certificate result with optional expiration."""

    result: RecipientCertResult
    expires_at: float | None


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
        self._cert_cache: dict[str, CachedRecipientCertResult] = {}

    @property
    def config(self) -> dict[str, Any]:
        merged = {**self.entry.data, **self.entry.options}
        merged.setdefault(CONF_FILE_TYPES, DEFAULT_LOCAL_FILE_TYPES)
        merged.setdefault(CONF_HASH_MODE, DEFAULT_HASH_MODE)
        merged.setdefault(CONF_FROM_NAME, DEFAULT_FROM_NAME)
        merged.setdefault(CONF_SIGN_DEFAULT, DEFAULT_SIGN_DEFAULT)
        merged.setdefault(CONF_ENCRYPT_DEFAULT, DEFAULT_ENCRYPT_DEFAULT)
        merged.setdefault(
            CONF_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
            DEFAULT_ALLOW_UNENCRYPTED_FALLBACK_DEFAULT,
        )
        merged.setdefault(
            CONF_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
            DEFAULT_SKIP_RECIPIENTS_WITHOUT_CERT_DEFAULT,
        )
        merged.setdefault(CONF_INCLUDE_CERT_CHAIN, DEFAULT_INCLUDE_CERT_CHAIN)
        merged.setdefault(CONF_LOCAL_SOURCE_ENABLED, True)
        merged.setdefault(CONF_LOCAL_CERT_DIR, DEFAULT_LOCAL_CERT_DIR)
        merged.setdefault(CONF_SOURCE_ORDER, DEFAULT_SOURCE_ORDER)
        merged.setdefault(CONF_SMIMEA_SOURCE_ENABLED, DEFAULT_SMIMEA_SOURCE_ENABLED)
        merged.setdefault(CONF_REMOTE_SOURCE_ENABLED, DEFAULT_REMOTE_SOURCE_ENABLED)
        merged.setdefault(CONF_REMOTE_TIMEOUT, DEFAULT_REMOTE_TIMEOUT)
        return merged

    @property
    def notify_service_name(self) -> str:
        name = str(
            self.config.get(CONF_NOTIFY_SERVICE_NAME, DEFAULT_NOTIFY_SERVICE_NAME)
        ).strip()
        return slugify(name) or DEFAULT_NOTIFY_SERVICE_NAME

    async def async_reload_certificates(self) -> None:
        """Reload sender cert/key from disk."""
        self._sender_material = None
        await self.async_validate_sender_material()
        _LOGGER.info("S/MIME sender certificates reloaded")

    async def async_validate_sender_material(self) -> None:
        """Validate sender cert and key are loadable and matching."""
        material = await self.hass.async_add_executor_job(self._load_sender_material)
        self._sender_material = material

        now = datetime.now(UTC)
        warn_delta = timedelta(
            days=int(
                self.config.get(
                    CONF_CERT_EXPIRY_WARNING_DAYS, DEFAULT_CERT_EXPIRY_WARNING_DAYS
                )
            )
        )
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
            _LOGGER.warning(
                "Local recipient certificate directory does not exist: %s", cert_dir
            )

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
                "Recipient certificate not found for %s. Active sources=%s source=%s location=%s error=%s attempted=%s smimea_name=%s records=%s ttl=%s dnssec_ad=%s",
                email,
                self._active_source_order(),
                result.source,
                result.location,
                result.error,
                result.attempted_locations,
                result.smimea_name,
                result.record_count,
                result.ttl,
                _format_dnssec_ad(result.dnssec_ad),
            )
            raise HomeAssistantError(
                f"No valid recipient certificate found for {email}: {result.error or 'certificate not found'}"
            )

        cert = result.certificate
        _LOGGER.info(
            "Recipient certificate found for %s\n"
            "Source: %s\n"
            "SMIMEA name: %s\n"
            "SMIMEA usage/selector/matching_type: %s/%s/%s\n"
            "Subject: %s\n"
            "Issuer: %s\n"
            "Not valid before: %s\n"
            "Not valid after: %s\n"
            "Email addresses: %s\n"
            "S/MIME suitable: yes\n"
            "DNS TTL: %s\n"
            "DNSSEC AD: %s",
            email,
            result.source,
            result.smimea_name or "n/a",
            result.smimea_usage if result.smimea_usage is not None else "n/a",
            result.smimea_selector if result.smimea_selector is not None else "n/a",
            result.smimea_matching_type
            if result.smimea_matching_type is not None
            else "n/a",
            cert.subject.rfc4514_string(),
            cert.issuer.rfc4514_string(),
            cert.not_valid_before_utc.isoformat(),
            cert.not_valid_after_utc.isoformat(),
            ", ".join(_certificate_emails(cert)),
            result.ttl if result.ttl is not None else "n/a",
            _format_dnssec_ad(result.dnssec_ad),
        )

    async def async_send_service(self, call: ServiceCall) -> None:
        """Handle smime_notify.send service calls."""
        await self.async_send_smime_mail(call.data, service_context="send")

    async def async_send_notify_service(self, call: ServiceCall) -> None:
        """Handle notify.<service_name> calls."""
        data = call.data
        payload = data.get("data") or {}
        send_payload = {
            "title": data.get("title"),
            "message": data.get("message"),
            "html": payload.get("html"),
            "target": data.get("target"),
            "cc": payload.get("cc"),
            "bcc": payload.get("bcc"),
            "reply_to": payload.get("reply_to"),
            "attachments": payload.get("attachments"),
            "headers": payload.get("headers") or {},
            "sign": payload.get("sign"),
            "encrypt": payload.get("encrypt"),
            "allow_unencrypted_fallback": payload.get("allow_unencrypted_fallback"),
            "skip_recipients_without_cert": payload.get("skip_recipients_without_cert"),
        }
        await self.async_send_smime_mail(send_payload, service_context="notify")

    async def async_send_smime_mail(
        self, payload: dict[str, Any], *, service_context: str
    ) -> None:
        """Normalize service payload and send S/MIME mail."""
        title = str(payload.get("title") or "")
        plaintext = str(payload.get("message") or "")
        if not plaintext:
            raise HomeAssistantError("Plaintext body is required")

        html = payload.get("html")
        if not html:
            html = f"<p>{html_lib.escape(plaintext)}</p>"

        target = _as_email_list(payload.get("target"))
        if not target:
            default_recipient = str(
                self.config.get(CONF_DEFAULT_RECIPIENT, "") or ""
            ).strip()
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
            service_context=service_context,
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
        encrypt_flag = (
            self.config[CONF_ENCRYPT_DEFAULT] if encrypt is None else bool(encrypt)
        )
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
        all_recipients = (
            recipient_groups["to"] + recipient_groups["cc"] + recipient_groups["bcc"]
        )
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
                    missing_cert_errors[email] = (
                        cert_result.error or "certificate not found"
                    )

            if missing_cert_errors and skip_missing:
                for group_name in ("to", "cc", "bcc"):
                    recipient_groups[group_name] = [
                        email
                        for email in recipient_groups[group_name]
                        if email not in missing_cert_errors
                    ]
                if not any(recipient_groups.values()):
                    raise HomeAssistantError(
                        "Encryption requested but no recipients remain after skipping missing certificates"
                    )
                _LOGGER.warning(
                    "Skipping recipients without certificate: %s",
                    sorted(missing_cert_errors),
                )
            elif missing_cert_errors and not allow_fallback:
                missing_text = "; ".join(
                    f"{email}: {error}" for email, error in missing_cert_errors.items()
                )
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
            signed_der = await self.hass.async_add_executor_job(
                self._sign_data, base_bytes
            )
            if encrypt_flag:
                ordered_recipients = (
                    recipient_groups["to"]
                    + recipient_groups["cc"]
                    + recipient_groups["bcc"]
                )
                encrypted_der = await self.hass.async_add_executor_job(
                    self._encrypt_data,
                    signed_der,
                    [recipient_certs[email] for email in ordered_recipients],
                )
                final_message = self._build_pkcs7_wrapper(
                    base_message, encrypted_der, smime_type="enveloped-data"
                )
            else:
                final_message = self._build_pkcs7_wrapper(
                    base_message, signed_der, smime_type="signed-data"
                )
        elif encrypt_flag:
            ordered_recipients = (
                recipient_groups["to"]
                + recipient_groups["cc"]
                + recipient_groups["bcc"]
            )
            encrypted_der = await self.hass.async_add_executor_job(
                self._encrypt_data,
                base_bytes,
                [recipient_certs[email] for email in ordered_recipients],
            )
            final_message = self._build_pkcs7_wrapper(
                base_message, encrypted_der, smime_type="enveloped-data"
            )
        else:
            _LOGGER.warning(
                "Sending message without signing and encryption (context=%s).",
                service_context,
            )
            final_message = base_message

        await self._async_send_smtp(
            message=final_message,
            recipients=recipient_groups["to"]
            + recipient_groups["cc"]
            + recipient_groups["bcc"],
        )

    async def _async_send_smtp(
        self, message: EmailMessage, recipients: list[str]
    ) -> None:
        cfg = self.config
        encryption_mode = cfg[CONF_SMTP_ENCRYPTION]
        if encryption_mode == SMTP_ENCRYPTION_SSL_LEGACY:
            encryption_mode = SMTP_ENCRYPTION_SSL
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
            await smtp.sendmail(
                str(cfg[CONF_FROM_EMAIL]), recipients, message.as_bytes(policy=SMTP)
            )
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

    def _build_pkcs7_wrapper(
        self, base_message: EmailMessage, pkcs7_der: bytes, *, smime_type: str
    ) -> EmailMessage:
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
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=password_bytes
        )
        signing_cert = certs[0]
        self._assert_private_key_matches_certificate(private_key, signing_cert)

        return SenderMaterial(
            signing_cert=signing_cert,
            additional_certs=certs[1:],
            private_key=private_key,
        )

    def _assert_private_key_matches_certificate(
        self, private_key: Any, cert: x509.Certificate
    ) -> None:
        cert_public = cert.public_key()
        private_public = private_key.public_key()

        if isinstance(cert_public, rsa.RSAPublicKey) and isinstance(
            private_public, rsa.RSAPublicKey
        ):
            if cert_public.public_numbers() != private_public.public_numbers():
                raise HomeAssistantError(
                    "Private key does not match signing certificate"
                )
            return
        if isinstance(cert_public, ec.EllipticCurvePublicKey) and isinstance(
            private_public, ec.EllipticCurvePublicKey
        ):
            if cert_public.public_numbers() != private_public.public_numbers():
                raise HomeAssistantError(
                    "Private key does not match signing certificate"
                )
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
        builder = builder.add_signer(
            material.signing_cert, material.private_key, hashes.SHA256()
        )
        if self.config.get(CONF_INCLUDE_CERT_CHAIN, True):
            for cert in material.additional_certs:
                builder = builder.add_certificate(cert)

        return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])

    def _encrypt_data(
        self, data: bytes, recipient_certs: list[x509.Certificate]
    ) -> bytes:
        builder = pkcs7.PKCS7EnvelopeBuilder().set_data(data)
        for cert in recipient_certs:
            builder = builder.add_recipient(cert)
        return builder.encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])

    async def _async_resolve_recipient_certificate(
        self, email: str
    ) -> RecipientCertResult:
        cached = self._cert_cache.get(email)
        now = time.monotonic()
        if cached and (cached.expires_at is None or cached.expires_at > now):
            _LOGGER.debug(
                "Recipient certificate cache hit for %s from %s",
                email,
                cached.result.source,
            )
            return cached.result
        if cached:
            _LOGGER.debug("Recipient certificate cache expired for %s", email)
            self._cert_cache.pop(email, None)

        source_order = self._active_source_order()
        _LOGGER.debug(
            "Recipient certificate lookup for %s using sources: %s", email, source_order
        )
        failures: list[str] = []
        last_result: RecipientCertResult | None = None

        for source in source_order:
            _LOGGER.debug(
                "Checking recipient certificate source %s for %s", source, email
            )
            if source == "local":
                if not self.config.get(CONF_LOCAL_SOURCE_ENABLED, True):
                    failures.append("local: disabled")
                    _LOGGER.debug("Local certificate source disabled for %s", email)
                    continue
                result = await self.hass.async_add_executor_job(
                    self._resolve_recipient_certificate_local, email
                )
            elif source == "smimea":
                if not self.config.get(CONF_SMIMEA_SOURCE_ENABLED, False):
                    failures.append("smimea: disabled")
                    _LOGGER.debug("SMIMEA certificate source disabled for %s", email)
                    continue
                result = await self.hass.async_add_executor_job(
                    self._resolve_recipient_certificate_smimea, email
                )
            elif source == "remote":
                if not self.config.get(CONF_REMOTE_SOURCE_ENABLED, False):
                    failures.append("remote: disabled")
                    _LOGGER.debug("Remote certificate source disabled for %s", email)
                    continue
                result = self._resolve_recipient_certificate_remote(email)
            else:
                failures.append(f"{source}: unknown source")
                _LOGGER.warning("Unknown recipient certificate source %s", source)
                continue

            last_result = result
            if result.certificate:
                expires_at = time.monotonic() + result.ttl if result.ttl else None
                self._cert_cache[email] = CachedRecipientCertResult(result, expires_at)
                _LOGGER.debug(
                    "Recipient certificate found for %s via %s; cache_ttl=%s",
                    email,
                    result.source,
                    result.ttl if result.ttl is not None else "none",
                )
                return result

            failures.append(f"{result.source or source}: {result.error or 'not found'}")
            _LOGGER.debug(
                "Recipient certificate source %s failed for %s: %s; attempted=%s",
                result.source or source,
                email,
                result.error,
                result.attempted_locations,
            )

        error = "; ".join(failures) or "certificate not found"
        return RecipientCertResult(
            email=email,
            certificate=None,
            source=last_result.source if last_result else None,
            location=last_result.location if last_result else None,
            error=error,
            attempted_locations=last_result.attempted_locations
            if last_result
            else None,
            smimea_name=last_result.smimea_name if last_result else None,
        )

    def _active_source_order(self) -> list[str]:
        configured = str(self.config.get(CONF_SOURCE_ORDER, DEFAULT_SOURCE_ORDER) or "")
        ordered = [
            item.strip().lower() for item in configured.split(",") if item.strip()
        ]
        for source, enabled in (
            ("local", self.config.get(CONF_LOCAL_SOURCE_ENABLED, True)),
            ("smimea", self.config.get(CONF_SMIMEA_SOURCE_ENABLED, False)),
            ("remote", self.config.get(CONF_REMOTE_SOURCE_ENABLED, False)),
        ):
            if enabled and source not in ordered:
                ordered.append(source)
        return ordered or ["local"]

    def _resolve_recipient_certificate_local(self, email: str) -> RecipientCertResult:
        cert_dir = Path(str(self.config.get(CONF_LOCAL_CERT_DIR) or "").strip())
        attempted: list[str] = []
        if not cert_dir.exists() or not cert_dir.is_dir():
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="local",
                location=str(cert_dir),
                error="local cert directory not found",
                attempted_locations=attempted,
            )

        file_types = self._validated_file_types()
        if not file_types:
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="local",
                location=str(cert_dir),
                error="no file types configured",
                attempted_locations=attempted,
            )

        for name in _candidate_names(
            email, str(self.config.get(CONF_HASH_MODE, DEFAULT_HASH_MODE))
        ):
            for file_type in file_types:
                candidate = cert_dir / f"{name}.{file_type}"
                attempted.append(str(candidate))
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
                        attempted_locations=attempted,
                    )
                return RecipientCertResult(
                    email=email,
                    certificate=cert,
                    source="local",
                    location=str(candidate),
                    attempted_locations=attempted,
                )

        return RecipientCertResult(
            email=email,
            certificate=None,
            source="local",
            location=str(cert_dir),
            error="certificate not found",
            attempted_locations=attempted,
        )

    def _resolve_recipient_certificate_smimea(self, email: str) -> RecipientCertResult:
        smimea_name = _build_smimea_owner_name(email)
        timeout = float(self.config.get(CONF_REMOTE_TIMEOUT, DEFAULT_REMOTE_TIMEOUT))
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)
        resolver_description = ",".join(resolver.nameservers) or "system resolver"
        _LOGGER.debug(
            "SMIMEA lookup for %s querying %s with resolver %s",
            email,
            smimea_name,
            resolver_description,
        )

        try:
            answer = resolver.resolve(smimea_name, "SMIMEA", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            _LOGGER.debug("SMIMEA name %s does not exist", smimea_name)
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="smimea",
                location=smimea_name,
                error=f"SMIMEA name queried was wrong or not found: {smimea_name}",
                attempted_locations=[smimea_name],
                smimea_name=smimea_name,
            )
        except dns.resolver.NoNameservers as err:
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="smimea",
                location=smimea_name,
                error=f"SMIMEA lookup failed: no usable nameservers ({err})",
                attempted_locations=[smimea_name],
                smimea_name=smimea_name,
            )
        except dns.exception.DNSException as err:
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="smimea",
                location=smimea_name,
                error=f"SMIMEA lookup failed: {err}",
                attempted_locations=[smimea_name],
                smimea_name=smimea_name,
            )

        ttl = int(answer.rrset.ttl) if answer.rrset is not None else None
        record_count = len(answer) if answer.rrset is not None else 0
        dnssec_ad = None
        if getattr(answer, "response", None) is not None:
            dnssec_ad = bool(answer.response.flags & dns.flags.AD)
            _LOGGER.debug(
                "SMIMEA lookup for %s returned AD=%s", email, str(dnssec_ad).lower()
            )
        else:
            _LOGGER.warning(
                "SMIMEA lookup for %s did not expose DNSSEC AD status", email
            )

        _LOGGER.debug(
            "SMIMEA lookup for %s name=%s found_records=%s ttl=%s",
            email,
            smimea_name,
            record_count,
            ttl,
        )

        if record_count == 0:
            return RecipientCertResult(
                email=email,
                certificate=None,
                source="smimea",
                location=smimea_name,
                error="SMIMEA record not found",
                attempted_locations=[smimea_name],
                ttl=ttl,
                dnssec_ad=dnssec_ad,
                smimea_name=smimea_name,
                record_count=0,
            )

        unsupported: list[str] = []
        for rdata in answer:
            usage = int(rdata.usage)
            selector = int(rdata.selector)
            matching_type = int(rdata.mtype)
            _LOGGER.debug(
                "SMIMEA record for %s usage/selector/matching_type=%s/%s/%s data_len=%s",
                email,
                usage,
                selector,
                matching_type,
                len(rdata.cert),
            )
            try:
                cert = _certificate_from_smimea_record_data(
                    usage, selector, matching_type, bytes(rdata.cert)
                )
                _LOGGER.debug(
                    "SMIMEA DER parsing succeeded for %s from %s", email, smimea_name
                )
                _validate_recipient_certificate(cert, email)
            except HomeAssistantError as err:
                _LOGGER.debug(
                    "SMIMEA certificate rejected for %s from %s: %s",
                    email,
                    smimea_name,
                    err,
                )
                unsupported.append(f"{usage}/{selector}/{matching_type}: {err}")
                continue
            except Exception as err:
                _LOGGER.debug(
                    "SMIMEA record found but certificate DER parsing failed for %s from %s: %s",
                    email,
                    smimea_name,
                    err,
                )
                unsupported.append(
                    f"{usage}/{selector}/{matching_type}: SMIMEA record found but certificate DER parsing failed: {err}"
                )
                continue

            return RecipientCertResult(
                email=email,
                certificate=cert,
                source="smimea",
                location=smimea_name,
                attempted_locations=[smimea_name],
                ttl=ttl,
                dnssec_ad=dnssec_ad,
                smimea_name=smimea_name,
                smimea_usage=usage,
                smimea_selector=selector,
                smimea_matching_type=matching_type,
                record_count=record_count,
            )

        return RecipientCertResult(
            email=email,
            certificate=None,
            source="smimea",
            location=smimea_name,
            error="; ".join(unsupported) or "no usable SMIMEA records found",
            attempted_locations=[smimea_name],
            ttl=ttl,
            dnssec_ad=dnssec_ad,
            smimea_name=smimea_name,
            record_count=record_count,
        )

    def _resolve_recipient_certificate_remote(self, email: str) -> RecipientCertResult:
        base_url = str(self.config.get(CONF_REMOTE_BASE_URL) or "").strip()
        sanitized_url = _sanitize_url_for_log(base_url) if base_url else ""
        attempted = [sanitized_url] if sanitized_url else []
        _LOGGER.debug(
            "Remote recipient certificate source for %s is configured but not implemented; base_url_configured=%s",
            email,
            bool(base_url),
        )
        return RecipientCertResult(
            email=email,
            certificate=None,
            source="remote",
            location=sanitized_url or None,
            error="remote certificate source is not implemented yet",
            attempted_locations=attempted,
        )

    def _validated_file_types(self) -> list[str]:
        configured = self.config.get(CONF_FILE_TYPES, DEFAULT_LOCAL_FILE_TYPES)
        file_types: list[str] = []
        for entry in configured:
            normalized = str(entry).strip().lower().lstrip(".")
            if normalized and all(ch.isalnum() for ch in normalized):
                file_types.append(normalized)
        return file_types


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the S/MIME notify entity for a config entry."""
    manager = hass.data[DOMAIN][entry.entry_id][DATA_MANAGER]
    async_add_entities([SmimeNotifyEntity(manager, entry)])


class SmimeNotifyEntity(NotifyEntity):
    """Notify entity for S/MIME email messages."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_icon = "mdi:email-lock"

    def __init__(self, manager: SmimeNotifyManager, entry: ConfigEntry) -> None:
        self._manager = manager
        self._attr_unique_id = entry.entry_id
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": entry.title,
            "manufacturer": "S/MIME Notify",
        }

    async def async_send_message(self, message: str, title: str | None = None) -> None:
        """Send a notification message through the configured S/MIME mailer."""
        await self._manager.async_send_smime_mail(
            {"title": title or "", "message": message}, service_context="notify_entity"
        )
        if hasattr(self, "_async_record_notification"):
            self._async_record_notification()


def _normalize_email(email: str) -> str:
    return str(email).strip().lower()


def _format_dnssec_ad(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return str(value).lower()


def _sha256_email(email: str) -> str:
    return hashlib.sha256(email.encode("utf-8")).hexdigest()


def _build_smimea_owner_name(email: str) -> str:
    """Build the RFC 8162 SMIMEA owner name for an email address."""
    normalized = _normalize_email(email)
    if "@" not in normalized:
        raise HomeAssistantError("Invalid email address for SMIMEA lookup")
    local_part, domain = normalized.rsplit("@", 1)
    local_part = local_part.strip().lower()
    domain = domain.strip().lower().rstrip(".")
    if not local_part or not domain:
        raise HomeAssistantError("Invalid email address for SMIMEA lookup")
    local_hash = hashlib.sha256(local_part.encode("utf-8")).hexdigest()[:56]
    return f"{local_hash}._smimecert.{domain}"


def _certificate_from_smimea_record_data(
    usage: int, selector: int, matching_type: int, cert_data: bytes
) -> x509.Certificate:
    """Return a certificate from supported SMIMEA certificate association data."""
    if usage != 3 or selector != 0 or matching_type != 0:
        raise HomeAssistantError(
            f"Unsupported SMIMEA usage/selector/matching_type: {usage}/{selector}/{matching_type}"
        )
    try:
        return x509.load_der_x509_certificate(cert_data)
    except Exception as err:
        raise HomeAssistantError(
            "SMIMEA record found but certificate DER parsing failed"
        ) from err


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


def _sanitize_url_for_log(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.username and not parsed.password:
        return url
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def _validate_extra_headers(headers: dict[str, Any]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for name, value in headers.items():
        header_name = str(name).strip()
        header_value = str(value).strip()
        if not header_name:
            continue
        if (
            "\n" in header_name
            or "\r" in header_name
            or "\n" in header_value
            or "\r" in header_value
        ):
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


def _validate_recipient_certificate(
    cert: x509.Certificate, recipient_email: str
) -> None:
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
            raise HomeAssistantError(
                "Recipient certificate is not valid for S/MIME email protection"
            )
    except x509.ExtensionNotFound:
        _LOGGER.debug(
            "Recipient certificate has no EKU extension; accepting certificate"
        )


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
