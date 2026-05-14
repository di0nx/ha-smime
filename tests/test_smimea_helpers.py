"""Tests for SMIMEA helper behavior."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from homeassistant.exceptions import HomeAssistantError

from custom_components.smime_notify.notify import (
    _build_smimea_owner_name,
    _certificate_emails,
    _certificate_from_smimea_record_data,
    SmimeNotifyManager,
    certificate_supports_pkcs7_recipient_encryption,
    get_public_key_type,
)


def _build_test_cert(email: str, key=None) -> bytes:
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SMIMEA Test")])
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SMIMEA Test")])
        )
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestSmimeaHelpers(unittest.TestCase):
    """Verify SMIMEA helper functions."""

    def test_smimea_owner_name_uses_truncated_local_part_hash(self) -> None:
        self.assertEqual(
            _build_smimea_owner_name("dion@kitsos.net"),
            "d55bcf8025bdb22b72cf95c0306748d814c0effe3859bddc00d2b1aa._smimecert.kitsos.net",
        )

    def test_smimea_300_der_parsing_loads_x509_certificate(self) -> None:
        cert = _certificate_from_smimea_record_data(
            3, 0, 0, _build_test_cert("dion@kitsos.net")
        )
        self.assertIn("dion@kitsos.net", _certificate_emails(cert))

    def test_ec_cert_is_not_supported_for_pkcs7_recipient_encryption(self) -> None:
        cert = _certificate_from_smimea_record_data(
            3, 0, 0, _build_test_cert("dion@kitsos.net")
        )
        self.assertEqual(get_public_key_type(cert), "EC")
        self.assertFalse(certificate_supports_pkcs7_recipient_encryption(cert))

    def test_rsa_cert_is_supported_for_pkcs7_recipient_encryption(self) -> None:
        cert = _certificate_from_smimea_record_data(
            3,
            0,
            0,
            _build_test_cert(
                "dion@kitsos.net",
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
            ),
        )
        self.assertEqual(get_public_key_type(cert), "RSA")
        self.assertTrue(certificate_supports_pkcs7_recipient_encryption(cert))

    def test_encrypt_data_rejects_ec_cert_before_pkcs7_backend(self) -> None:
        cert = _certificate_from_smimea_record_data(
            3, 0, 0, _build_test_cert("dion@kitsos.net")
        )
        manager = SmimeNotifyManager.__new__(SmimeNotifyManager)
        with self.assertRaisesRegex(HomeAssistantError, "only RSA"):
            manager._encrypt_data(b"test", [("dion@kitsos.net", cert)])


if __name__ == "__main__":
    unittest.main()
