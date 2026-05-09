"""Tests for SMIMEA helper behavior."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from custom_components.smime_notify.notify import (
    _build_smimea_owner_name,
    _certificate_emails,
    _certificate_from_smimea_record_data,
)


def _build_test_cert(email: str) -> bytes:
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


if __name__ == "__main__":
    unittest.main()
