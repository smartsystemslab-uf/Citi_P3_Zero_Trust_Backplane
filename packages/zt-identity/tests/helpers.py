"""Test helpers: a throw-away SPIFFE-style CA and SVIDs (no SPIRE needed)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def now() -> datetime:
    return datetime.now(timezone.utc)


def make_ca(cn: str = "test-ca"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now() - timedelta(minutes=5)).not_valid_after(now() + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_svid(ca_key, ca_cert, uri: str | None, *, ca: bool = False, digital_signature: bool = True,
              valid_for: timedelta = timedelta(hours=1), start_offset: timedelta = timedelta(minutes=-1)):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svid")]))
         .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now() + start_offset).not_valid_after(now() + start_offset + valid_for)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature, False, False, False, False, ca, ca, False, False), critical=True))
    if uri:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False)
    return key, b.sign(ca_key, hashes.SHA256())


def pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
