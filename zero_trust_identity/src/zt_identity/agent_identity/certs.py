"""Agent credential profile (B): X.509 certificates from a dedicated Agent CA.

The Agent CA is a separate trust root from the SPIRE workload CA. Each agent
certificate carries exactly one URI SAN `urn:citi-p3:agent:<agent_id>`, is a
non-CA leaf with digitalSignature usage, and is short-lived.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AttributeOID, ExtendedKeyUsageOID, ExtensionOID, NameOID

AGENT_URN_PREFIX = "urn:citi-p3:agent:"
RENEW_PROOF_CONTEXT = b"citi-p3-agent-renew/v1\x00"


class AgentCertError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def spki_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fingerprint(cert_der: bytes) -> str:
    return "sha256:" + hashlib.sha256(cert_der).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_ca(common_name: str, days: int = 30) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = new_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citi P3 AuthCmp (experiment only)"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def build_csr(key: ec.EllipticCurvePrivateKey, agent_id: str, nonce: str) -> bytes:
    """CSR = proof of possession of `key`; the issuer nonce makes it fresh."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
        .add_attribute(AttributeOID.CHALLENGE_PASSWORD, nonce.encode("ascii"))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def csr_nonce(csr: x509.CertificateSigningRequest) -> str:
    try:
        return csr.attributes.get_attribute_for_oid(AttributeOID.CHALLENGE_PASSWORD).value.decode("ascii")
    except (x509.AttributeNotFound, UnicodeDecodeError) as exc:
        raise AgentCertError("csr_missing_nonce") from exc


def renew_proof_material(csr_der: bytes, nonce: str) -> bytes:
    return RENEW_PROOF_CONTEXT + hashlib.sha256(csr_der).digest() + nonce.encode("ascii")


def sign_renew_proof(current_key: ec.EllipticCurvePrivateKey, csr_der: bytes, nonce: str) -> str:
    return b64u(current_key.sign(renew_proof_material(csr_der, nonce), ec.ECDSA(hashes.SHA256())))


def verify_renew_proof(cert: x509.Certificate, csr_der: bytes, nonce: str, proof_b64: str) -> None:
    try:
        cert.public_key().verify(b64u_dec(proof_b64), renew_proof_material(csr_der, nonce), ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise AgentCertError("renew_proof_invalid") from exc


def issue_agent_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    public_key,
    agent_id: str,
    ttl_seconds: int,
) -> x509.Certificate:
    now = utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citi P3 AuthCmp Agents"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(int.from_bytes(secrets.token_bytes(16), "big") >> 1)
        .not_valid_before(now - timedelta(seconds=5))
        .not_valid_after(now + timedelta(seconds=ttl_seconds))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(AGENT_URN_PREFIX + agent_id)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


@dataclass(frozen=True)
class VerifiedAgentCert:
    agent_id: str
    serial: str
    fingerprint: str
    not_after: datetime
    public_key: ec.EllipticCurvePublicKey


def verify_agent_cert(cert_der: bytes, ca_cert: x509.Certificate, *, now: datetime | None = None) -> VerifiedAgentCert:
    """Chain (single-level) + validity + profile checks for an agent certificate."""
    now = now or utcnow()
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        raise AgentCertError("agent_cert_malformed") from exc
    if cert.issuer != ca_cert.subject:
        raise AgentCertError("agent_cert_untrusted_issuer")
    try:
        cert.verify_directly_issued_by(ca_cert)          # signature + issuer/AKI checks
    except Exception as exc:
        raise AgentCertError("agent_cert_bad_signature") from exc
    if not (cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
        raise AgentCertError("agent_cert_outside_validity")
    if not (ca_cert.not_valid_before_utc <= now < ca_cert.not_valid_after_utc):
        raise AgentCertError("agent_ca_outside_validity")
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound as exc:
        raise AgentCertError("agent_cert_profile") from exc
    if bc.ca or not ku.digital_signature or ku.key_cert_sign:
        raise AgentCertError("agent_cert_profile")
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or not uris[0].startswith(AGENT_URN_PREFIX):
        raise AgentCertError("agent_cert_san")
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise AgentCertError("agent_cert_key_type")
    return VerifiedAgentCert(
        agent_id=uris[0][len(AGENT_URN_PREFIX):],
        serial=format(cert.serial_number, "x"),
        fingerprint=fingerprint(cert_der),
        not_after=cert.not_valid_after_utc,
        public_key=pub,
    )
