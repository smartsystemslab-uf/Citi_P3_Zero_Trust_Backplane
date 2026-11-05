"""X.509-SVID leaf validation and peer-identity extraction.

Chain building, signature and validity-period checks against the SPIRE trust
bundle are done by OpenSSL during the handshake (CERT_REQUIRED + the bundle as
the only trust anchors). This module adds the SPIFFE-specific checks from the
X509-SVID standard (exactly one spiffe:// URI SAN, leaf is not a CA,
digitalSignature key usage, no certificate-signing usage) and the
trust-domain / per-request expiry checks.
"""
from __future__ import annotations

import weakref
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from ..identity import AuthenticationError, VerifiedTransportIdentity


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def spiffe_id_of(cert: x509.Certificate) -> str:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound as exc:
        raise AuthenticationError("svid_missing_san") from exc
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise AuthenticationError("svid_uri_san_count", str(len(uris)))
    uri = uris[0]
    if not uri.startswith("spiffe://"):
        raise AuthenticationError("svid_uri_not_spiffe", uri)
    return uri


def validate_svid_leaf(cert: x509.Certificate, trust_domain: str) -> str:
    spiffe_id = spiffe_id_of(cert)
    td = spiffe_id[len("spiffe://"):].split("/", 1)[0]
    if td != trust_domain:
        raise AuthenticationError("svid_wrong_trust_domain", td)
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if bc.ca:
            raise AuthenticationError("svid_leaf_is_ca")
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound as exc:
        raise AuthenticationError("svid_missing_key_usage") from exc
    if not ku.digital_signature or ku.key_cert_sign or ku.crl_sign:
        raise AuthenticationError("svid_bad_key_usage")
    now = utcnow()
    if cert.not_valid_after_utc <= now or cert.not_valid_before_utc > now:
        raise AuthenticationError("svid_outside_validity")
    return spiffe_id


class PeerIdentityCache:
    """Caches the verified peer identity per TLS connection (SSLObject).

    The expensive part (DER parse + SVID checks) runs once per connection;
    expiry is re-checked on every request so a long-lived keep-alive
    connection cannot outlive the peer's SVID.
    """

    def __init__(self, trust_domain: str) -> None:
        self.trust_domain = trust_domain
        self._cache: "weakref.WeakKeyDictionary[Any, VerifiedTransportIdentity]" = weakref.WeakKeyDictionary()
        self.connections_seen = 0

    def identity_for(self, ssl_object: Any) -> VerifiedTransportIdentity:
        if ssl_object is None:
            raise AuthenticationError("transport_not_tls")
        ident = self._cache.get(ssl_object)
        if ident is None:
            der = ssl_object.getpeercert(binary_form=True)
            if not der:
                raise AuthenticationError("no_peer_certificate")
            cert = x509.load_der_x509_certificate(der)
            spiffe_id = validate_svid_leaf(cert, self.trust_domain)
            ident = VerifiedTransportIdentity(
                spiffe_id=spiffe_id,
                cert_serial=format(cert.serial_number, "x"),
                not_after=cert.not_valid_after_utc,
                connection_id=id(ssl_object),
            )
            self._cache[ssl_object] = ident
            self.connections_seen += 1
        if ident.not_after <= utcnow():
            raise AuthenticationError("transport_credential_expired", ident.spiffe_id)
        return ident
