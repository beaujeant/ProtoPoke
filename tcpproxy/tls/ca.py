"""
Certificate Authority management for TLS MITM (Burp-style).

The proxy acts as a man-in-the-middle:
  client → [proxy presents CA-signed cert] → proxy → [proxy connects with TLS] → server

The CA is generated once and persisted on disk.  For each unique hostname the
proxy encounters, it issues a short-lived leaf certificate signed by that CA.
The client must trust the proxy CA (install it as a trusted root) for the TLS
handshake to succeed without warnings — exactly the same workflow as Burp Suite.

Leaf certs are cached in-memory (keyed by hostname) so repeated connections to
the same host do not regenerate the cert and key each time.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import pathlib
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

# Default storage location – under the user's home directory so it persists
# across sessions and is not world-readable (key file is chmod 0o600).
_DEFAULT_DIR = os.path.expanduser("~/.tcpproxy")
DEFAULT_CA_CERT_PATH = os.path.join(_DEFAULT_DIR, "ca.crt")
DEFAULT_CA_KEY_PATH  = os.path.join(_DEFAULT_DIR, "ca.key")


class CertificateAuthority:
    """
    Root CA used to sign per-session leaf certificates.

    Typical usage::

        ca = CertificateAuthority.get_or_create()
        cert_pem, key_pem = ca.issue_cert("example.com")

    To use a custom CA location::

        ca = CertificateAuthority.get_or_create(
            cert_path="/path/to/my-ca.crt",
            key_path="/path/to/my-ca.key",
        )

    To load an existing CA (e.g. a corporate root that clients already trust)::

        ca = CertificateAuthority.load(cert_path, key_path)
    """

    def __init__(
        self,
        cert: x509.Certificate,
        key: rsa.RSAPrivateKey,
    ) -> None:
        self._cert = cert
        self._key  = key
        # hostname → (cert_pem, key_pem) — avoid re-generating for the same host
        self._cert_cache: dict[str, tuple[bytes, bytes]] = {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def cert_pem(self) -> bytes:
        """DER-encoded CA certificate in PEM format."""
        return self._cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        """PKCS#1 private key in PEM format (unencrypted)."""
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "CertificateAuthority":
        """Generate a new RSA-2048 self-signed root CA."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,         "tcpproxy CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,   "tcpproxy"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security Research"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        logger.info("Generated new proxy CA")
        return cls(cert, key)

    @classmethod
    def load(cls, cert_path: str, key_path: str) -> "CertificateAuthority":
        """Load an existing CA from PEM files on disk."""
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        with open(key_path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        logger.info("Loaded proxy CA from %s", cert_path)
        return cls(cert, key)  # type: ignore[arg-type]

    def save(self, cert_path: str, key_path: str) -> None:
        """Persist the CA cert and key to PEM files."""
        pathlib.Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(key_path).parent.mkdir(parents=True, exist_ok=True)
        with open(cert_path, "wb") as fh:
            fh.write(self.cert_pem)
        with open(key_path, "wb") as fh:
            fh.write(self.key_pem)
        os.chmod(key_path, 0o600)  # private key should not be world-readable
        logger.info("Saved proxy CA to %s", cert_path)

    @classmethod
    def get_or_create(
        cls,
        cert_path: Optional[str] = None,
        key_path:  Optional[str] = None,
    ) -> "CertificateAuthority":
        """
        Load the CA from disk if it already exists; otherwise generate a new
        one and save it so it is reused on the next startup.
        """
        cert_path = cert_path or DEFAULT_CA_CERT_PATH
        key_path  = key_path  or DEFAULT_CA_KEY_PATH
        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cls.load(cert_path, key_path)
        ca = cls.generate()
        ca.save(cert_path, key_path)
        return ca

    # ------------------------------------------------------------------
    # Leaf certificate issuance
    # ------------------------------------------------------------------

    def issue_cert(self, hostname: str) -> tuple[bytes, bytes]:
        """
        Issue a leaf certificate for *hostname* signed by this CA.

        Accepts both DNS names and IP addresses.  Results are cached by
        hostname so that repeated connections never regenerate the key pair.

        Returns:
            (cert_pem, key_pem) as bytes.
        """
        if hostname in self._cert_cache:
            return self._cert_cache[hostname]

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        # Build a Subject Alternative Name that matches the target
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            san = x509.DNSName(hostname)

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=397))  # ~13 months
            .add_extension(
                x509.SubjectAlternativeName([san]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        self._cert_cache[hostname] = (cert_pem, key_pem)
        logger.debug("Issued leaf cert for %s", hostname)
        return cert_pem, key_pem
