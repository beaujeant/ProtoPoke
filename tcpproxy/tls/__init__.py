"""TLS/SSL support for tcpproxy."""

from .ca import CertificateAuthority, DEFAULT_CA_CERT_PATH, DEFAULT_CA_KEY_PATH
from .handler import TLSHandler

__all__ = [
    "CertificateAuthority",
    "DEFAULT_CA_CERT_PATH",
    "DEFAULT_CA_KEY_PATH",
    "TLSHandler",
]
