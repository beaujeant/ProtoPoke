"""
TLS handler — builds ssl.SSLContext objects for both sides of the proxy.

Listening side (client → proxy)
--------------------------------
When tls_listen=True the proxy presents a certificate to the client.
Two modes:

1. **Auto-CA mode** (default, Burp-style):
   A CA is loaded from / generated at ca_cert_path / ca_key_path.
   A leaf certificate for the upstream hostname is issued on-the-fly and
   signed by that CA.  The user must install the CA cert as a trusted root
   in their browser / OS / tool of choice.

2. **Manual cert mode**:
   Set tls_cert_path + tls_key_path to supply your own cert/key pair.
   The CA is not used and does not need to exist.

Upstream side (proxy → server)
--------------------------------
When tls_upstream=True the proxy connects to the server over TLS.
Set tls_upstream_verify=False to accept any server certificate (equivalent
to Burp's "Accept any certificate" option — useful for self-signed or
expired certs on internal services).
"""

from __future__ import annotations

import logging
import os
import ssl
import tempfile
from typing import TYPE_CHECKING, Optional
from weakref import WeakKeyDictionary

from .ca import CertificateAuthority

if TYPE_CHECKING:
    from ..config import ProxyConfig

logger = logging.getLogger(__name__)


class TLSHandler:
    """
    Owns all TLS state for one ProxyEngine instance.

    Call setup() once before starting the proxy.  After that use:
        get_listen_ssl_context()   → pass to asyncio.start_server()
        get_upstream_ssl_context() → pass to asyncio.open_connection()
    """

    def __init__(self, config: "ProxyConfig") -> None:
        self._config = config
        self._ca: Optional[CertificateAuthority] = None
        self._listen_ctx: Optional[ssl.SSLContext] = None
        # ssl.SSLObject → SNI server_name captured during the TLS handshake.
        # WeakKeyDictionary so entries are released automatically when the
        # ssl object is garbage-collected (i.e. the connection is gone).
        self._sni_map: WeakKeyDictionary = WeakKeyDictionary()
        # hostname → SSLContext built from a CA-signed cert for that hostname.
        # Avoids repeating temp-file I/O for repeated connections to the same host.
        self._host_ctx_cache: dict[str, ssl.SSLContext] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """
        Initialise the CA and build the listening SSL context.

        This is synchronous — cert generation is CPU-bound and fast enough
        that there is no benefit in making it async.
        """
        if not self._config.tls_listen:
            return

        if self._config.tls_cert_path and self._config.tls_key_path:
            # User supplied their own cert — skip CA entirely
            self._listen_ctx = self._ctx_from_files(
                self._config.tls_cert_path,
                self._config.tls_key_path,
            )
            logger.info("TLS listen: using user-supplied cert %s", self._config.tls_cert_path)
        else:
            # Auto-CA mode: load or generate the CA, then issue a leaf cert
            self._ca = CertificateAuthority.get_or_create(
                cert_path=self._config.ca_cert_path,
                key_path=self._config.ca_key_path,
            )
            self._listen_ctx = self._ctx_for_host(self._config.upstream_host)
            # Cache the default-host context so _sni_callback hits the cache too
            self._host_ctx_cache[self._config.upstream_host] = self._listen_ctx
            # Install the SNI callback so we issue a correctly-named cert for
            # every unique server_name the client presents in its ClientHello.
            self._listen_ctx.set_servername_callback(self._sni_callback)
            logger.info(
                "TLS listen: auto-CA mode; SNI-aware cert dispatch enabled (default host: %s)",
                self._config.upstream_host,
            )

    # ------------------------------------------------------------------
    # Public context accessors
    # ------------------------------------------------------------------

    def get_listen_ssl_context(self) -> Optional[ssl.SSLContext]:
        """
        Return the SSLContext for asyncio.start_server(), or None if TLS is
        disabled on the listening side.
        """
        return self._listen_ctx

    def get_upstream_ssl_context(self) -> Optional[ssl.SSLContext]:
        """
        Return the SSLContext for asyncio.open_connection(), or None if TLS is
        disabled on the upstream side.

        When tls_upstream_verify=False the context accepts any server cert
        (no hostname check, no chain validation).
        """
        if not self._config.tls_upstream:
            return None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        if self._config.tls_upstream_verify:
            ctx.verify_mode  = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            ctx.load_default_certs()
            logger.debug("TLS upstream: certificate verification enabled")
        else:
            ctx.check_hostname = False
            ctx.verify_mode  = ssl.CERT_NONE
            logger.debug("TLS upstream: certificate verification DISABLED")

        return ctx

    # ------------------------------------------------------------------
    # CA accessor (for tests and for exporting to the user)
    # ------------------------------------------------------------------

    @property
    def ca(self) -> Optional[CertificateAuthority]:
        """The active CA instance, or None when using a manual cert."""
        return self._ca

    def get_sni_hostname(self, ssl_object: Optional[ssl.SSLObject]) -> Optional[str]:
        """
        Return the SNI server_name captured during the TLS handshake for
        *ssl_object*, or None if no SNI was sent or TLS is not in use.

        Call this after the client connection is established (the handshake
        is complete by the time asyncio invokes the connection callback).
        """
        if ssl_object is None:
            return None
        try:
            return self._sni_map.get(ssl_object)
        except TypeError:
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sni_callback(
        self,
        ssl_object: ssl.SSLObject,
        server_name: Optional[str],
        original_ctx: ssl.SSLContext,
    ) -> None:
        """
        OpenSSL SNI callback — called during the TLS ClientHello.

        When the client announces a server_name extension, we:
        1. Store it in _sni_map so the connection handler can retrieve it.
        2. Issue (or fetch from cache) a CA-signed cert for that hostname.
        3. Swap the SSLContext on *ssl_object* so the client sees the
           correctly-named certificate instead of the default one.

        Returning None tells OpenSSL to continue the handshake.
        """
        if not server_name:
            return None

        # Capture the SNI for later retrieval by the connection handler
        try:
            self._sni_map[ssl_object] = server_name
        except TypeError:
            logger.debug("SNI map: ssl_object not weakly referenceable, skipping")

        # Build (or reuse) an SSLContext with a cert for this specific hostname
        try:
            ctx = self._host_ctx_cache.get(server_name)
            if ctx is None:
                ctx = self._ctx_for_host(server_name)
                self._host_ctx_cache[server_name] = ctx
            ssl_object.context = ctx
            logger.debug("SNI: issued cert and swapped context for %s", server_name)
        except Exception as exc:
            logger.error("SNI callback failed for %s: %s", server_name, exc)

        return None

    def _ctx_for_host(self, hostname: str) -> ssl.SSLContext:
        """Issue a CA-signed leaf cert for *hostname* and return an SSLContext."""
        assert self._ca is not None, "CA must be initialised before calling _ctx_for_host"
        cert_pem, key_pem = self._ca.issue_cert(hostname)

        # ssl.SSLContext.load_cert_chain() requires file paths, not raw bytes.
        # We write to NamedTemporaryFiles, load, then delete immediately.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cf:
            cf.write(cert_pem)
            cert_path = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as kf:
            kf.write(key_pem)
            key_path = kf.name

        try:
            return self._ctx_from_files(cert_path, key_path)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    @staticmethod
    def _ctx_from_files(cert_path: str, key_path: str) -> ssl.SSLContext:
        """Build a server-side SSLContext from PEM files."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx
