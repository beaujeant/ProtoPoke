"""
Tests for TLS/SSL support.

Coverage:
    TestCertificateAuthority  — CA generation, save/load, get_or_create, leaf cert issuance
    TestTLSHandler            — SSLContext building (auto-CA, manual cert, upstream)
    TestTLSProxyIntegration   — End-to-end: TLS client → proxy → TLS server
                                and plain client → proxy → TLS server scenarios
"""

from __future__ import annotations

import asyncio
import os
import ssl
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from tcpproxy.config import ProxyConfig
from tcpproxy.core.proxy import ProxyEngine
from tcpproxy.tls.ca import CertificateAuthority, DEFAULT_CA_CERT_PATH, DEFAULT_CA_KEY_PATH
from tcpproxy.tls.handler import TLSHandler

from tests.conftest import free_port, echo_server_ctx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@asynccontextmanager
async def tls_echo_server_ctx(
    cert_pem: bytes,
    key_pem: bytes,
    host: str = "127.0.0.1",
):
    """Async context manager: TLS echo server using the supplied cert/key PEM bytes."""
    with (
        tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cf,
        tempfile.NamedTemporaryFile(delete=False, suffix=".key") as kf,
    ):
        cf.write(cert_pem)
        kf.write(key_pem)
        cert_path, key_path = cf.name, kf.name

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        server = await asyncio.start_server(handler, host, 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        try:
            yield host, port
        finally:
            server.close()
            await server.wait_closed()
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)


# ---------------------------------------------------------------------------
# TestCertificateAuthority
# ---------------------------------------------------------------------------

class TestCertificateAuthority:

    def test_generate_returns_ca_instance(self):
        ca = CertificateAuthority.generate()
        assert isinstance(ca, CertificateAuthority)

    def test_cert_pem_is_valid_pem(self):
        ca = CertificateAuthority.generate()
        pem = ca.cert_pem
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_key_pem_is_valid_pem(self):
        ca = CertificateAuthority.generate()
        pem = ca.key_pem
        assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    def test_ca_has_ca_true_constraint(self):
        ca = CertificateAuthority.generate()
        cert = x509.load_pem_x509_certificate(ca.cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_ca_subject_contains_tcpproxy(self):
        ca = CertificateAuthority.generate()
        cert = x509.load_pem_x509_certificate(ca.cert_pem)
        cn_values = [
            attr.value for attr in cert.subject
            if attr.oid == x509.oid.NameOID.COMMON_NAME
        ]
        assert any("tcpproxy" in v for v in cn_values)

    def test_save_and_load_roundtrip(self, tmp_path):
        ca = CertificateAuthority.generate()
        cert_path = str(tmp_path / "ca.crt")
        key_path  = str(tmp_path / "ca.key")
        ca.save(cert_path, key_path)

        assert Path(cert_path).exists()
        assert Path(key_path).exists()
        # key should be restricted
        assert (os.stat(key_path).st_mode & 0o777) == 0o600

        loaded = CertificateAuthority.load(cert_path, key_path)
        assert loaded.cert_pem == ca.cert_pem
        assert loaded.key_pem  == ca.key_pem

    def test_get_or_create_generates_if_missing(self, tmp_path):
        cert_path = str(tmp_path / "ca.crt")
        key_path  = str(tmp_path / "ca.key")
        ca = CertificateAuthority.get_or_create(cert_path, key_path)
        assert Path(cert_path).exists()
        assert Path(key_path).exists()
        assert isinstance(ca, CertificateAuthority)

    def test_get_or_create_loads_if_present(self, tmp_path):
        cert_path = str(tmp_path / "ca.crt")
        key_path  = str(tmp_path / "ca.key")
        ca1 = CertificateAuthority.get_or_create(cert_path, key_path)
        ca2 = CertificateAuthority.get_or_create(cert_path, key_path)
        # Should load the same cert — bytes match
        assert ca1.cert_pem == ca2.cert_pem

    def test_get_or_create_uses_default_paths_if_none(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "tcpproxy.tls.ca.DEFAULT_CA_CERT_PATH", str(tmp_path / "ca.crt")
        )
        monkeypatch.setattr(
            "tcpproxy.tls.ca.DEFAULT_CA_KEY_PATH", str(tmp_path / "ca.key")
        )
        ca = CertificateAuthority.get_or_create()
        assert ca is not None

    # --- Leaf cert issuance ---

    def test_issue_cert_for_dns_hostname(self):
        ca = CertificateAuthority.generate()
        cert_pem, key_pem = ca.issue_cert("example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert "example.com" in dns_names

    def test_issue_cert_for_ip_address(self):
        ca = CertificateAuthority.generate()
        import ipaddress
        cert_pem, key_pem = ca.issue_cert("127.0.0.1")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san_ext.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("127.0.0.1") in ips

    def test_issue_cert_is_signed_by_ca(self):
        ca = CertificateAuthority.generate()
        cert_pem, _ = ca.issue_cert("test.local")
        leaf = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
        # Issuer of leaf == subject of CA
        assert leaf.issuer == ca_cert.subject

    def test_issue_cert_has_ca_false(self):
        ca = CertificateAuthority.generate()
        cert_pem, _ = ca.issue_cert("leaf.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_issue_cert_cached(self):
        ca = CertificateAuthority.generate()
        pem1a, pem1b = ca.issue_cert("cached.test")
        pem2a, pem2b = ca.issue_cert("cached.test")
        assert pem1a == pem2a
        assert pem1b == pem2b

    def test_issue_cert_different_hosts_different_certs(self):
        ca = CertificateAuthority.generate()
        cert_a, _ = ca.issue_cert("host-a.test")
        cert_b, _ = ca.issue_cert("host-b.test")
        assert cert_a != cert_b


# ---------------------------------------------------------------------------
# TestTLSHandler
# ---------------------------------------------------------------------------

class TestTLSHandler:

    def test_no_tls_listen_ctx_is_none(self):
        cfg = ProxyConfig(tls_listen=False)
        h = TLSHandler(cfg)
        h.setup()
        assert h.get_listen_ssl_context() is None

    def test_no_tls_upstream_ctx_is_none(self):
        cfg = ProxyConfig(tls_upstream=False)
        h = TLSHandler(cfg)
        h.setup()
        assert h.get_upstream_ssl_context() is None

    def test_auto_ca_mode_creates_ca(self, tmp_path):
        cfg = ProxyConfig(
            tls_listen=True,
            upstream_host="example.com",
            ca_cert_path=str(tmp_path / "ca.crt"),
            ca_key_path=str(tmp_path / "ca.key"),
        )
        h = TLSHandler(cfg)
        h.setup()
        assert h.ca is not None
        assert isinstance(h.ca, CertificateAuthority)

    def test_auto_ca_mode_returns_ssl_context(self, tmp_path):
        cfg = ProxyConfig(
            tls_listen=True,
            upstream_host="example.com",
            ca_cert_path=str(tmp_path / "ca.crt"),
            ca_key_path=str(tmp_path / "ca.key"),
        )
        h = TLSHandler(cfg)
        h.setup()
        ctx = h.get_listen_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_manual_cert_mode_no_ca(self, tmp_path):
        # Generate a cert to use as manual cert
        ca = CertificateAuthority.generate()
        cert_pem, key_pem = ca.issue_cert("manual.test")
        cert_path = str(tmp_path / "manual.crt")
        key_path  = str(tmp_path / "manual.key")
        Path(cert_path).write_bytes(cert_pem)
        Path(key_path).write_bytes(key_pem)

        cfg = ProxyConfig(
            tls_listen=True,
            upstream_host="manual.test",
            tls_cert_path=cert_path,
            tls_key_path=key_path,
        )
        h = TLSHandler(cfg)
        h.setup()
        assert h.ca is None  # CA not used in manual mode
        ctx = h.get_listen_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_upstream_verify_enabled(self):
        cfg = ProxyConfig(tls_upstream=True, tls_upstream_verify=True)
        h = TLSHandler(cfg)
        ctx = h.get_upstream_ssl_context()
        assert ctx is not None
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_upstream_verify_disabled(self):
        cfg = ProxyConfig(tls_upstream=True, tls_upstream_verify=False)
        h = TLSHandler(cfg)
        ctx = h.get_upstream_ssl_context()
        assert ctx is not None
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False


# ---------------------------------------------------------------------------
# TestTLSProxyIntegration
# ---------------------------------------------------------------------------

class TestTLSProxyIntegration:
    """
    End-to-end tests using real TLS connections.

    The CA is generated fresh each test so tests are isolated and don't
    touch ~/.tcpproxy.
    """

    async def test_tls_listen_and_passthrough(self, tmp_path):
        """
        Client connects to proxy over TLS.
        Proxy forwards to a plain TCP echo server.
        """
        ca = CertificateAuthority.generate()
        ca_cert_path = str(tmp_path / "ca.crt")
        ca_key_path  = str(tmp_path / "ca.key")
        ca.save(ca_cert_path, ca_key_path)

        async with echo_server_ctx() as (up_host, up_port):
            listen_port = free_port()
            cfg = ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=listen_port,
                upstream_host=up_host,
                upstream_port=up_port,
                tls_listen=True,
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
            )
            engine = ProxyEngine(cfg)
            await engine.start()

            try:
                # Client trusts our proxy CA
                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_ctx.load_verify_locations(cadata=ca.cert_pem.decode())
                client_ctx.check_hostname = False  # 127.0.0.1 won't match CN anyway

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1", listen_port,
                        ssl=client_ctx,
                        server_hostname="127.0.0.1",
                    ),
                    timeout=5.0,
                )
                msg = b"hello tls proxy"
                writer.write(msg)
                await writer.drain()
                # TLS doesn't support half-close (write_eof raises NotImplementedError).
                # Read exactly what we sent (echo), then close the connection.
                data = await asyncio.wait_for(
                    reader.readexactly(len(msg)), timeout=3.0
                )
                assert data == msg
                writer.close()
            finally:
                await engine.stop()

    async def test_tls_upstream_insecure(self, tmp_path):
        """
        Proxy connects to a TLS upstream server with verify=False.
        The server uses a self-signed cert the proxy hasn't explicitly trusted.
        """
        ca = CertificateAuthority.generate()
        cert_pem, key_pem = ca.issue_cert("127.0.0.1")

        async with tls_echo_server_ctx(cert_pem, key_pem) as (up_host, up_port):
            listen_port = free_port()
            cfg = ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=listen_port,
                upstream_host=up_host,
                upstream_port=up_port,
                tls_upstream=True,
                tls_upstream_verify=False,  # accept the self-signed cert
            )
            engine = ProxyEngine(cfg)
            await engine.start()

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", listen_port),
                    timeout=5.0,
                )
                msg = b"hello upstream tls"
                writer.write(msg)
                await writer.drain()
                data = await asyncio.wait_for(
                    reader.readexactly(len(msg)), timeout=3.0
                )
                assert data == msg
                writer.close()
            finally:
                await engine.stop()

    async def test_tls_both_sides(self, tmp_path):
        """
        Client → TLS → proxy → TLS → server (both sides encrypted).
        """
        ca = CertificateAuthority.generate()
        ca_cert_path = str(tmp_path / "ca.crt")
        ca_key_path  = str(tmp_path / "ca.key")
        ca.save(ca_cert_path, ca_key_path)

        # Server uses a separate CA-signed cert
        server_cert_pem, server_key_pem = ca.issue_cert("127.0.0.1")

        async with tls_echo_server_ctx(server_cert_pem, server_key_pem) as (up_host, up_port):
            listen_port = free_port()
            cfg = ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=listen_port,
                upstream_host=up_host,
                upstream_port=up_port,
                tls_listen=True,
                tls_upstream=True,
                tls_upstream_verify=False,  # server uses same CA but no system trust
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
            )
            engine = ProxyEngine(cfg)
            await engine.start()

            try:
                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_ctx.load_verify_locations(cadata=ca.cert_pem.decode())
                client_ctx.check_hostname = False

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1", listen_port,
                        ssl=client_ctx,
                        server_hostname="127.0.0.1",
                    ),
                    timeout=5.0,
                )
                msg = b"double tls"
                writer.write(msg)
                await writer.drain()
                data = await asyncio.wait_for(
                    reader.readexactly(len(msg)), timeout=3.0
                )
                assert data == msg
                writer.close()
            finally:
                await engine.stop()

    async def test_manual_cert_listen(self, tmp_path):
        """
        Proxy uses a manually supplied cert (no auto-CA) on the listening side.
        """
        ca = CertificateAuthority.generate()
        cert_pem, key_pem = ca.issue_cert("127.0.0.1")
        cert_path = str(tmp_path / "manual.crt")
        key_path  = str(tmp_path / "manual.key")
        Path(cert_path).write_bytes(cert_pem)
        Path(key_path).write_bytes(key_pem)

        async with echo_server_ctx() as (up_host, up_port):
            listen_port = free_port()
            cfg = ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=listen_port,
                upstream_host=up_host,
                upstream_port=up_port,
                tls_listen=True,
                tls_cert_path=cert_path,
                tls_key_path=key_path,
            )
            engine = ProxyEngine(cfg)
            await engine.start()

            try:
                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_ctx.load_verify_locations(cadata=ca.cert_pem.decode())
                client_ctx.check_hostname = False

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1", listen_port,
                        ssl=client_ctx,
                        server_hostname="127.0.0.1",
                    ),
                    timeout=5.0,
                )
                msg = b"manual cert test"
                writer.write(msg)
                await writer.drain()
                data = await asyncio.wait_for(
                    reader.readexactly(len(msg)), timeout=3.0
                )
                assert data == msg
                writer.close()
            finally:
                await engine.stop()
