# TLS / MITM

ProtoPoke can terminate TLS on the client side (MITM mode) and optionally connect to the upstream server over TLS. This lets you intercept and modify encrypted traffic.

## How It Works

1. ProtoPoke generates a **root Certificate Authority** (CA) on first use
2. When a client connects, ProtoPoke dynamically generates a per-session certificate signed by the CA
3. The client trusts the CA certificate, so the TLS handshake succeeds
4. ProtoPoke decrypts client traffic, processes it (intercept, rules, etc.), then forwards it to the upstream — optionally re-encrypting with a separate TLS connection

```
Client ──TLS──▶ ProtoPoke ──TLS (optional)──▶ Upstream
         ↑ signed by CA        ↑ upstream cert verification disabled
```

## Configuration

=== "TUI"

    Config tab → enable **TLS Listen** and/or **TLS Upstream**

=== "Python API"

    ```python
    fwd = ForwarderConfig(
        listen_port=8080,
        upstream_host="api.example.com",
        upstream_port=443,
        tls_listen=True,        # MITM: terminate TLS from client
        tls_upstream=True,      # Connect to upstream over TLS
    )
    ```

=== "MCP"

    The MCP server runs embedded in the UI; configure TLS on the forwarder
    in the Config tab (or via the ``update_forwarder`` MCP tool), then start
    the forwarder. Launch with ``protopoke --mcp`` to expose the server at
    ``http://127.0.0.1:7878/mcp``.

## Installing the CA Certificate

For the MITM to work, clients must trust the ProtoPoke CA certificate.

### Export the CA Certificate

=== "MCP"

    ```
    get_ca_cert()
    ```

=== "Python API"

    ```python
    # api.ca is the active CertificateAuthority (None unless TLS-listen is on
    # in auto-CA mode). cert_pem is the PEM-encoded CA certificate.
    ca_pem = api.ca.cert_pem
    with open("protopoke-ca.crt", "wb") as f:
        f.write(ca_pem)
    ```

By default the CA certificate and key are auto-generated on first use and
stored at `~/.protopoke/ca.crt` and `~/.protopoke/ca.key`, so the same CA is
reused across proxy restarts. You can also provide your own CA certificate
and key via `ForwarderConfig`:

```python
fwd = ForwarderConfig(
    name="Default",
    ...,
    tls_listen=True,
    ca_cert_path="/path/to/ca.pem",
    ca_key_path="/path/to/ca-key.pem",
)
```

For a one-off leaf certificate (skipping the auto-CA entirely), set
`tls_cert_path` and `tls_key_path` instead — useful for wildcard certs or
certs the client already trusts unconditionally.

## Notes

- Upstream TLS certificate verification is always disabled in proxy mode — ProtoPoke is a reverse engineering tool, not a production proxy
- The CA is generated using `cryptography >= 41`
- Per-session certificates are generated on-the-fly and cached
- `tls_listen` is rejected for UDP forwarders (DTLS is not supported) and for SOCKS5 forwarders (wrapping the SOCKS handshake in TLS is non-standard)
