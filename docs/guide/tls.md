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

=== "MCP CLI"

    ```bash
    protopoke-mcp --tls-listen --tls-upstream \
        --upstream-host api.example.com --upstream-port 443
    ```

## Installing the CA Certificate

For the MITM to work, clients must trust the ProtoPoke CA certificate.

### Export the CA Certificate

=== "MCP"

    ```
    get_ca_cert()
    ```

=== "Python API"

    ```python
    ca_pem = api.get_ca_cert()
    ```

The CA certificate and key are auto-generated and stored in memory by default. You can also provide your own CA certificate and key via `ForwarderConfig`:

```python
fwd = ForwarderConfig(
    name="Default",
    ...,
    tls_listen=True,
    ca_cert_path="/path/to/ca.pem",
    ca_key_path="/path/to/ca-key.pem",
)
```

## Notes

- Upstream TLS certificate verification is always disabled in proxy mode — ProtoPoke is a reverse engineering tool, not a production proxy
- The CA is generated using `cryptography >= 41`
- Per-session certificates are generated on-the-fly and cached
