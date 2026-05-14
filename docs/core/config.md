# Config

In the library, configuration is a `ForwarderConfig` dataclass per
forwarder. `ProtoPokeAPI` takes a list of them and wires up the shared
session registry, event bus, tamper controller, and rules engine.

## ForwarderConfig

```python
from protopoke.config import ForwarderConfig

fwd = ForwarderConfig(
    name="Default",
    listen_host="127.0.0.1",
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | str | `"Forwarder"` | Human-readable label |
| `enabled` | bool | `True` | Include in "start all" |
| `forwarder_type` | str / `ForwarderType` | `"tcp"` | `"tcp"`, `"udp"`, or `"socks5"` |
| `listen_host` | str | `"127.0.0.1"` | Bind address |
| `listen_port` | int | `8080` | Listen port |
| `upstream_host` | str | `"127.0.0.1"` | Target host (ignored by SOCKS5) |
| `upstream_port` | int | `9090` | Target port (ignored by SOCKS5) |
| `connect_timeout` | float | `10.0` | Upstream connection timeout |
| `read_buffer_size` | int | `4096` | Read buffer size |
| `socks_auth_user` | str | `None` | SOCKS5 username (`None` = no-auth) |
| `socks_auth_pass` | str | `None` | SOCKS5 password |
| `max_sessions` | int | `0` | Max concurrent sessions (`0` = unlimited) |
| `keep_upstream_on_client_disconnect` | bool | `True` | Keep upstream open after the client disconnects (→ `ONLY_SERVER`). TCP/SOCKS5 only |
| `keep_client_on_server_disconnect` | bool | `True` | Keep the client writable after the server disconnects (→ `ONLY_CLIENT`). TCP/SOCKS5 only |
| `tamper_enabled` | bool | `False` | Enable intercept on startup |
| `framer_name` | str | `"raw"` | `raw`, `delimiter`, `length_prefix`, `line` (UDP is always `raw`) |
| `framer_kwargs` | dict | `{}` | Framer-specific parameters |
| `custom_framer_path` | str | `None` | Path to a custom framer script |
| `protocol_definition_path` | str | `None` | Protocol definition file path |
| `log_level` | str | `"INFO"` | Logging level for this forwarder |
| `tls_listen` | bool | `False` | TLS MITM on the client side (rejected for UDP/SOCKS5) |
| `tls_upstream` | bool | `False` | Connect to the upstream over TLS |
| `ca_cert_path` / `ca_key_path` | str | `None` | Custom CA (auto-generated at `~/.protopoke/ca.*` when unset) |
| `tls_cert_path` / `tls_key_path` | str | `None` | Fixed leaf cert/key (skips the auto-CA) |

## Transport types

```python
# Plain TCP proxy (default)
tcp = ForwarderConfig(name="tcp", listen_port=8080,
                      upstream_host="10.0.0.1", upstream_port=9090)

# UDP proxy — one session per (client_host, client_port) flow.
# Always uses the raw framer; cannot use tls_listen.
udp = ForwarderConfig(name="dns", forwarder_type="udp", listen_port=5353,
                      upstream_host="1.1.1.1", upstream_port=53)

# SOCKS5 proxy — the upstream target comes from each client's CONNECT
# request, so upstream_host / upstream_port are ignored.
socks = ForwarderConfig(name="socks", forwarder_type="socks5",
                        listen_port=1080,
                        socks_auth_user="user", socks_auth_pass="pass")
```

### TLS / MITM

```python
fwd = ForwarderConfig(
    name="https",
    listen_port=8443,
    upstream_host="api.example.com",
    upstream_port=443,
    tls_listen=True,      # terminate TLS from the client (MITM)
    tls_upstream=True,    # re-encrypt to the upstream
)
```

On first use a root CA is generated at `~/.protopoke/ca.crt` / `ca.key` and
reused across restarts. The client must trust that CA. Export it once TLS
listening is active:

```python
# api.ca is the active CertificateAuthority (set when tls_listen is on
# in auto-CA mode); cert_pem is the PEM-encoded CA certificate.
with open("protopoke-ca.crt", "wb") as f:
    f.write(api.ca.cert_pem)
```

Upstream certificate verification is intentionally disabled — ProtoPoke is a
reverse-engineering tool, not a production proxy.

## Multiple forwarders

```python
api = ProtoPokeAPI([
    ForwarderConfig(name="Service A", listen_port=8080,
                    upstream_host="10.0.0.1", upstream_port=9090),
    ForwarderConfig(name="Service B", listen_port=8081,
                    upstream_host="10.0.0.2", upstream_port=9091),
])
await api.start()

# Control individual forwarders
await api.start_forwarder("Service A")
await api.stop_forwarder("Service B")
print(api.is_running("Service A"), api.list_running())
```

## Serialising a config

```python
fwd.save("forwarder_config.json")
fwd = ForwarderConfig.load("forwarder_config.json")
```

## Projects

There is no database — sessions and frames live in memory for the life of
the process. To persist a whole working set, use `ProjectManager`, which
bundles forwarders, rules, playbooks, captured traffic, display filters, and
MCP settings into a single `.pp` ZIP archive.

```python
from protopoke.project.manager import ProjectManager

pm = ProjectManager()
pm.new("My Capture")
pm.forwarders[0].listen_port = 9000
pm.save_as("/path/to/project.pp")
pm.save()                                   # re-save to the same path

pm2 = ProjectManager()
state = pm2.open("/path/to/project.pp")
# state.forwarders, state.rules_engine, state.intercept_filter,
# state.playbooks, state.captured_sessions, state.mcp_settings, ...
```

A `.pp` archive contains `project.json`, `forwarders.json`, `rules.json`,
`forge.json`, `logs.json`, `filters.json`, and `mcp.json`. It carries a
`format_version` (currently **7**); opening a file from a newer ProtoPoke
raises an error, older formats are migrated forward where possible. Loading
is bounded for safety (max 32 members, 100 MB per member).

## Next

- [Traffic](traffic.md) — sessions, events, and decoding frames
- [User Interface — Config](../ui/config.md) — the same, in the TUI
