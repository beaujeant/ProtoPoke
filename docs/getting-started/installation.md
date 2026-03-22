# Installation

ProtoPoke requires **Python 3.11 or later**.

## Install from Source

### Using uv (recommended)

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke

uv venv
uv pip install -e ".[dev]"
```

### Using pip + venv

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

## Optional Extras

| Extra | Command | What it adds |
|-------|---------|-------------|
| `dev` | `pip install -e ".[dev]"` | pytest, pytest-asyncio, pytest-cov |
| `mcp` | `pip install -e ".[mcp]"` | MCP server support (`mcp >= 1.0`) |
| `all` | `pip install -e ".[all]"` | Everything above |

## Dependencies

### Runtime

| Package | Purpose |
|---------|---------|
| `cryptography >= 41` | TLS MITM: root CA generation, per-session certificate signing |
| `textual >= 0.80` | Terminal UI framework |
| `pyyaml >= 6.0` | YAML parsing for protocol definitions |

### Optional

| Package | Purpose |
|---------|---------|
| `mcp >= 1.0` | MCP server (`pip install "protopoke[mcp]"`) |

### Development

| Package | Purpose |
|---------|---------|
| `pytest >= 7.4` | Test runner |
| `pytest-asyncio >= 0.23` | Async test support |
| `pytest-cov >= 4.1` | Coverage reports |

## Verify Installation

```bash
# Launch the TUI
protopoke

# Run the test suite
pytest
```
