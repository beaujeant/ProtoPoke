---
title: "Installation"
---

ProtoPoke requires **Python 3.11 or later** and runs on Linux, macOS, and
Windows.

## Get the source

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke
```

## Install with uv (recommended)

[uv](https://docs.astral.sh/uv/) is the fastest way to get a working
environment — it creates the virtualenv and installs dependencies in one go.

<Tabs>
  <Tab title="Linux">
    ```bash
    # Install uv if you don't have it
    curl -LsSf https://astral.sh/uv/install.sh | sh

    uv venv
    uv pip install -e .
    ```
  </Tab>
  <Tab title="macOS">
    ```bash
    # Install uv if you don't have it (or: brew install uv)
    curl -LsSf https://astral.sh/uv/install.sh | sh

    uv venv
    uv pip install -e .
    ```
  </Tab>
  <Tab title="Windows">
    ```powershell
    # Install uv if you don't have it
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

    uv venv
    uv pip install -e .
    ```
  </Tab>
</Tabs>

`uv venv` creates a `.venv` in the project directory. `uv run protopoke`
runs the TUI inside it without needing to activate anything; or activate the
venv the usual way (see below).

`pip install -e .` installs everything needed to **use** ProtoPoke. Only
contributors who run the test suite need the `dev` extra — see
[Optional extras](#optional-extras) below.

## Native installation (pip + venv)

If you would rather not use uv, the standard library `venv` plus `pip`
works everywhere.

<Tabs>
  <Tab title="Linux">
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate

    pip install -e .
    ```
  </Tab>
  <Tab title="macOS">
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate

    pip install -e .
    ```

    <Note>
      macOS ships an old system Python. Install a current one with
      `brew install python@3.12` (or [python.org](https://www.python.org/))
      and use that interpreter for `python3 -m venv`.
    </Note>
  </Tab>
  <Tab title="Windows">
    ```powershell
    py -3 -m venv .venv
    .venv\Scripts\activate

    pip install -e .
    ```

    <Tip>
      The Textual-based TUI works best in **Windows Terminal**. The legacy
      `conhost.exe` console has limited colour and key support.
    </Tip>
  </Tab>
</Tabs>

## Optional extras

| Extra | Command | What it adds |
|-------|---------|--------------|
| `dev` | `pip install -e ".[dev]"` | pytest, pytest-asyncio, pytest-cov |
| `mcp` | `pip install -e ".[mcp]"` | MCP server support (`mcp >= 1.0`) |
| `all` | `pip install -e ".[all]"` | Everything above |

With uv, replace `pip install` with `uv pip install`.

## Dependencies

### Runtime

| Package | Purpose |
|---------|---------|
| `cryptography >= 41` | TLS MITM: root CA generation, per-session certificate signing |
| `textual >= 0.80` | Terminal UI framework |
| `pyyaml >= 6.0` | YAML parsing for protocol definitions |

### Optional / development

| Package | Purpose |
|---------|---------|
| `mcp >= 1.0` | MCP server (`pip install "protopoke[mcp]"`) |
| `pytest >= 7.4` | Test runner |
| `pytest-asyncio >= 0.23` | Async test support |
| `pytest-cov >= 4.1` | Coverage reports |

## Verify the installation

```bash
# Launch the terminal UI
protopoke

# Run the test suite (requires the `dev` extra)
pytest
```

If `protopoke` is not on your `PATH`, make sure the virtualenv is activated
(or use `uv run protopoke`).

## Next steps

- Using the terminal UI? → [User Interface](/ui/getting-started)
- Scripting with Python? → [Core Library](/core/getting-started)
