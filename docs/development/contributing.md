# Contributing

## Setup

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
pytest

# Single file
pytest tests/test_framing.py

# Single test
pytest -k test_length_prefix

# With coverage
pytest --cov=protopoke
```

Tests use `pytest-asyncio` with `asyncio_mode = "auto"` — all `async def test_*` functions run automatically without needing `@pytest.mark.asyncio`.

## Test Layout

```
tests/
├── conftest.py                   Shared fixtures
├── test_proxy_integration.py     End-to-end proxy flow
├── test_session.py               Session + SessionRegistry
├── test_framing.py               All four framers
├── test_protocol_parser.py       DefinitionBasedDecoder + Encoder
├── test_protocol_definition.py   YAML/JSON schema loading
├── test_protocol_display.py      Hexdump and tree renderers
├── test_tamper.py                QueuedTamperController
├── test_rules.py                 ReplaceRule + InterceptRule + engines
├── test_forge.py                 ForgeEngine replay
├── test_forge_models.py          Playbook / PlaybookFrame models
├── test_fuzzing.py               FuzzerEngine + mutators
├── test_fuzzing_integration.py   End-to-end fuzzing
├── test_events.py                EventBus pub/sub
├── test_config_serialization.py  ProxyConfig round-trip
├── test_project_manager.py       Save/open .pp ZIP files
├── test_models.py                Frame / SessionInfo / TamperedUnit
├── test_tls.py                   TLS MITM
├── test_send_frame.py            api.send_frame()
├── test_inject_to_server.py      api.inject_to_server()
├── test_mcp_server.py            MCP tool coverage
├── test_sqlite_storage.py        SqliteStorageBackend
├── test_to_dict_serialisation.py .to_dict() / .from_dict() round-trips
└── test_sequence.py              SEQUENCE match strategy
```

## Code Style

- Python 3.11+ — use modern type hints and `from __future__ import annotations`
- All I/O is async (`asyncio`); no threads except the SQLite executor bridge
- Data classes for all models — no ORM, no metaclasses
- Dependencies are explicit constructor arguments, not globals
- Registration (e.g. `FRAMER_REGISTRY`) is explicit, not auto-discovered

## Project Structure

See [Architecture](architecture.md) for a detailed breakdown of the codebase.
