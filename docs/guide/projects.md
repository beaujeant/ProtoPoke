# Projects

ProtoPoke can save and load your work as project files (`.pp`), preserving proxy configuration, rules, forge data, and captured traffic.

## Project File Format

A `.pp` file is a standard ZIP archive containing:

| File | Contents |
|------|----------|
| `project.json` | Project metadata (name, format version, timestamps) |
| `forwarders.json` | List of forwarder configurations |
| `rules.json` | Replace rules and intercept rules |
| `forge.json` | Playbook definitions (frames, run history, connection config) |
| `logs.json` | Captured sessions and frames (the Traffic tab content) |
| `filters.json` | Frame display filters |
| `mcp.json` | Embedded MCP server settings (enabled flag, host, port) |

The archive is loaded with safety limits (max 32 members, 100 MB per member).

## Managing Projects

### TUI

| Action | Shortcut |
|--------|----------|
| New project | ++ctrl+n++ |
| Open project | ++ctrl+o++ |
| Save project | ++ctrl+s++ |
| Save as... | ++ctrl+shift+s++ |

### Python API

`ProjectManager` holds the project state in memory; `open()` returns a
`ProjectState` you can wire into a running `ProtoPokeAPI`.

```python
from protopoke.project.manager import ProjectManager

pm = ProjectManager()

# Start a fresh project and save it to a path
pm.new("My Capture")
pm.forwarders[0].listen_port = 9000
pm.save_as("/path/to/project.pp")

# Re-save to the same path later
pm.save()

# Load an existing project
pm2 = ProjectManager()
state = pm2.open("/path/to/project.pp")
# state.forwarders, state.rules_engine, state.intercept_filter,
# state.playbooks, state.captured_sessions, state.mcp_settings, ...
```

## Format Version

Project files carry a `format_version` field (currently **7**). Opening a
file created by a *newer* version of ProtoPoke raises an error asking you to
upgrade; older formats are migrated forward on load where possible.
