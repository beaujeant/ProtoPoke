# Projects

ProtoPoke can save and load your work as project files (`.pp`), preserving proxy configuration, rules, forge data, and captured traffic.

## Project File Format

A `.pp` file is a ZIP archive containing:

| File | Contents |
|------|----------|
| `project.json` | Project metadata (name, version) |
| `forwarders.json` | List of forwarder configurations |
| `rules.json` | Replace rules and intercept rules |
| `forge.json` | Playbook definitions |
| `traffic.json` | Captured session data (optional) |
| `logs.json` | Log records (optional) |

## Managing Projects

### TUI

| Action | Shortcut |
|--------|----------|
| New project | ++ctrl+n++ |
| Open project | ++ctrl+o++ |
| Save project | ++ctrl+s++ |
| Save as... | ++ctrl+shift+s++ |

### Python API

```python
from protopoke.project.manager import ProjectManager

manager = ProjectManager()

# Save
manager.save("/path/to/project.pp", api)

# Load
state = manager.open("/path/to/project.pp")
# state contains forwarders, rules, playbooks, traffic
```

## Version History

| Version | Format |
|---------|--------|
| v3 | Single `config.json` (one forwarder only) |
| v4 | `forwarders.json` (multi-forwarder support) — current format |

The `ProjectManager.open()` method automatically migrates v3 files to v4 on load.
