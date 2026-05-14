# Fuzzing

ProtoPoke includes a replay-based fuzzer that mutates captured session traffic and detects anomalies in the server's response.

## How It Works

1. Select a captured session as the **baseline**
2. Choose one or more **mutators** that modify frame bytes
3. The fuzzer replays the session N times, applying mutations each iteration
4. Each response is compared against the baseline to detect **anomalies** (crashes, timeouts, response size changes)

## Running a Campaign

### TUI

1. Switch to the **Fuzzer** tab (++f5++)
2. Select a captured session
3. Choose mutators and set iteration count
4. Click **Start**
5. Review results — anomalies are flagged automatically

### Python API

```python
from protopoke.fuzzing.mutators.raw import BitFlipMutator, KnownBadMutator

# fuzz_session() returns a FuzzCampaign with all results populated.
campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[BitFlipMutator(), KnownBadMutator()],
    iterations=100,
    stop_on_crash=True,
)

# campaign.results is the full list; .interesting_results / .crash_results
# are convenience filters.
for result in campaign.interesting_results:
    print(f"iteration {result.iteration} ({result.mutator_name}): "
          f"reset={result.connection_reset} timed_out={result.timed_out}")
    print(f"  mutated frame: {result.mutated_bytes.hex()}")
```

### MCP

```
fuzz_start(
    session_id="<uuid>",
    mutators=[{"name": "bit_flip"}, {"name": "known_bad"}],
    iterations=100,
    stop_on_crash=true
)
```

Campaigns run as background tasks. Poll with `fuzz_status` and fetch results with `fuzz_results`:

```
fuzz_status(campaign_id="<uuid>")
fuzz_results(campaign_id="<uuid>", interesting_only=true)
fuzz_stop(campaign_id="<uuid>")
list_campaigns()
```

## Built-in Mutators

### Raw Mutators

These operate on raw frame bytes and do not require a protocol definition.

| Mutator | MCP name | Description | Parameters |
|---------|----------|-------------|------------|
| `BitFlipMutator` | `bit_flip` | Flip random bits in the frame | `count` (default: 1) |
| `ByteInsertMutator` | `byte_insert` | Insert random bytes at random positions | `count` (default: 4) |
| `ByteDeleteMutator` | `byte_delete` | Delete random bytes | `max_count` (default: 4) |
| `KnownBadMutator` | `known_bad` | Replace segments with known-bad payloads (format strings, overflows, etc.) | — |
| `RadamsaMutator` | `radamsa` | Use the [Radamsa](https://gitlab.com/akihe/radamsa) fuzzer as a mutator | `radamsa_path`, `timeout` |
| `ChainMutator` | — | Apply multiple mutators in sequence | `mutators` list |

### Protocol-Aware Mutators

These require a loaded protocol definition and operate on parsed field boundaries.

| Mutator | MCP name | Description | Parameters |
|---------|----------|-------------|------------|
| `FieldBoundaryMutator` | `field_boundary` | Set fields to boundary values (0, max, min) | — |
| `FieldOverflowMutator` | `field_overflow` | Replace variable-length fields with oversized data | `lengths` (default: [256, 1024, 4096]) |
| `NullByteMutator` | `null_byte` | Inject null bytes into string/bytes fields | — |
| `LengthMangleMutator` | `length_mangle` | Corrupt length fields (off-by-one, zero, max) | — |

## Custom Mutators

Create a custom mutator by subclassing `FrameMutator`. `mutate()` receives
the `Frame` about to be sent and its `ParsedMessage` (or `None` when no
protocol definition matched), and returns the bytes to send instead — or
`None` to leave the frame unchanged:

```python
from protopoke.fuzzing.mutators.base import FrameMutator
from protopoke.models import Frame, ParsedMessage

class MyMutator(FrameMutator):
    async def mutate(self, frame: Frame, parsed: ParsedMessage | None) -> bytes | None:
        """Return mutated bytes, or None to skip this frame."""
        data = frame.raw_bytes
        # Example: swap the first two bytes
        if len(data) < 2:
            return None
        return data[1:2] + data[0:1] + data[2:]
```

Pass custom mutators directly:

```python
campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[MyMutator()],
    iterations=50,
)
```

## Anomaly Detection

The fuzzer automatically compares each iteration's response against the baseline and flags anomalies:

- **Crash** — connection refused or reset during replay
- **Timeout** — server stopped responding
- **Size delta** — response size differs significantly from baseline
